/*
 * Copyright (C) 2018  Miroslav Lichvar <mlichvar@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <assert.h>
#include <arpa/inet.h>
#include <float.h>
#include <math.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <pcap/pcap.h>

#include "sender.h"

#define MAX_CLIENTS 16384

struct config {
	enum request_mode mode;
	char *interface;
	char dst_mac[6];
	uint32_t dst_address;
	uint32_t src_network;
	int src_bits;
	int ptp_domain;
	int min_rate;
	int max_rate;
	unsigned int senders;
	bool exp_distribution;
	bool allow_late_tx;
	double multiplier;
	double sampling_interval;
	double offset_correction;
	bool hw_timestamping;
};

struct client {
	uint64_t remote_id;
	uint64_t local_id;
	struct timespec local_rx;
	int warmup;
};

struct perf_stats {
	int clients;
	int requests;
	int invalid_responses;
	union {
		int basic_responses;
		int delay_responses;
	};
	union {
		int interleaved_responses;
		int sync_responses;
	};
	int offset_updates;
	double sum_offset;
	double sum2_offset;
	double min_offset;
	double max_offset;
};

static pcap_t *open_pcap(struct config *config) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap;
	int r;

	if (!(pcap = pcap_create(config->interface, errbuf))) {
		fprintf(stderr, "pcap: %s\n", errbuf);
		goto err;
	}

	if ((r = pcap_set_snaplen(pcap, 128)) ||
	    (r = pcap_set_promisc(pcap, 0)) ||
	    (r = pcap_set_timeout(pcap, 10)) ||
	    (r = pcap_set_immediate_mode(pcap, 1)) ||
	    (r = pcap_set_buffer_size(pcap, 1 << 24)) ||
	    (r = pcap_set_tstamp_type(pcap, config->hw_timestamping ?
				      PCAP_TSTAMP_ADAPTER_UNSYNCED : PCAP_TSTAMP_HOST)) ||
	    (r = pcap_set_tstamp_precision(pcap, PCAP_TSTAMP_PRECISION_NANO))) {
		fprintf(stderr, "pcap: %s\n", pcap_statustostr(r));
		goto err;
	}

	if ((r = pcap_activate(pcap))) {
		fprintf(stderr, "pcap: %s\n", pcap_statustostr(r));
		if (r < 0)
			goto err;
	}

	if (pcap_set_datalink(pcap, DLT_EN10MB)) {
		fprintf(stderr, "Could not set pcap datalink\n");
		goto err;
	}

	if (pcap_setdirection(pcap, PCAP_D_IN)) {
		fprintf(stderr, "Could not set pcap direction\n");
		goto err;
	}

	if (pcap_setnonblock(pcap, 1, errbuf)) {
		fprintf(stderr, "pcap: %s\n", errbuf);
		goto err;
	}

	return pcap;
err:
	if (pcap)
		pcap_close(pcap);
	return NULL;
}

static bool get_iface_mac(struct config *config, char mac[6]) {
	struct ifreq req;
	int sock_fd;

	sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock_fd < 0)
		return false;

	snprintf(req.ifr_name, sizeof (req.ifr_name), "%s", config->interface);

	if (ioctl(sock_fd, SIOCGIFHWADDR, &req)) {
		fprintf(stderr, "Could not get MAC address of %s\n", config->interface);
		close(sock_fd);
		return false;
	}
	close(sock_fd);

	memcpy(mac, req.ifr_hwaddr.sa_data, 6);
	return true;
}

static void add_nsec_to_ts(struct timespec *ts, uint64_t nsec) {
	ts->tv_sec += nsec / 1000000000U;
	ts->tv_nsec += nsec % 1000000000U;
	while (ts->tv_nsec >= 1000000000U) {
		ts->tv_nsec -= 1000000000U;
		ts->tv_sec++;
	}
}

static int compare_ts(struct timespec *ts1, struct timespec *ts2) {
	if (ts1->tv_sec != ts2->tv_sec)
		return ts1->tv_sec - ts2->tv_sec;
	if (ts1->tv_nsec != ts2->tv_nsec)
		return ts1->tv_nsec - ts2->tv_nsec;
	return 0;
}

static double diff_ts(struct timespec *ts1, struct timespec *ts2) {
	return (ts1->tv_sec - ts2->tv_sec) + 1e-9 * (ts1->tv_nsec - ts2->tv_nsec);
}

static void make_request(struct sender_request *request, struct client *client, int index,
			 struct config *config, struct timespec *when) {
	request->when = *when;
	request->src_address = config->src_network ^ (index % (1U << (32 - config->src_bits)));
	request->_pad = 0;
	request->remote_id = client->remote_id;
	request->local_id = (uint64_t)random() << 32 | random();

	client->local_id = request->local_id;
}

static bool process_response(struct pcap_pkthdr *header, const u_char *data, struct config *config,
			     struct perf_stats *stats, struct client *clients, int num_clients) {
	struct client *client;
	struct timespec rx = { .tv_sec = header->ts.tv_sec, .tv_nsec = header->ts.tv_usec };
	struct timespec prev_rx, tx = {0};
	uint64_t tx_ntp;
	uint32_t dst_address;
	int src_port, ptp_type = 0;
	bool valid;
	double offset;

	if (header->caplen < 86)
		return false;

	if (memcmp(config->dst_mac, data + 6, 6))
		return false;

	if (ntohs(*(uint16_t *)(data + 12)) != 0x0800)
		return false;

	data += 14;
	if (data[0] >> 4 != 4 || (data[0] & 0xf) != 5 || data[9] != 17 ||
	    ntohl(*(uint32_t *)(data + 12)) != config->dst_address)
		return false;

	dst_address = ntohl(*(uint32_t *)(data + 16));
	src_port = ntohs(*(uint16_t *)(data + 20));
	data += 28;

	if ((dst_address ^ config->src_network) >> (32 - config->src_bits))
		return false;

	client = &clients[(dst_address ^ config->src_network) % (uint32_t)num_clients];
	prev_rx = client->local_rx;

	switch (config->mode) {
	case NTP_BASIC:
	case NTP_INTERLEAVED:
		valid = header->caplen >= 90 && src_port == 123 && (data[0] & 0x7) == 0x4 &&
			(*(uint64_t *)(data + 24) & -2ULL) == (client->local_id & -2ULL);
		if (valid) {
			if (config->mode == NTP_INTERLEAVED)
				client->remote_id = *(uint64_t *)(data + 32);
			else
				client->remote_id = *(uint64_t *)(data + 40);
			client->local_rx = rx;
		}
		break;
	case PTP_DELAY:
	case PTP_NSM:
		ptp_type = data[0] & 0xf;
		valid = header->caplen >= 86 && data[1] == 2 &&
			*(uint16_t *)(data + 30) == (uint16_t)client->local_id &&
			((ptp_type == 9 && src_port == 320) ||
			 (config->mode == PTP_NSM &&
			  ((ptp_type == 0 && src_port == 319) ||
			   (ptp_type == 8 && src_port == 320))));
		if (valid) {
			if (ptp_type == 0)
				client->local_rx = rx;
			else
				memset(&client->local_rx, 0, sizeof client->local_rx);
		}
		break;
	default:
		assert(0);
	}

	if (!valid) {
		if (!client->warmup)
			stats->invalid_responses++;
		return false;
	}

	if (client->warmup)
		return true;

	switch (config->mode) {
	case NTP_BASIC:
	case NTP_INTERLEAVED:
		if (*(uint64_t *)(data + 24) == client->local_id) {
			if (config->mode != NTP_BASIC)
				return true;
			stats->basic_responses++;
		} else {
			if (config->mode != NTP_INTERLEAVED)
				return true;
			rx = prev_rx;
			stats->interleaved_responses++;
		}

		tx_ntp = be64toh(*(uint64_t *)(data + 40));
		tx.tv_sec = (tx_ntp >> 32) - 2208988800;
		tx.tv_nsec = (tx_ntp & 0xffffffffU) / 4.294967296;
		break;
	case PTP_DELAY:
	case PTP_NSM:
		switch (ptp_type) {
		case 8:
			rx = prev_rx;
			/* Fall through */
		case 0:
			/* TODO: handle reversed order of sync and followup */
			if (ptp_type == 0 && data[6] & 0x2)
				return true;

			stats->sync_responses++;

			tx.tv_sec = (uint64_t)ntohs(*(uint32_t *)(data + 32)) << 16 |
					ntohl(*(uint32_t *)(data + 36));
			tx.tv_nsec = ntohl(*(uint32_t *)(data + 40));
			break;
		case 9:
			stats->delay_responses++;
			return true;
		default:
			assert(0);
		}
		break;
	default:
		assert(0);
	}

	if (!rx.tv_sec || !tx.tv_sec)
		return true;

	offset = diff_ts(&rx, &tx) - config->offset_correction;

	stats->offset_updates++;
	stats->sum_offset += offset;
	stats->sum2_offset += offset * offset;
	if (stats->min_offset > offset)
		stats->min_offset = offset;
	if (stats->max_offset < offset)
		stats->max_offset = offset;

	return true;
}

static bool measure_perf(struct config *config, pcap_t *pcap, int *senders, int rate,
			 struct perf_stats *stats) {
	struct sender_request requests[config->senders][MAX_SENDER_REQUESTS];
	struct client clients[MAX_CLIENTS];
	int num_requests[config->senders];
	unsigned int i, num_clients, interval, sender_index = 0, client_index = 0;
	struct pcap_pkthdr *header;
	const u_char *data;
	struct timespec tx_next, max_tx_ahead, now, tx_end, rx_end;

	memset(stats, 0, sizeof *stats);
	stats->min_offset = DBL_MAX;
	stats->max_offset = -DBL_MAX;

	interval = 1e9 / rate;

	num_clients = rate / 10;
	if (num_clients < 1)
		num_clients = 1;
	if (num_clients > MAX_CLIENTS)
		num_clients = MAX_CLIENTS;
	if (num_clients > 1U << (32 - config->src_bits)) {
		fprintf(stderr, "Warning: source network might be too small for rate %d\n", rate);
		num_clients = 1U << (32 - config->src_bits);
	}

	assert(num_clients > 0 && num_clients <= MAX_CLIENTS);

	stats->clients = num_clients;

	memset(clients, 0, sizeof clients);
	for (i = 0; i < num_clients; i++)
		clients[i].warmup = 3;

	clock_gettime(CLOCK_MONOTONIC, &now);
	tx_next = tx_end = rx_end = now;

	add_nsec_to_ts(&tx_end, 1.0e9 * config->sampling_interval);
	add_nsec_to_ts(&rx_end, 1.0e9 * config->sampling_interval + 0.1e9);

	while (1) {
		max_tx_ahead = now;
		add_nsec_to_ts(&max_tx_ahead, interval * num_clients / 4);

		if (compare_ts(&now, &rx_end) > 0)
			break;

		for (i = 0; i < config->senders; i++)
			num_requests[i] = 0;

		for (i = 0; i < MAX_SENDER_REQUESTS * config->senders; i++) {
			if (compare_ts(&tx_next, &tx_end) > 0 ||
			    compare_ts(&tx_next, &max_tx_ahead) > 0)
				break;

			if (compare_ts(&now, &tx_next) > 0 && !config->allow_late_tx) {
				fprintf(stderr, "Could not send requests at rate %d\n", rate);
				return false;
			}

			make_request(&requests[sender_index][num_requests[sender_index]++],
				     &clients[client_index], client_index, config, &tx_next);

			if (clients[client_index].warmup)
				clients[client_index].warmup--;
			if (!clients[client_index].warmup)
				stats->requests++;

			sender_index = (sender_index + 1) % config->senders;
			client_index = (client_index + 1) % num_clients;

			add_nsec_to_ts(&tx_next, !config->exp_distribution ? interval :
				       interval * -log((random() & 0x7fffffff) / 2147483647.0));
		}

		for (i = 0; i < config->senders; i++) {
			if (num_requests[i] == 0)
				continue;
			if (!sender_send_requests(senders[i], requests[i], num_requests[i]))
				return false;
		}

		while (pcap_next_ex(pcap, &header, &data)) {
			process_response(header, data, config, stats, clients, num_clients);
		}

		clock_gettime(CLOCK_MONOTONIC, &now);
	}

	return true;
}

static void print_header(struct config *config) {
	printf("               |          responses            |     TX timestamp offset (ns)\n");
	printf("rate   clients |  lost invalid %15s |    min    mean     max    rms\n",
	       config->mode <= NTP_INTERLEAVED ? "basic  xleave" : "delay sync/fw");
}

static int get_lost_packets(struct perf_stats *stats, struct config *config) {
	switch (config->mode) {
	case NTP_BASIC:
	case NTP_INTERLEAVED:
		return stats->requests - stats->invalid_responses -
			stats->basic_responses - stats->interleaved_responses;
	case PTP_DELAY:
		return stats->requests - stats->invalid_responses -
			stats->delay_responses;
	case PTP_NSM:
		return 2 * stats->requests - stats->invalid_responses -
			stats->delay_responses - stats->sync_responses;
	default:
		assert(0);
	}
}

static void print_stats(struct perf_stats *stats, struct config *config, int rate) {
	printf("%-8d %5d %6.2f%% %6.2f%% %6.2f%% %6.2f%%",
	       rate, stats->clients,
	       100.0 * get_lost_packets(stats, config) / stats->requests,
	       100.0 * stats->invalid_responses / stats->requests,
	       100.0 * stats->basic_responses / stats->requests,
	       100.0 * stats->interleaved_responses / stats->requests);
	if (config->offset_correction && stats->offset_updates)
		printf("  %+7.0f %+7.0f %+7.0f %6.0f",
		       1e9 * stats->min_offset, 1e9 * stats->sum_offset / stats->offset_updates,
		       1e9 * stats->max_offset, 1e9 * sqrt(stats->sum2_offset / stats->offset_updates));
	if (0)
		printf(" | %7d", stats->requests);

	printf("\n");
}

static bool run_perf(struct config *config) {
	struct sender_config sender_config;
	struct perf_stats stats;
	pcap_t *pcap;
	int i, rate, senders[config->senders];
	bool ret = true;

	sender_config.mode = config->mode;
	if (!get_iface_mac(config, sender_config.src_mac))
		return false;

	memcpy(sender_config.dst_mac, config->dst_mac, 6);
	sender_config.dst_address = config->dst_address;
	sender_config.ptp_domain = config->ptp_domain;

	pcap = open_pcap(config);
	if (!pcap)
		return false;

	sender_config.sock_fd = pcap_fileno(pcap);

	for (i = 0; i < config->senders; i++) {
		senders[i] = sender_start(&sender_config);
		if (!senders[i]) {
			for (i--; i >= 0; i--)
				sender_stop(senders[i]);
			pcap_close(pcap);
			return false;
		}
	}

	print_header(config);

	for (rate = config->min_rate; rate <= config->max_rate; rate *= config->multiplier) {
		ret = measure_perf(config, pcap, senders, rate, &stats);
		if (!ret)
			break;

		print_stats(&stats, config, rate);

		if (get_lost_packets(&stats, config) + stats.invalid_responses >
		    stats.requests / 2)
			break;
	}

	for (i = 0; i < config->senders; i++)
		sender_stop(senders[i]);
	pcap_close(pcap);

	return ret;
}

static bool is_local_network(uint32_t net, int bits) {
	return ((net ^ ntohl(inet_addr("10.0.0.0"))) >> 24 == 0 && bits >= 8) ||
		((net ^ ntohl(inet_addr("172.16.0.0"))) >> 20 == 0 && bits >= 12) ||
		((net ^ ntohl(inet_addr("192.168.0.0"))) >> 16 == 0 && bits >= 16);
}

int main(int argc, char **argv) {
	struct config config;
	char *s;
	int opt, dst_mac_set = 0;

	srandom(time(NULL));
	setvbuf(stdout, NULL, _IOLBF, BUFSIZ);

	memset(&config, 0, sizeof config);
	config.mode = INVALID_MODE;
	config.min_rate = 1000;
	config.max_rate = 1000000;
	config.senders = 1;
	config.multiplier = 1.5;
	config.sampling_interval = 2.0;

	while ((opt = getopt(argc, argv, "BID:N:i:s:d:m:r:p:elt:x:o:Hh")) != -1) {
		switch (opt) {
			case 'B':
				config.mode = NTP_BASIC;
				break;
			case 'I':
				config.mode = NTP_INTERLEAVED;
				break;
			case 'D':
				config.mode = PTP_DELAY;
				config.ptp_domain = atoi(optarg);
				break;
			case 'N':
				config.mode = PTP_NSM;
				config.ptp_domain = atoi(optarg);
				break;
			case 'i':
				config.interface = optarg;
				break;
			case 's':
				if (!(s = strchr(optarg, '/')))
					goto err;
				*s = '\0';
				if (inet_pton(AF_INET, optarg, &config.src_network) <= 0)
					goto err;
				config.src_network = ntohl(config.src_network);
				config.src_bits = atoi(s + 1);
				break;
			case 'd':
				if (inet_pton(AF_INET, optarg, &config.dst_address) <= 0)
					goto err;
				config.dst_address = ntohl(config.dst_address);
				break;
			case 'm':
				if (sscanf(optarg, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
					   config.dst_mac + 0, config.dst_mac + 1,
					   config.dst_mac + 2, config.dst_mac + 3,
					   config.dst_mac + 4, config.dst_mac + 5) != 6)
					goto err;
				dst_mac_set = 1;
				break;
			case 'r':
				if ((s = strchr(optarg, '-'))) {
					*s = '\0';
					config.min_rate = atoi(optarg);
					config.max_rate = atoi(s + 1);
				} else {
					config.min_rate = config.max_rate = atoi(optarg);
				}
				break;
			case 'p':
				config.senders = atoi(optarg);
				break;
			case 'e':
				config.exp_distribution = true;
				break;
			case 'l':
				config.allow_late_tx = true;
				break;
			case 'x':
				config.multiplier = atof(optarg);
				break;
			case 't':
				config.sampling_interval = atof(optarg);
				break;
			case 'o':
				config.offset_correction = atof(optarg);
				break;
			case 'H':
				config.hw_timestamping = true;
				break;
			default:
				goto err;
		}
	}

	if (config.mode == INVALID_MODE || !config.interface || !dst_mac_set ||
	    !config.dst_address || config.src_bits < 8 || config.src_bits > 32 ||
	    config.min_rate < 1 || config.multiplier < 1.001 || config.sampling_interval < 0.2 ||
	    config.senders < 1 || config.senders > 16)
		goto err;

	if (!is_local_network(config.dst_address, 32) ||
	    !is_local_network(config.src_network, config.src_bits)) {
		fprintf(stderr, "Non-local source or destination network\n");
		return 1;
	}

	return !run_perf(&config);
err:
	fprintf(stderr, "Usage: %s MODE NETWORK-OPTIONS [OTHER-OPTIONS]\n", argv[0]);
	fprintf(stderr, "\nMode:\n");
	fprintf(stderr, "\t-B              send NTP client requests in basic mode\n");
	fprintf(stderr, "\t-I              send NTP client requests in interleaved mode\n");
	fprintf(stderr, "\t-D DOMAIN       send PTP delay requests\n");
	fprintf(stderr, "\t-N DOMAIN       send PTP NetSync Monitor (NSM) requests\n");
	fprintf(stderr, "\nNetwork options:\n");
	fprintf(stderr, "\t-i INTERFACE    specify network interface\n");
	fprintf(stderr, "\t-s NETWORK/BITS specify source IPv4 network\n");
	fprintf(stderr, "\t-d IP-ADDRESS   specify destination IPv4 address\n");
	fprintf(stderr, "\t-m MAC          specify destination MAC address\n");
	fprintf(stderr, "\nOther options:\n");
	fprintf(stderr, "\t-r RATE[-RATE]  specify minimum and maximum rate (1000-1000000)\n");
	fprintf(stderr, "\t-p NUMBER       specify number of processes to send requests (1)\n");
	fprintf(stderr, "\t-e              make transmit interval exponentially distributed\n");
	fprintf(stderr, "\t-l              allow late transmissions\n");
	fprintf(stderr, "\t-x MULT         specify rate multiplier (1.5)\n");
	fprintf(stderr, "\t-t INTERVAL     specify sampling interval (2.0 seconds)\n");
	fprintf(stderr, "\t-o CORRECTION   print offset between remote TX and local RX timestamp\n");
	fprintf(stderr, "\t                with specified correction (e.g. network and RX delay)\n");
	fprintf(stderr, "\t-H              enable HW timestamping for TX offset statistics\n");
	fprintf(stderr, "\t-h              print this help message\n");
	return 1;
}
