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
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>

#ifdef NTS
#include <gnutls/crypto.h>
#endif

#include "sender.h"

#ifdef NTS
#define MAX_PACKET_LENGTH 512
#else
#define MAX_PACKET_LENGTH 128
#endif

#define MAX_PACKETS 128

struct nts_context {
	int cookie_len;
#ifdef NTS
	unsigned char cookie[256];
	gnutls_aead_cipher_hd_t cipher;
#endif
};

#ifdef NTS
static unsigned int convert_hex_to_bytes(const char *hex, void *buf, unsigned int len) {
	char *p, byte[3];
	unsigned int i;

	for (i = 0; i < len && *hex != '\0'; i++) {
		byte[0] = *hex++;
		if (*hex == '\0')
			return 0;
		byte[1] = *hex++;
		byte[2] = '\0';
		((char *)buf)[i] = strtol(byte, &p, 16);

		if (p != byte + 2)
			return 0;
	}

	return *hex == '\0' ? i : 0;
}
#endif

static bool initialize_nts(struct sender_config *config, struct nts_context *nts) {
#ifdef NTS
	unsigned char key[256];
	gnutls_datum_t datum;

	if (!config->nts.c2s || !config->nts.cookie ||
	    !(config->mode == NTP_BASIC || config->mode == NTP_INTERLEAVED)) {
		nts->cookie_len = 0;
		nts->cipher = NULL;
		return true;
	}

	nts->cookie_len = convert_hex_to_bytes(config->nts.cookie,
					       nts->cookie, sizeof nts->cookie);
	if (nts->cookie_len == 0 || nts->cookie_len % 4 != 0) {
		fprintf(stderr, "Invalid cookie length %d\n", nts->cookie_len);
		return false;
	}

	datum.data = key;
	datum.size = convert_hex_to_bytes(config->nts.c2s, key, sizeof key);

	if (gnutls_aead_cipher_init(&nts->cipher, GNUTLS_CIPHER_AES_128_SIV, &datum) < 0) {
		fprintf(stderr, "Invalid key length: %d\n", datum.size);
		return false;
	}

#else
	nts->cookie_len = 0;
#endif
	return true;
}

static void destroy_nts(struct nts_context *nts) {
#ifdef NTS
	if (nts->cipher)
		gnutls_aead_cipher_deinit(nts->cipher);
#endif
}

static int make_packet(struct sender_request *request, struct sender_config *config,
		       struct nts_context *nts, unsigned char *buf, int max_len) {
	unsigned char *auth = NULL;
	uint32_t sum = 0;
	uint16_t carry;
	int i, len = 0, data_len, src_port, dst_port;

	switch (config->mode) {
	case NTP_BASIC:
	case NTP_INTERLEAVED:
		src_port = 32768 + random() % 28000;
		dst_port = 123;
		data_len = 48;
		if (nts->cookie_len > 0)
			data_len += 4 + 32 + 4 + nts->cookie_len + 4 + 4 + 16 + 16;
		break;
	case PTP_DELAY:
	case PTP_NSM:
		src_port = dst_port = 319;
		data_len = config->mode == PTP_NSM ? 48 : 44;
		break;
	default:
		assert(0);
	}

	assert(max_len >= 128);
	memset(buf, 0, max_len);

	/* Ethernet header */
	memcpy(buf + 0, config->dst_mac, 6);
	memcpy(buf + 6, config->src_mac, 6);
	put_u16(htons(0x0800), buf + 12);
	buf += 14, len += 14;

	/* IP header */
	memcpy(buf, "\x45\x00\x00\x00\xd7\xe9\x40\x00\x40\x11", 10);
	put_u16(htons(20 + 8 + data_len), buf + 2);
	put_u32(htonl(request->src_address), buf + 12);
	put_u32(htonl(config->dst_address), buf + 16);

	for (i = 0; i < 20; i += 2)
		sum += get_u16(buf + i);
	while ((carry = sum >> 16))
		sum = (sum & 0xffff) + carry;

	put_u16(~sum, buf + 10);

	buf += 20, len += 20;

	/* UDP header and data */
	put_u16(htons(src_port), buf + 0);
	put_u16(htons(dst_port), buf + 2);
	put_u16(htons(8 + data_len), buf + 4);
	buf += 8, len += 8;

	assert(max_len >= len + data_len);

	switch (config->mode) {
	case NTP_BASIC:
	case NTP_INTERLEAVED:
		buf[0] = 0xe3;
		put_u64(request->remote_id, buf + 24);
		put_u64(request->local_id ^ 1, buf + 32);
		put_u64(request->local_id, buf + 40);
		auth = buf + 48;
		break;
	case PTP_NSM:
		put_u32(htonl(0x21fe0000), buf + 44);
		/* Fall through */
	case PTP_DELAY:
		put_u16(htons(0x0102), buf + 0);
		put_u16(htons(data_len), buf + 2);
		put_u8(config->ptp_domain, buf + 4);
		buf[6] = config->ptp_mcast ? 0 : 0x4;
		put_u32(htonl(request->src_address), buf + 20);
		put_u16(request->local_id, buf + 30);
		buf[32] = 0x1;
		break;
	default:
		assert(0);
	}

	if (auth && nts->cookie_len > 0) {
#ifdef NTS
		size_t clen;

		/* Unique Identifier */
		put_u16(htons(0x0104), auth + 0);
		put_u16(htons(4 + 32), auth + 2);
		put_u32(random(), auth + 4);
		put_u32(random(), auth + 8);
		auth += 4 + 32;

		/* Cookie */
		put_u16(htons(0x0204), auth + 0);
		put_u16(htons(4 + nts->cookie_len), auth + 2);
		memcpy(auth + 4, nts->cookie, nts->cookie_len);
		auth += 4 + nts->cookie_len;

		/* Authenticator */
		put_u16(htons(0x0404), auth + 0);
		put_u16(htons(4 + 4 + 16 + 16), auth + 2);
		put_u16(htons(16), auth + 4);
		put_u16(htons(16), auth + 6);
		put_u32(random(), auth + 8);
		put_u32(random(), auth + 12);
		put_u32(random(), auth + 16);
		put_u32(random(), auth + 20);
		clen = 16;
		if (gnutls_aead_cipher_encrypt(nts->cipher,
					       auth + 4 + 4, 16, buf, auth - buf, 0,
					       "", 0, auth + 4 + 4 + 16, &clen) < 0 ||
		    clen != 16)
			assert(0);
		auth += 4 + 4 + 16 + 16;
#endif
	}

	return len + data_len;
}

static bool run_sender(int perf_fd, struct sender_config *config) {
	struct sender_request requests[MAX_SENDER_REQUESTS];
	struct mmsghdr msg_headers[MAX_PACKETS];
	unsigned char packets[MAX_PACKETS][MAX_PACKET_LENGTH];
	struct iovec msg_iovs[MAX_PACKETS];
	struct nts_context nts;
	struct timespec now;
	int i, j, r, n, next_tx, sent = 0;

	if (!initialize_nts(config, &nts))
		return false;

	while (1) {
		r = read(perf_fd, requests, sizeof requests);
		if (r < 0) {
			fprintf(stderr, "read() failed: %m\n");
			return false;
		}

		assert(r % sizeof requests[0] == 0);
		n = r / sizeof requests[0];

		if (n == 0)
			break;

		for (i = 0; i < n; ) {
			clock_gettime(CLOCK_MONOTONIC, &now);

			for (j = 0; i < n && j < MAX_PACKETS; i++, j++) {
				next_tx = (requests[i].when.tv_sec - now.tv_sec) * 1000000000 +
						requests[i].when.tv_nsec - now.tv_nsec;

				if (next_tx > 0)
					break;

				memset(&msg_headers[j], 0, sizeof msg_headers[j]);
				msg_iovs[j].iov_base = packets[j];
				msg_iovs[j].iov_len = make_packet(&requests[i], config, &nts,
								  packets[j], sizeof packets[j]);

				msg_headers[j].msg_hdr.msg_iov = &msg_iovs[j];
				msg_headers[j].msg_hdr.msg_iovlen = 1;
			}

			if (j > 0) {
				for (sent = 0; sent < j; ) {
					r = sendmmsg(config->sock_fd, &msg_headers[sent],
						     j - sent, 0);
					if (r < 0) {
						if (errno == EAGAIN)
							continue;
						fprintf(stderr, "send() failed: %m\n");
						return false;
					}
					sent += r;
				}
			}
		}
	}

	destroy_nts(&nts);

	return true;
}

int sender_start(struct sender_config *config) {
	pid_t pid;
	int fd, fds[2];
	bool ret;

	if (pipe2(fds, O_DIRECT)) {
		fprintf(stderr, "pipe2() failed(): %m\n");
		return 0;
	}

	pid = fork();

	if (pid < 0) {
		fprintf(stderr, "fork() failed: %m\n");
		return 0;
	}

	if (pid) {
		close(fds[0]);
		return fds[1];
	}

	for (fd = 3; fd < 100; fd++) {
		if (fd != fds[0] && fd != config->sock_fd)
			close(fd);
	}

	ret = run_sender(fds[0], config);

	close(fds[0]);
	close(config->sock_fd);

	exit(!ret);
}

bool sender_send_requests(int sender_fd, struct sender_request *requests, int num) {
	if (write(sender_fd, requests, sizeof (struct sender_request) * num) !=
	    sizeof (struct sender_request) * num)
		return false;
	return true;
}

void sender_stop(int sender_fd) {
	close(sender_fd);
	wait(NULL);
}
