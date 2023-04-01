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

#ifndef SENDER_H
#define SENDER_H

#include <limits.h>
#include <time.h>
#include <stdbool.h>
#include <stdint.h>

#define MAX_SENDER_REQUESTS (PIPE_BUF / sizeof (struct sender_request))

enum request_mode {
	INVALID_MODE,
	NTP_BASIC,
	NTP_INTERLEAVED,
	PTP_DELAY,
	PTP_NSM,
};

struct sender_config {
	int sock_fd;
	enum request_mode mode;
	char src_mac[6];
	char dst_mac[6];
	uint32_t dst_address;
	int ptp_domain;
	int ptp_mcast;
	struct {
		const char *c2s;
		const char *cookie;
	} nts;
};

struct sender_request {
	struct timespec when;
	uint32_t src_address;
	uint32_t _pad;
	uint64_t remote_id;
	uint64_t local_id;
};

int sender_start(struct sender_config *config);
bool sender_send_requests(int sender_fd, struct sender_request *requests, int num);
void sender_stop(int sender_fd);

#define GET_UNALIGNED(ptr) __extension__	\
({						\
	struct __attribute__((packed)) {	\
            __typeof__(*(ptr)) __v;		\
	} *__p = (__typeof__(__p)) (ptr);	\
	__p->__v;				\
})

#define PUT_UNALIGNED(val, ptr)		\
do {						\
	struct __attribute__((packed)) {	\
		__typeof__(*(ptr)) __v;		\
	} *__p = (__typeof__(__p)) (ptr);	\
	__p->__v = (val);			\
} while(0)


static inline uint8_t get_u8(const void *ptr)
{
	return *((const uint8_t *) ptr);
}

static inline void put_u8(uint8_t val, void *ptr)
{
	*((uint8_t *) ptr) = val;
}

static inline uint16_t get_u16(const void *ptr)
{
	return GET_UNALIGNED((const uint16_t *) ptr);
}

static inline uint32_t get_u32(const void *ptr)
{
	return GET_UNALIGNED((const uint32_t *) ptr);
}

static inline uint32_t get_u64(const void *ptr)
{
	return GET_UNALIGNED((const uint32_t *) ptr);
}

static inline void put_u16(uint16_t val, void *ptr)
{
	PUT_UNALIGNED(val, (uint16_t *) ptr);
}

static inline void put_u32(uint32_t val, void *ptr)
{
	PUT_UNALIGNED(val, (uint32_t *) ptr);
}

static inline void put_u64(uint64_t val, void *ptr)
{
	PUT_UNALIGNED(val, (uint64_t *) ptr);
}

#endif
