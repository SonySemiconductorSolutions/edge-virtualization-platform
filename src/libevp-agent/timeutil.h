/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>

#include <internal/time.h>

struct timespec;

#define ISO8601_SIZ sizeof("2022-01-01T00:00:00.000000Z")

/* CLOCK_MONOTONIC-based functions */
int absts2relms_roundup(const struct timespec *abstimeout);
void relms2absts(int ms, struct timespec *abstimeout);
void gettime(struct timespec *now);
uint64_t gettime_ms(void);

/* CLOCK_REALTIME-based variants */
void getrealtime(struct timespec *now);
int absts2relms_realtime_roundup(const struct timespec *abstimeout);
void relms2absts_realtime(int ms, struct timespec *abstimeout);

/* Time formating functions */
char *iso8601time_r(struct timespec *ts, char dst[static ISO8601_SIZ]);

/* convert struct timespec to ms and round up */
#define timespec2ms(x)                                                        \
	(((uint64_t)(x)->tv_sec) * 1000L + (((x)->tv_nsec + 999999) / 1000000))
