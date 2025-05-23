/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include <internal/util.h>

#include "cdefs.h"
#include "timeutil.h"

static int
_absts2relms_roundup(clockid_t clockid, const struct timespec *abstimeout)
{
	int timeout_ms;
	struct timespec now;
	int ret;
	ret = clock_gettime(clockid, &now);
	if (ret != 0) {
		xerrx(1, "Clockid %i not supported.", clockid);
	}
	if (timespeccmp(abstimeout, &now, <=)) {
		timeout_ms = 0;
	} else {
		struct timespec diff;
		timespecsub(abstimeout, &now, &diff);
		if (diff.tv_sec > INT_MAX / 1000 - 1) {
			timeout_ms = INT_MAX;
		} else {
			timeout_ms = (timespec2ns(&diff) + 999999) / 1000000;
		}

		if (timeout_ms < 0) {
			// Maybe the execution of this code was delayed. So the
			// result indicates a past time
			xwarnx("Calculated time is negative (%i). "
			       "Set 0 ms "
			       "as a minimum valid value.\n",
			       timeout_ms);
			timeout_ms = 0;
		}
	}
	return timeout_ms;
}

static void
_relms2absts(clockid_t clockid, int ms, struct timespec *abstimeout)
{
	struct timespec now;
	struct timespec diff;
	int ret;
	ret = clock_gettime(clockid, &now);
	if (ret != 0) {
		xerrx(1, "Clockid %i not supported.", clockid);
	}
	diff.tv_sec = ms / 1000;
	diff.tv_nsec = (ms % 1000) * 1000000;
	timespecadd(&now, &diff, abstimeout);
}

void
gettime(struct timespec *now)
{
	int ret = clock_gettime(CLOCK_MONOTONIC, now);
	if (ret != 0) {
		xerrx(1, "Clockid %i not supported.", CLOCK_MONOTONIC);
	}
}

void
getrealtime(struct timespec *now)
{
	int ret = clock_gettime(CLOCK_REALTIME, now);
	if (ret != 0) {
		xerrx(1, "Clockid %i not supported.", CLOCK_REALTIME);
	}
}

uint64_t
gettime_ms(void)
{
	struct timespec now;

	gettime(&now);
	return timespec2ms(&now);
}

char *
iso8601time_r(struct timespec *ts, char dst[ISO8601_SIZ])
{
	long usecs, secs;
	time_t t;
	int r;
	char tmp[ISO8601_SIZ];
	struct tm tm;

	secs = ts->tv_sec;
	usecs = ts->tv_nsec / 1000;

	/* adjust seconds and microseconds */
	secs += usecs / 1000000;
	usecs %= 1000000;

	t = secs;
	gmtime_r(&t, &tm);
	r = strftime(tmp, sizeof(tmp), "%Y-%m-%dT%H:%M:%S", &tm);
	if (r == 0) {
		return NULL;
	}

	/*
	 * As we adjusted the usecs variable is imposible to
	 * have truncation here, but it is always better to
	 * have additional checks instead of crying later.
	 */
	r = snprintf(dst, ISO8601_SIZ, "%s.%06ldZ", tmp, usecs);
	if (r < 0 || (unsigned)r >= ISO8601_SIZ) {
		return NULL;
	}

	return dst;
}

int
absts2relms_roundup(const struct timespec *abstimeout)
{
	return _absts2relms_roundup(CLOCK_MONOTONIC, abstimeout);
}

void
relms2absts(int ms, struct timespec *abstimeout)
{
	_relms2absts(CLOCK_MONOTONIC, ms, abstimeout);
}

int
absts2relms_realtime_roundup(const struct timespec *abstimeout)
{
	return _absts2relms_roundup(CLOCK_REALTIME, abstimeout);
}

void
relms2absts_realtime(int ms, struct timespec *abstimeout)
{
	_relms2absts(CLOCK_REALTIME, ms, abstimeout);
}
