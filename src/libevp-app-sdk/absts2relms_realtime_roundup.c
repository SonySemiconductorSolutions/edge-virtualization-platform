/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sys/time.h>

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <internal/time.h>

#include "sdkutil.h"

static int
_absts2relms_roundup(clockid_t clockid, const struct timespec *abstimeout)
{
	int timeout_ms;
	struct timespec now;
	int ret;
	ret = clock_gettime(clockid, &now);
	if (ret != 0) {
		fprintf(stderr, "Clockid %i not supported.", clockid);
		abort();
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
			fprintf(stderr,
				"Calculated time is negative (%i). "
				"Set 0 ms "
				"as a minimum valid value.\n",
				timeout_ms);
			timeout_ms = 0;
		}
	}
	return timeout_ms;
}

int
absts2relms_realtime_roundup(const struct timespec *abstimeout)
{
	return _absts2relms_roundup(CLOCK_REALTIME, abstimeout);
}
