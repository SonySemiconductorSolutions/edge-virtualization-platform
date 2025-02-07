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

static void
_relms2absts(clockid_t clockid, int ms, struct timespec *abstimeout)
{
	struct timespec now;
	struct timespec diff;
	int ret;

	ret = clock_gettime(clockid, &now);
	if (ret != 0) {
		fprintf(stderr, "Clockid %i not supported.", clockid);
		abort();
	}
	diff.tv_sec = ms / 1000;
	diff.tv_nsec = (ms % 1000) * 1000000;
	timespecadd(&now, &diff, abstimeout);
}

void
relms2absts_realtime(int ms, struct timespec *abstimeout)
{
	_relms2absts(CLOCK_REALTIME, ms, abstimeout);
}
