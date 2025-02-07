/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "sdkutil.h"

void
gettime(struct timespec *now)
{
	int ret = clock_gettime(CLOCK_MONOTONIC, now);
	if (ret != 0) {
		fprintf(stderr, "Clockid %i not supported.", CLOCK_MONOTONIC);
		abort();
	}
}
