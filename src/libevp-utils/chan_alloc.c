/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>

#include <internal/chan.h>

#include "chan_def.h"

struct chan *
chan_alloc(void)
{
	struct chan *ch;
	pthread_condattr_t cond_attr;
	pthread_cond_t cond;

	if (pthread_condattr_init(&cond_attr) != 0) {
		goto err;
	}

	if (pthread_condattr_setclock(&cond_attr, CLOCK_MONOTONIC) != 0) {
		goto err;
	}

	if ((pthread_cond_init(&cond, &cond_attr)) != 0)
		goto err;

	if ((ch = malloc(sizeof(*ch))) == NULL)
		goto err;

	*ch = (struct chan){
		.m = PTHREAD_MUTEX_INITIALIZER,
		.cond = cond,
	};

	pthread_condattr_destroy(&cond_attr);
	return ch;

err:
	pthread_condattr_destroy(&cond_attr);
	pthread_cond_destroy(&cond);

	return NULL;
}
