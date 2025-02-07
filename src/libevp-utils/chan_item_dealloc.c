/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <pthread.h>
#include <semaphore.h>
#include <stddef.h>
#include <stdlib.h>

#include <internal/chan.h>

#include "chan_def.h"

void
chan_item_dealloc(struct chan_item *it)
{
	if (!it)
		return;
	sem_destroy(&it->sem);
	pthread_cond_destroy(&it->cond);
	free(it);
}
