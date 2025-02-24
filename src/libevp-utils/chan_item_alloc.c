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

struct chan_item *
chan_item_alloc(void)
{
	struct chan_item *it;
	if ((it = malloc(sizeof(*it))) == NULL)
		return NULL;

	*it = (struct chan_item){0};

	if (sem_init(&it->sem, 0, 0)) {
		free(it);
		return NULL;
	}

	return it;
}
