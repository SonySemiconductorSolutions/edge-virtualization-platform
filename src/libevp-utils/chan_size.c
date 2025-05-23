/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <pthread.h>

#include <internal/chan.h>

#include "chan_def.h"

int
chan_size(struct chan *ch)
{
	struct chan_item *it;
	int n = 0;

	pthread_mutex_lock(&ch->m);

	for (it = ch->head; it; it = it->next)
		n++;

	pthread_mutex_unlock(&ch->m);

	return n;
}
