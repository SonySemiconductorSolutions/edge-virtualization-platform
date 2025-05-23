/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>

#include <internal/chan.h>

#include "chan_def.h"

void
chan_dealloc(struct chan *ch)
{
	struct chan_item *it, *next;

	pthread_cond_destroy(&ch->cond);
	pthread_mutex_destroy(&ch->m);

	for (it = ch->head; it; it = next) {
		next = it->next;
		chan_item_dealloc(it);
	}

	free(ch);
}
