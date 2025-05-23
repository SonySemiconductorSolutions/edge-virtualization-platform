/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <pthread.h>
#include <stddef.h>

#include <internal/chan.h>

#include "chan_def.h"

struct chan_item *
chan_dequeue(struct chan *ch)
{
	struct chan_item *it;

	/*
	 * Ok, we have an item in the chan queue and we can
	 * dequeue it and keep it locked
	 */
	it = ch->head;
	ch->head = it->next;
	if (ch->head == NULL)
		ch->tail = NULL;

	return it;
}
