/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stddef.h>

#include <internal/chan.h>

#include "chan_def.h"

void
chan_enqueue(struct chan *ch, struct chan_item *it, struct chan_msg *msg)
{
	it->msg = *msg;

	if (ch->tail == NULL) {
		ch->tail = ch->head = it;
	} else {
		ch->tail->next = it;
		ch->tail = it;
	}
}
