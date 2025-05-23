/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <pthread.h>
#include <stddef.h>

#include <internal/chan.h>

#include "chan_def.h"

int
chan_tryrecv(struct chan *ch)
{
	/*
	 * Try to get a message from the channel queue.  If the queue is
	 * empty then wait to someone signal a send
	 */
	pthread_mutex_lock(&ch->m);
	if (ch->head == NULL) {
		pthread_mutex_unlock(&ch->m);
		return 0;
	}

	return chan_recv_helper(ch);
}
