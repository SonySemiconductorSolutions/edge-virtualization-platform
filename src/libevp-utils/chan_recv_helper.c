/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <pthread.h>
#include <stddef.h>

#include <internal/chan.h>

#include "chan_def.h"

/*
 * This function must be called with ch->m locked.
 */
int
chan_recv_helper(struct chan *ch)
{
	struct chan_item *it = chan_dequeue(ch);

	pthread_mutex_unlock(&ch->m);

	/*
	 * We already dequed the queue item and we can process
	 * the chan message and deliver the response in the
	 * synchronous case
	 */
	it->msg.fn(&it->msg);
	if (it->msg.resp) {
		/*
		 * synchronous msg, `it' is freed by the
		 * sender which is waiting in it->cond.
		 * The signal function is called with the mutex
		 * taken to avoid the race condition where the
		 * item is freed by the other thread before
		 * we are able to finish correctly.
		 */
		sem_post(&it->sem);
	} else {
		/*
		 * asynchronous msg, we have to free `it'
		 * because the sender does not care anymore
		 * about `it'
		 */
		chan_item_dealloc(it);
	}

	return 1;
}
