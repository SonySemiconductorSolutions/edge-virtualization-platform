/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <stddef.h>
#include <stdlib.h>

#include <internal/chan.h>

#include "chan_def.h"

int
chan_send(struct chan *ch, struct chan_msg *msg)
{
	struct chan_item *it = chan_item_alloc();

	if (it == NULL) {
		return 0;
	}

	pthread_mutex_lock(&ch->m);
	chan_enqueue(ch, it, msg);
	pthread_cond_signal(&ch->cond);
	pthread_mutex_unlock(&ch->m);

	if (msg->resp) {
		/*
		 * synchronous msg, `it->m' is hold
		 * by this thread and we have to wait
		 * in `it->sem' until the receiver
		 * posts it and then we can free `it'
		 */

		while (sem_wait(&it->sem) && errno == EINTR)
			;

		chan_item_dealloc(it);
	}

	return 1;
}
