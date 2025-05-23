/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <time.h>

#include <internal/chan.h>

#include "chan_def.h"

int
chan_timedrecv(struct chan *ch, int ms)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	ts.tv_sec += ms / 1000;
	ts.tv_nsec += (ms % 1000) * 1000000;

	if (ts.tv_nsec >= 1000000000) {
		ts.tv_sec += ts.tv_sec / 1000000000;
		ts.tv_nsec %= 1000000000;
	}

	/*
	 * Try to get a message from the channel queue.  If the queue is
	 * empty then wait to someone signal a send
	 */
	pthread_mutex_lock(&ch->m);
	while (ch->head == NULL) {
		int r;
		struct timespec now;

		clock_gettime(CLOCK_MONOTONIC, &now);

		if (now.tv_sec > ts.tv_sec ||
		    (now.tv_sec == ts.tv_sec && now.tv_nsec >= ts.tv_nsec)) {
			pthread_mutex_unlock(&ch->m);
			return 0;
		}

		r = pthread_cond_timedwait(&ch->cond, &ch->m, &ts);

		if (r != 0 && r != ETIMEDOUT) {
			pthread_mutex_unlock(&ch->m);
			return 0;
		}
	}

	return chan_recv_helper(ch);
}
