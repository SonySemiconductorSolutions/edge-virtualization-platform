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
chan_recv(struct chan *ch)
{
	pthread_mutex_lock(&ch->m);
	while (ch->head == NULL) {
		if (pthread_cond_wait(&ch->cond, &ch->m)) {
			return 0;
		}
	}

	return chan_recv_helper(ch);
}
