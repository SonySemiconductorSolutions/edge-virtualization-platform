/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef CHAN_DEF_H_
#define CHAN_DEF_H_

#include <pthread.h>
#include <semaphore.h>

#include <internal/chan.h>

struct chan_item {
	sem_t sem;
	pthread_cond_t cond;
	struct chan_msg msg;
	struct chan_item *next;
};

struct chan {
	pthread_mutex_t m;
	pthread_cond_t cond;
	struct chan_item *head, *tail;
};

struct chan_item *chan_item_alloc(void);
void chan_item_dealloc(struct chan_item *it);
void chan_enqueue(struct chan *ch, struct chan_item *it, struct chan_msg *msg);
struct chan_item *chan_dequeue(struct chan *ch);
int chan_recv_helper(struct chan *ch);
int chan_size(struct chan *ch);

#endif
