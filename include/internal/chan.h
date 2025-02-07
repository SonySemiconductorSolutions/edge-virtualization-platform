/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef CHAN_H_
#define CHAN_H_

struct chan;

struct chan_msg {
	void (*fn)(struct chan_msg *);
	void *param;
	void *resp;
};

struct chan *chan_alloc(void);
void chan_dealloc(struct chan *ch);

int chan_recv(struct chan *ch);
int chan_tryrecv(struct chan *ch);
int chan_timedrecv(struct chan *ch, int ms);
int chan_send(struct chan *ch, struct chan_msg *msg);

#endif
