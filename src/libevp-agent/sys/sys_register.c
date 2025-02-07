/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <internal/chan.h>

#include "../main_loop.h"
#include "../xlog.h"
#include "sys.h"

static void
insert(struct chan_msg *msg)
{
	struct SYS_client *c = msg->param;
	struct sys_group *gr = c->gr;

	if (!gr->list) {
		gr->list = c->prev = c->next = c;
	} else {
		c->next = gr->list;
		c->prev = gr->list->prev;
		c->prev->next = c->next->prev = c;
	}
}

struct SYS_client *
sys_register(struct sys_group *gr)
{
	struct SYS_client *c = sys_client_alloc(gr);

	if (c == NULL) {
		xlog_error("sys_client_alloc failed");
		goto failure;
	}

	struct chan_msg msg = {
		.fn = insert,
		.param = c,
		/* Force synchronous transaction. */
		.resp = &(int){0},
	};

	main_loop_wakeup(__func__);

	if (!chan_send(gr->ch, &msg)) {
		xlog_error("chan_send failed");
		goto failure;
	}

	return c;

failure:
	sys_client_dealloc(c);
	return NULL;
}
