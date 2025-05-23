/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <internal/chan.h>

#include "../xlog.h"
#include "sys.h"

static void
remove(struct chan_msg *msg)
{
	struct SYS_client *c = msg->param;
	struct sys_group *gr = c->gr;

	if (c->next == c) {
		gr->list = NULL;
	} else {
		c->next->prev = c->prev;
		c->prev->next = c->next;

		if (gr->list == c) {
			gr->list = c->next;
		}
	}

	sys_client_dealloc(c);
}

int
sys_unregister(struct sys_group *gr, struct SYS_client *c)
{
	if (c->gr != gr) {
		xlog_error(
			"SYS_client instance %p does not belong to this group",
			(void *)c);
		return -1;
	}

	struct chan_msg msg = {.fn = remove,
			       .param = c,
			       /* Force synchronous response. */
			       .resp = &(int){0}};

	if (!chan_send(gr->ch, &msg)) {
		xlog_error("chan_send failed");
		return -1;
	}

	return 0;
}
