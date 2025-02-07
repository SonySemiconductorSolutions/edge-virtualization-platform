/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>

#include <evp/sdk_sys.h>

#include <internal/chan.h>

#include "../xlog.h"
#include "sys.h"

static void
process_response(struct chan_msg *msg)
{
	struct sys_response *r = msg->param;

	r->cb(r->c, r->reason, r->user);
	free(r->response);
	free(r);
}

static int
collect(struct SYS_client *c, sys_collect_cb cb, void *user)
{
	struct sys_response *r;

	for (r = c->resp_head; r; r = r->next) {
		if (cb(r->id, r->response, r->status, user)) {
			r->reason = SYS_REASON_ERROR;
		} else {
			r->reason = SYS_REASON_FINISHED;
		}

		struct chan_msg msg = {
			.fn = process_response,
			.param = r,
		};

		if (!chan_send(c->ch, &msg)) {
			xlog_error("chan_send failed");
			return -1;
		}
	}

	/* Responses will be released by process_response asynchronously,
	 * so it is no longer needed to keep track of them. */
	c->resp_head = c->resp_tail = NULL;
	return 0;
}

int
sys_collect_responses(struct sys_group *gr, sys_collect_cb cb, void *user)
{
	struct SYS_client *c, *next;

	for (c = gr->list; c; c = next) {
		int ret = collect(c, cb, user);

		if (ret) {
			return ret;
		}

		next = c->next;

		if (next == gr->list) {
			break;
		}
	}

	return 0;
}
