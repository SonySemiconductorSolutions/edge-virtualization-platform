/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>

#include <evp/sdk_sys.h>

#include <internal/chan.h>
#include <internal/string_map.h>

#include "../xlog.h"
#include "sys.h"

static void
on_sent_telemetry(struct chan_msg *msg)
{
	struct sys_telemetry *t = msg->param;

	t->cb(t->c, SYS_REASON_FINISHED, t->user);
	sys_telemetry_dealloc(t);
}

static void
on_failed_telemetry(struct chan_msg *msg)
{
	struct sys_telemetry *t = msg->param;

	t->cb(t->c, SYS_REASON_ERROR, t->user);
	sys_telemetry_dealloc(t);
}

static int
collect(struct sys_telemetry *t, sys_telemetry_collect cb, void *user)
{
	struct SYS_client *c = t->c;

	if (cb(t->topic, t, user)) {
		struct chan_msg msg = {
			.fn = on_failed_telemetry,
			.param = t,
		};

		xlog_error("user callback failed");

		if (!chan_send(c->ch, &msg)) {
			xlog_error("chan_send failed");
		}

		return -1;
	}

	struct chan_msg msg = {
		.fn = on_sent_telemetry,
		.param = t,
	};

	if (!chan_send(c->ch, &msg)) {
		xlog_error("chan_send failed");
		return -1;
	}

	return 0;
}

int
sys_collect_telemetry(struct sys_group *gr, sys_telemetry_collect cb,
		      void *user)
{
	struct sys_telemetry *next;

	for (struct sys_telemetry *t = gr->telemetries; t; t = next) {
		next = t->next;

		if (collect(t, cb, user)) {
			gr->telemetries = next;
			return -1;
		}
	}

	gr->telemetries = NULL;
	return 0;
}
