/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _POSIX_C_SOURCE 200809L

#include <stdlib.h>
#include <string.h>

#include <evp/sdk_sys.h>

#include <internal/chan.h>
#include <internal/string_map.h>

#include "../main_loop.h"
#include "../platform.h"
#include "../xlog.h"
#include "sys.h"

static void
send_telemetry(struct chan_msg *msg)
{
	enum SYS_result *err = msg->resp;
	struct sys_telemetry *st = msg->param;
	struct sys_group *gr = st->c->gr;

	st->next = gr->telemetries;
	gr->telemetries = st;
	main_loop_wakeup("TELEMETRY");
	*err = SYS_RESULT_OK;
}

enum SYS_result
SYS_send_telemetry(struct SYS_client *c, const char *topic, const char *value,
		   SYS_telemetry_cb cb, void *user)
{
	enum SYS_result err;
	struct sys_telemetry *st = malloc(sizeof(*st));
	char *valuedup = plat_mod_mem_mng_strdup(value);
	char *topicdup = plat_mod_mem_mng_strdup(topic);

	if (!valuedup || !topicdup || !st) {
		xlog_error("failed to copy telemetry data");
		err = SYS_RESULT_ERROR_NO_MEM;
		goto failure;
	}

	*st = (struct sys_telemetry){
		.c = c,
		.cb = cb,
		.topic = topicdup,
		.value = valuedup,
		.user = user,
	};

	struct chan_msg msg = {
		.fn = send_telemetry,
		.param = st,
		.resp = &err,
	};

	main_loop_wakeup(__func__);

	if (chan_send(c->gr->ch, &msg) == 0) {
		return SYS_RESULT_ERROR_NO_MEM;
	}

	if (err) {
		goto failure;
	}

	return SYS_RESULT_OK;

failure:
	free(topicdup);
	free(valuedup);
	free(st);
	return err;
}
