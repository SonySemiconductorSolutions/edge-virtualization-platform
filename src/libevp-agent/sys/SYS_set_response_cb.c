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
set_response(struct chan_msg *msg)
{
	struct sys_response *r = msg->param;
	enum SYS_result *err = msg->resp;
	struct SYS_client *c = r->c;

	if (!c->resp_head) {
		c->resp_head = r;
	} else if (c->resp_tail) {
		c->resp_tail->next = r;
	}

	c->resp_tail = r;
	*err = SYS_RESULT_OK;
}

enum SYS_result
SYS_set_response_cb(struct SYS_client *c, SYS_response_id id,
		    const char *response, enum SYS_response_status status,
		    SYS_response_cb cb, void *user)
{
	enum SYS_result err;
	struct sys_response *r = NULL;
	char *rdup = plat_mod_mem_mng_strdup(response);

	if (!rdup) {
		err = SYS_RESULT_ERROR_NO_MEM;
		goto failure;
	}

	r = malloc(sizeof(*r));

	if (!r) {
		err = SYS_RESULT_ERROR_NO_MEM;
		goto failure;
	}

	*r = (struct sys_response){
		.c = c,
		.id = id,
		.response = rdup,
		.status = status,
		.cb = cb,
		.user = user,
	};

	struct chan_msg msg = {
		.fn = set_response,
		.param = r,
		.resp = &err,
	};

	main_loop_wakeup(__func__);

	if (!chan_send(c->gr->ch, &msg)) {
		xlog_error("chan_send failed");
		err = SYS_RESULT_ERROR_NO_MEM;
		goto failure;
	}

	return err;

failure:
	free(rdup);
	free(r);
	return err;
}
