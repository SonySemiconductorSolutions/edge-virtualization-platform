/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <internal/chan.h>
#include <internal/string_map.h>

#include "../xlog.h"
#include "sys.h"

struct closure {
	const struct sys_command *cmd;
	char *params;
	SYS_response_id id;
};

static void
call_ddc_cb(struct chan_msg *msg)
{
	struct closure *cl = msg->param;
	const struct sys_command *cmd = cl->cmd;

	cmd->fn(cmd->c, cl->id, cl->params, cmd->user);
	free(cl->params);
	free(cl);
}

int
sys_notify_ddc(struct sys_group *gr, const char *method, const char *params,
	       SYS_response_id id)
{
	struct closure *cl = NULL;
	char *paramsdup = NULL;
	const struct sys_command *cmd = string_map_lookup(gr->ddc_map, method);

	if (!cmd) {
		xlog_warning("notify for unknown system method '%s'", method);
		goto failure;
	}

	if (!(paramsdup = strdup(params))) {
		xlog_error("strdup params failed with errno %d", errno);
		goto failure;
	}

	if ((cl = malloc(sizeof(*cl))) == NULL) {
		xlog_error("out of memory notifying '%s'", method);
		goto failure;
	}

	*cl = (struct closure){
		.params = paramsdup,
		.cmd = cmd,
		.id = id,
	};

	struct chan_msg msg = {
		.fn = call_ddc_cb,
		.param = cl,
	};

	if (chan_send(cmd->c->ch, &msg) == 0) {
		xlog_error("out of memory delivering command '%s'", method);
		goto failure;
	}

	return 0;

failure:
	free(paramsdup);
	free(cl);
	return -1;
}
