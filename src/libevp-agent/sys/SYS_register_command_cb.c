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

#include "sys.h"

static void
register_command(struct chan_msg *msg)
{
	enum SYS_result *err = msg->resp;
	const struct sys_command *p = msg->param;
	struct sys_command *cmd;
	struct sys_group *gr = p->c->gr;

	if (!(cmd = malloc(sizeof(*cmd)))) {
		*err = SYS_RESULT_ERROR_NO_MEM;
		return;
	}

	*cmd = *p;

	if (string_map_insert(gr->ddc_map, p->command, cmd, false)) {
		if (errno == EEXIST) {
			*err = SYS_RESULT_ERROR_ALREADY_REGISTERED;
		} else {
			*err = SYS_RESULT_ERROR_NO_MEM;
		}

		free(cmd->command);
		free(cmd);
		return;
	}

	*err = SYS_RESULT_OK;
}

enum SYS_result
SYS_register_command_cb(struct SYS_client *c, const char *command,
			SYS_command_cb cb, void *user)
{
	enum SYS_result err;
	char *namedup = strdup(command);

	if (!namedup) {
		return SYS_RESULT_ERROR_NO_MEM;
	}

	struct chan_msg msg = {
		.fn = register_command,
		.param =
			&(struct sys_command){
				.c = c,
				.command = namedup,
				.fn = cb,
				.user = user,
			},
		.resp = &err,
	};

	if (chan_send(c->gr->ch, &msg) == 0) {
		free(namedup);
		return SYS_RESULT_ERROR_NO_MEM;
	}

	return err;
}
