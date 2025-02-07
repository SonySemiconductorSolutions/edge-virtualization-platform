/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <evp/sdk_sys.h>

#include <internal/chan.h>
#include <internal/string_map.h>

#include "../main_loop.h"
#include "../sdk_impl.h"
#include "sys.h"

struct config_priv {
	const char *topic;
	struct sys_config *cfg;
};

static void
set_configuration(struct chan_msg *msg)
{
	enum SYS_result *err = msg->resp;
	const struct config_priv *p = msg->param;
	struct sys_config *cfg = p->cfg;
	struct sys_group *gr = cfg->c->gr;

	cfg->next = string_map_lookup(gr->cfg_map, p->topic);

	if (string_map_insert(gr->cfg_map, p->topic, cfg, true) < 0) {
		*err = SYS_RESULT_ERROR_NO_MEM;
		return;
	}

	sdk_lock();
	g_resend_request = true;
	sdk_unlock();

	main_loop_wakeup("RESEND-REQUEST");
	*err = SYS_RESULT_OK;
	return;
}

enum SYS_result
SYS_set_configuration_cb(struct SYS_client *c, const char *topic,
			 SYS_config_cb cb, enum SYS_type_configuration type,
			 void *user)
{
	enum SYS_result err;
	struct sys_config *cfg = malloc(sizeof(*cfg));

	if (!cfg) {
		return SYS_RESULT_ERROR_NO_MEM;
	}

	*cfg = (struct sys_config){
		.c = c,
		.cb = cb,
		.type = type,
		.user = user,
	};

	struct chan_msg msg = {
		.fn = set_configuration,
		.param =
			&(struct config_priv){
				.cfg = cfg,
				.topic = topic,
			},
		.resp = &err,
	};

	main_loop_wakeup(__func__);

	if (chan_send(c->gr->ch, &msg) == 0) {
		free(cfg);
		return SYS_RESULT_ERROR_NO_MEM;
	}

	return err;
}
