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

struct state {
	struct SYS_client *c;
	const char *key, *value;
};

static void
set_state(struct chan_msg *msg)
{
	const struct state *s = msg->param;
	struct SYS_client *c = s->c;
	struct sys_group *gr = c->gr;
	char *valuedup = plat_mod_mem_mng_strdup(s->value);
	enum SYS_result *err = msg->resp;

	if (valuedup == NULL) {
		*err = SYS_RESULT_ERROR_NO_MEM;
		return;
	}

	if (string_map_insert(gr->state_map, s->key, valuedup, 1)) {
		free(valuedup);
		*err = SYS_RESULT_ERROR_NO_MEM;
	} else {
		main_loop_wakeup("STATE");
		*err = SYS_RESULT_OK;
	}
}

enum SYS_result
SYS_set_state(struct SYS_client *c, const char *key, const char *value)
{
	enum SYS_result err;
	struct chan_msg msg = {
		.fn = set_state,
		.param = &(struct state){.c = c, .key = key, .value = value},
		.resp = &err};

	main_loop_wakeup(__func__);

	if (chan_send(c->gr->ch, &msg) == 0) {
		return SYS_RESULT_ERROR_NO_MEM;
	}

	return err;
}
