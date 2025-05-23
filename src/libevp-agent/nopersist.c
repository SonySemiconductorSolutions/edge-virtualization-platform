/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <parson.h>

#include "global.h"
#include "persist.h"
#include "xlog.h"

void
init_local_twins_db(void)
{
}

void
deinit_local_twins_db(void)
{
}

void
save_desired(const struct evp_agent_context *agent)
{
	JSON_Value *v = g_evp_global.desired;
	if (v == NULL) {
		xlog_error("desired is not initialized");
	}
}

void
save_current(const struct evp_agent_context *agent)
{
	JSON_Value *v = g_evp_global.current;
	if (v == NULL) {
		xlog_error("current is not initialized");
	}
}

void
load_desired(struct evp_agent_context *ctxt)
{
	if (g_evp_global.desired != NULL) {
		xlog_error("load_desired: desired already loaded");
		return;
	}
	g_evp_global.desired = json_value_init_object();
	if (g_evp_global.desired == NULL) {
		xlog_error("json_value_init_object failed");
	}
}

void
load_current(struct evp_agent_context *agent)
{
	if (g_evp_global.current != NULL) {
		xlog_error("load_current: current already loaded");
		return;
	}
	g_evp_global.current = json_value_init_object();
	if (g_evp_global.current == NULL) {
		xlog_error("json_value_init_object failed");
	}
}

void
save_json(const char *filename, const JSON_Value *v)
{
}
