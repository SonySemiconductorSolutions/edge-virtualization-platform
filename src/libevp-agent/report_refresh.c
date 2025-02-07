/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <evp/agent.h>
#include <parson.h>

#include <internal/util.h>

#include "agent_internal.h"
#include "base64.h"
#include "global.h"
#include "hub.h"
#include "persist.h"
#include "report.h"
#include "req.h"
#include "sdk_agent.h"
#include "sys/sys.h"
#include "xlog.h"

struct convert_state_args {
	const struct evp_hub_context *hub;
	JSON_Object *o;
	bool states_updated;
};

static void
convert_state(const char *module_instance, const char *topic, const void *blob,
	      size_t bloblen, void *user)
{
	struct convert_state_args *args = user;
	JSON_Object *o = args->o;

	char *name;
	xasprintf(&name, "state/%s/%s", module_instance, topic);
	if (args->hub->convert_state(o, name, blob, bloblen) == 0) {
		args->states_updated = true;
	}
	free(name);
}

int
hub_evp1_convert_state(JSON_Object *o, const char *name, const void *blob,
		       size_t bloblen)
{
	char *base64 = NULL;
	size_t base64len;
	int ret;
	ret = base64_encode(blob, bloblen, &base64, &base64len);
	if (ret != 0) {
		xlog_error("base64_encode: failed encoding blob");
	} else {
		if (json_object_set_string(o, name, base64) != JSONSuccess) {
			xlog_error("json_object_set_string: failed setting %s "
				   "to %s",
				   name, base64);
			ret = -1;
		}
	}
	free(base64);
	return ret;
}

int
hub_evp2_convert_state(JSON_Object *o, const char *name, const void *blob,
		       size_t bloblen)
{
	char *str = xmalloc(bloblen + 1);
	memcpy(str, blob, bloblen);
	str[bloblen] = '\0';
	int ret = 0;
	if (json_object_set_string(o, name, str) != JSONSuccess) {
		xlog_error("json_object_set_string: failed setting %s "
			   "to %s",
			   name, str);
		ret = -1;
	}
	free(str);
	return ret;
}

char *
report_refresh_status(const struct evp_agent_context *agent,
		      const struct evp_hub_context *hub, void *cb_data,
		      intmax_t *qos, enum req_priority *priority)
{
	JSON_Object *current_obj = json_value_get_object(g_evp_global.current);

	/* Update the systemInfo only if the new value is valid
	 *
	 * TODO:
	 * 	It doesn't make sense to generate the sytemInfo each time, as
	 * 	this value remains constant during agent execution
	 */
	JSON_Value *system_info_value = hub->get_system_info();
	if (system_info_value != NULL) {
		json_object_set_value(current_obj, "systemInfo",
				      system_info_value);
	}

	/* TODO: no error checks are done by refresh_report or its caller,
	 * so errors from device_state_add will be ignored as well. */
	hub->device_state_add(current_obj);
	hub->deployment_status_add(current_obj);

	save_current(agent);

	/*
	 * Note: this doesn't remove keys. I'm not even sure if there's
	 * a way to remove client attributes.
	 */

	config_get_int(EVP_CONFIG_MQTT_MFS_QOS, qos);
	*priority = REQ_PRIORITY_MFS;
	return json_serialize_to_string(g_evp_global.current);
}

char *
report_refresh_instance_state(const struct evp_agent_context *agent,
			      const struct evp_hub_context *hub, void *cb_data,
			      intmax_t *qos, enum req_priority *priority)
{
	JSON_Object *states_obj =
		json_value_get_object(g_evp_global.instance_states);
	bool *state_updated = cb_data;

	/*
	 * State from module instances
	 */
	struct convert_state_args args = {.hub = hub, .o = states_obj};
	sdk_collect_states(convert_state, &args);
	sys_collect_states(agent->sys, convert_state, &args);
	*state_updated = args.states_updated;

	*qos = 0;
	*priority = REQ_PRIORITY_LOW;
	return json_serialize_to_string(g_evp_global.instance_states);
}

void
clean_instance_state(const char *id)
{
	size_t len;
	char *topic;
	JSON_Object *o;
	const char *name;

	len = xasprintf(&topic, "state/%s/", id) - 1;
	o = json_value_get_object(g_evp_global.instance_states);

	if (o) {
		size_t n;

		for (n = json_object_get_count(o); n > 0; n--) {
			name = json_object_get_name(o, n - 1);
			if (strncmp(topic, name, len))
				continue;
			json_object_remove(o, name);
		}
	}

	free(topic);
}
