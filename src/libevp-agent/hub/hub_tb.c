/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stdlib.h>

#include <parson.h>

#include <internal/util.h>

#include "../evp_hub.h"
#include "../req.h"
#include "../telemetry.h"
#include "../xlog.h"

static JSON_Value *
compose_telemetry_payload(const struct telemetry_entries *telemetry_entries)
{
	/*
	 * Convert to:
	 *   {
	 *     "<module_instance_name>/<topic>": <value>,
	 *   }
	 */
	JSON_Value *value = json_value_init_object();
	JSON_Object *obj = json_value_get_object(value);
	for (size_t i = 0; i < telemetry_entries->n; ++i) {
		struct telemetry_entry *entry = &telemetry_entries->entries[i];
		char *name;

		xasprintf(&name, "%s/%s", entry->module_instance,
			  entry->topic);
		JSON_Value *jvalue = json_parse_string(entry->value);
		if (jvalue == NULL) {
			xlog_warning("convert_telemetry: invalid value: %s",
				     entry->value);
		} else {
			json_object_set_value(obj, name, jvalue);
		}
		free(name);
	}
	return value;
}

int
hub_tb_send_telemetry(struct transport_ctxt *ctxt,
		      const struct telemetry_entries *telemetry_entries)
{
	JSON_Value *value = compose_telemetry_payload(telemetry_entries);
	char *payload = json_serialize_to_string(value);
	json_value_free(value);
	if (payload == NULL) {
		xlog_error("Failed to allocate telemetry payload");
		return ENOMEM;
	} else {
		struct request *req = request_alloc();
		req->topic_template = "v1/devices/me/telemetry";
		req->payload = payload;
		req->payload_free = request_free_json_payload;
		if (request_insert(req)) {
			request_free(req);
			return EAGAIN;
		}
	}

	return 0;
}

int
hub_tb_send_periodic_report(struct request *req)
{
	req->topic_template = "v1/devices/me/attributes";
	return request_insert(req);
}

int
hub_tb_send_rpc_request(struct evp_agent_context *agent, struct request *req,
			JSON_Value *v)
{
	req->payload = json_serialize_to_string(v);
	req->payload_free = request_free_json_payload;
	req->topic_template = "v1/devices/me/rpc/request/%ju";
	return request_insert(req);
}
