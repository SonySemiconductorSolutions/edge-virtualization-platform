/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef EVP_HUB_H
#define EVP_HUB_H

#include <stdbool.h>

#include <evp/sdk_types.h>
#include <parson.h>

struct transport_ctxt;
struct telemetry_entries;
struct direct_command_response;
struct evp_agent_context;
struct request;
struct device_config;
struct instance_config_req;
struct instance_config_reqs;
struct storagetoken_data;
struct storagetoken_response;
struct storagetoken_ack_data;
struct Deployment;

enum evp_hub_type {
	EVP_HUB_TYPE_EVP1_TB,
	EVP_HUB_TYPE_EVP2_TB,
	EVP_HUB_TYPE_UNKNOWN
};

struct evp_hub_context {
	void (*on_connected)(struct evp_agent_context *ctxt,
			     struct transport_ctxt *transport,
			     const char *device_id, const char *client_id);
	void (*on_message)(struct evp_agent_context *ctxt, const char *topic,
			   int packet_id, int qos_level, const char *payload);
	bool (*is_ready)(void);
	int (*send_telemetry)(
		struct transport_ctxt *ctxt,
		const struct telemetry_entries *telemetry_entries);
	int (*device_state_add)(JSON_Object *o);
	int (*deployment_status_add)(JSON_Object *o);
	JSON_Value *(*get_system_info)(void);
	int (*send_direct_command_response)(
		struct transport_ctxt *ctxt,
		struct direct_command_response *response);
	int (*send_periodic_report)(struct request *req);
	JSON_Value *(*storagetoken_request_payload_create)(
		struct storagetoken_data *st_data);
	int (*send_storagetoken_request)(struct evp_agent_context *agent,
					 struct request *req, JSON_Value *v);
	int (*parse_device_config)(JSON_Value *payload,
				   struct device_config *cp);
	void (*update_desired_device_config)(struct device_config *cp);
	int (*parse_instance_config)(JSON_Value *payload,
				     struct instance_config_reqs *reqs);
	int (*storagetoken_response_parse)(const JSON_Object *payload,
					   struct storagetoken_response *resp);
	int (*parse_deployment)(JSON_Value *value, struct Deployment **rp);
	int (*convert_state)(JSON_Object *o, const char *name,
			     const void *blob, size_t bloblen);
	int (*notify_config)(const char *instance, const char *name,
			     const char *value);
	const char *impl_name;
	int (*check_backdoor)(const JSON_Value *deployment,
			      const char *instanceId, bool *out);
};

enum evp_hub_type get_hub_type(const char *iot_platform);
const struct evp_hub_context *evp_hub_setup(const char *config);

#endif
