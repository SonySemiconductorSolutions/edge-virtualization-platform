/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <config.h>

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <parson.h>

#include <internal/util.h>

#include "../../agent_internal.h"
#include "../../device_config.h"
#include "../../direct_command.h"
#include "../../global.h"
#include "../../hub.h"
#include "../../instance_config.h"
#include "../../manifest.h"
#include "../../map.h"
#include "../../module.h"
#include "../../module_instance.h"
#include "../../mstp_schema.h"
#include "../../persist.h"
#include "../../req.h"
#include "../../timeutil.h"
#include "../../transport.h"
#include "../../xlog.h"
#include "../../xmqtt.h"

#define REQID_MAP_CAPACITY 16

struct reqid_map_entry {
	bool valid;
	EVP_RPC_ID key;
	EVP_RPC_ID value;
};

struct requid_rbuf_map {
	struct reqid_map_entry pool[REQID_MAP_CAPACITY];
	size_t index;
};

static struct requid_rbuf_map g_reqid_map;

static size_t
reqid_rbuf_advance(size_t pos)
{
	return (pos + 1) % REQID_MAP_CAPACITY;
}

static struct reqid_map_entry *
reqid_rbuf_get_entry(size_t pos)
{
	return &g_reqid_map.pool[pos];
}

static struct reqid_map_entry *
reqid_map_find(EVP_RPC_ID key)
{
	for (size_t i = 0; i < __arraycount(g_reqid_map.pool); i++) {
		struct reqid_map_entry *entry = reqid_rbuf_get_entry(i);
		if (entry->valid && entry->key == key) {
			return entry;
		}
	}
	return NULL;
}

static void
reqid_map_set(EVP_RPC_ID key, EVP_RPC_ID value)
{
	// Use rbuf to insert entry
	size_t index = reqid_rbuf_advance(g_reqid_map.index);
	struct reqid_map_entry *entry = reqid_rbuf_get_entry(index);
	entry->key = key;
	entry->value = value;
	entry->valid = true;
	g_reqid_map.index = index;
}

static void
hub_tb_subscribe_topics(struct transport_ctxt *ctxt)
{
	// Initialize the pool to not use unitiliazed elements (for example
	// reqid=0 was a problem)
	for (size_t i = 0; i < __arraycount(g_reqid_map.pool); i++) {
		struct reqid_map_entry *entry = reqid_rbuf_get_entry(i);
		*entry = (struct reqid_map_entry){0};
	}

	const char *topics[] = {
		// https://thingsboard.io/docs/reference/mqtt-api/#subscribe-to-attribute-updates-from-the-server
		"v1/devices/me/attributes",
		// https://thingsboard.io/docs/reference/mqtt-api/#request-attribute-values-from-the-server
		"v1/devices/me/attributes/response/+",
		// https://thingsboard.io/docs/reference/mqtt-api/#server-side-rpc
		"v1/devices/me/rpc/request/+",
		// https://thingsboard.io/docs/reference/mqtt-api/#client-side-rpc
		"v1/devices/me/rpc/response/+",
	};
	ctxt->initial_get_done = false;
	for (size_t i = 0; i < __arraycount(topics); i++) {
		transport_subscribe(ctxt, topics[i]);
	}
}

static int
parse_patch_topic(const char *topic)
{
	// topic=v1/devices/me/attributes, id=0, qos=0, payload={"test":"this
	// is another test"}

	return strcmp(topic, "v1/devices/me/attributes");
}

/** @brief Try to parse the given topic using the given template.
 *
 * @param topic      Topic to parse
 * @param template   Scanf format string to parse the topic
 * @param reqidp     Address to store the request id on successful parsing
 *
 * @return 0 when it's successfuly parsed. Otherwise, returns
 *         a non zero value.
 */
static int
parse_response_topic(const char *topic, const char *template,
		     EVP_RPC_ID *reqidp)
{
	// topic=v1/devices/me/attributes/response/10000
	// topic=v1/devices/me/rpc/response/10000

	// XXX maybe shouldn't use sscanf
	unsigned long long reqid;
	int ret;
	ret = sscanf(topic, template, &reqid);
	if (ret != 1) {
		return 1;
	}
	if ((EVP_RPC_ID)reqid != reqid) {
		/* overflow */
		return 1;
	}
	*reqidp = reqid;
	return 0;
}

static int
parse_request_topic(const char *topic, EVP_RPC_ID *reqidp)
{
	// topic=v1/devices/me/rpc/request/10000

	// XXX maybe shouldn't use sscanf
	unsigned long long reqid;
	int ret;
	ret = sscanf(topic, "v1/devices/me/rpc/request/%llu", &reqid);
	if (ret != 1) {
		return 1;
	}
	if ((EVP_RPC_ID)reqid != reqid) {
		/* overflow */
		return 1;
	}
	*reqidp = reqid;
	return 0;
}

static void
dispatch_evp1_rpc_request(struct evp_agent_context *ctxt, EVP_RPC_ID id,
			  const char *payload)
{
	JSON_Value *json;
	struct direct_command_request *req = NULL;

	json = json_parse_string(payload);
	if (!json) {
		xlog_error("%s: direct command with invalid json", __func__);
		goto out;
	}

	JSON_Value *mdc_payload = json;

	req = parse_evp1_direct_command(id, mdc_payload);
	if (req == NULL) {
		xlog_error("%s: direct command with wrong format", __func__);
		goto out;
	}

	/*
	 * Try to map topic id to request id.
	 * Skip handling message if a key is already present.
	 */
	if (reqid_map_find(req->reqid)) {
		xlog_error("direct command request with duplicate ID %" PRIu64,
			   req->reqid);
		goto out;
	}

	reqid_map_set(req->reqid, id);
	evp_process_direct_command_request(ctxt, req);

out:
	direct_command_request_dtor(req);
	json_value_free(json);
}

static void
dispatch_evp2_rpc_request(struct evp_agent_context *ctxt, EVP_RPC_ID id,
			  const char *payload)
{
	JSON_Value *json;
	struct direct_command_request *req = NULL;

	json = json_parse_string(payload);
	if (!json) {
		xlog_error("%s: direct command with invalid json", __func__);
		goto out;
	}

	/* Unwrap TB payload for EVP2 */
	JSON_Object *o = json_value_get_object(json);
	JSON_Value *mdc_payload = json_object_get_value(o, "params");

	req = parse_evp2_direct_command(mdc_payload);
	if (req == NULL) {
		xlog_error("%s: direct command with wrong format", __func__);
		goto out;
	}

	/*
	 * Try to map topic id to request id.
	 * Skip handling message if a key is already present.
	 */
	if (reqid_map_find(req->reqid)) {
		xlog_error("direct command request with duplicate ID %" PRIu64,
			   req->reqid);
		goto out;
	}

	reqid_map_set(req->reqid, id);
	evp_process_direct_command_request(ctxt, req);

out:
	direct_command_request_dtor(req);
	json_value_free(json);
}

static void
dispatch_evp1_update_request(struct evp_agent_context *ctxt, JSON_Value *json)
{
	JSON_Value *deployment;

	// process deployment manifest if present
	if (!try_load_deployment(json, &deployment)) {
		save_deployment(ctxt, deployment);
	}

	struct instance_config_reqs reqs;

	// process module instance configuration if present
	if (!hub_evp1_parse_instance_config(json, &reqs)) {
		evp_process_instance_config(ctxt, &reqs, EVP_CONFIG_HUB);
		instance_config_reqs_dtor(&reqs);
	}
}

static void
dispatch_evp2_update_request(struct evp_agent_context *ctxt, JSON_Value *json)
{
	JSON_Value *deployment;
	JSON_Value *value;
	JSON_Object *obj = json_value_get_object(json);

	// process deployment manifest if present
	if (!try_load_deployment(json, &deployment)) {
		save_deployment(ctxt, deployment);
	}

	// process device configuration if present
	// As Thingsboard cannot have null values at the top
	// level there is a wrapper with the same name than
	// the object defined in the onwire schema
	value = json_object_get_value(obj, "desiredDeviceConfig");
	if (value) {
		struct device_config cp;

		if (!hub_evp2_parse_device_config(value, &cp)) {
			hub_received_device_config(ctxt, &cp);
			device_config_dtor(&cp);
		}
	}

	struct instance_config_reqs reqs;

	// process module instance configuration if present
	if (!hub_evp2_parse_instance_config(json, &reqs)) {
		evp_process_instance_config(ctxt, &reqs, EVP_CONFIG_HUB);
		instance_config_reqs_dtor(&reqs);
	}
}

static int
parse_rpc_response_topic_reqid(const char *topic, EVP_RPC_ID *id)
{
	return parse_response_topic(topic, "v1/devices/me/rpc/response/%llu",
				    id);
}

static int
parse_attr_response_topic_reqid(const char *topic, EVP_RPC_ID *id)
{

	return parse_response_topic(
		topic, "v1/devices/me/attributes/response/%llu", id);
}

static int
parse_response_topic_reqid(const char *topic, EVP_RPC_ID *id)
{
	if (!parse_rpc_response_topic_reqid(topic, id)) {
		return 0;
	}

	if (!parse_attr_response_topic_reqid(topic, id)) {
		return 0;
	}

	return 1;
}

void
hub_evp1_tb_on_message(struct evp_agent_context *ctxt, const char *topic,
		       int packet_id, int qos_level, const char *payload)
{
	EVP_RPC_ID id;
	if (!parse_request_topic(topic, &id)) {
		xlog_info("got an RPC request with request id %ju",
			  (uintmax_t)id);
		dispatch_evp1_rpc_request(ctxt, id, payload);
		return;
	}

	if (!parse_patch_topic(topic)) {
		xlog_info("got an update notification");
		if (!ctxt->transport_ctxt->initial_get_done) {
			xlog_warning("Ignoring a PATCH before the initial GET "
				     "response");
			return;
		}
		JSON_Value *json = json_parse_string(payload);
		if (json == NULL) {
			xlog_warning(
				"failed to parse payload with topic=%s: %s",
				topic, payload);
			return;
		}
		dispatch_evp1_update_request(ctxt, json);
		json_value_free(json);
		return;
	}

	if (!parse_response_topic_reqid(topic, &id)) {
		xlog_info("got a response reqId %ju", (uintmax_t)id);
		request_handle_response(ctxt, id, __UNCONST(payload));
		return;
	}
	xlog_warning("unknown topic %s", topic);
}

void
hub_evp2_tb_on_message(struct evp_agent_context *ctxt, const char *topic,
		       int packet_id, int qos_level, const char *payload)
{
	EVP_RPC_ID id;
	if (!parse_request_topic(topic, &id)) {
		xlog_info("got an RPC request with request id %ju",
			  (uintmax_t)id);
		dispatch_evp2_rpc_request(ctxt, id, payload);
		return;
	}

	if (!parse_patch_topic(topic)) {
		xlog_info("got an update notification");
		if (!ctxt->transport_ctxt->initial_get_done) {
			xlog_warning("Ignoring a PATCH before the initial GET "
				     "response");
			return;
		}
		JSON_Value *json = json_parse_string(payload);
		if (json == NULL) {
			xlog_warning(
				"failed to parse deployment with topic=%s: %s",
				topic, payload);
		}
		dispatch_evp2_update_request(ctxt, json);
		json_value_free(json);
		return;
	}

	if (!parse_rpc_response_topic_reqid(topic, &id)) {
		xlog_info("got a rpc response reqId %ju", (uintmax_t)id);
		hub_evp2_response_parse_reqid(payload, &id);
		request_handle_response(ctxt, id, __UNCONST(payload));
		return;
	}

	if (!parse_attr_response_topic_reqid(topic, &id)) {
		xlog_info("got an attributes response reqId %ju",
			  (uintmax_t)id);
		request_handle_response(ctxt, id, __UNCONST(payload));
		return;
	}

	xlog_warning("unknown topic %s", topic);
}

// deployment,desiredDeviceConfig,module-instance-config
static void
get_done_evp1(EVP_RPC_ID id, void *cb_data, void *payload, uint32_t delay,
	      int error)
{
	struct evp_agent_context *ctxt = cb_data;

	/*
	 * Note: The request using this callback has no timeout.
	 * This callback is invoked only when we received a response
	 * from the server. Thus "error" is always 0.
	 */
	// TODO: Replace assert (programming error)
	assert(error == 0);

	// Don't print deployment data in INFO level
	// Since it could contain user data
	xlog_debug("get_done (in %" PRIu32 " ms): id=%ju, payload=%s", delay,
		   (uintmax_t)id, (const char *)payload);

	xlog_info("get_done (in %" PRIu32 " ms): id=%ju, length=%zu", delay,
		  (uintmax_t)id, strlen(payload));

	/* Parse payload and process shared attributes. */
	/*
	 * Note: thingsboard returns a dict without "shared" key
	 * when there are no shared attributes.
	 */
	JSON_Value *root = json_parse_string(payload);
	if (root == NULL) {
		xlog_warning("failed to parse payload: %s",
			     (const char *)payload);
		return;
	}
	JSON_Object *obj = json_value_get_object(root);
	JSON_Value *shared = json_object_get_value(obj, "shared");
	dispatch_evp1_update_request(ctxt, shared);

	ctxt->transport_ctxt->initial_get_done = true;
	json_value_free(root);
}

static void
get_done_evp2(EVP_RPC_ID id, void *cb_data, void *payload, uint32_t delay,
	      int error)
{
	struct evp_agent_context *ctxt = cb_data;

	/*
	 * Note: The request using this callback has no timeout.
	 * This callback is invoked only when we received a response
	 * from the server. Thus "error" is always 0.
	 */
	// TODO: Replace assert (programming error)
	assert(error == 0);

	// Don't print deployment data in INFO level
	// Since it could contain user data
	xlog_debug("get_done (in %" PRIu32 " ms): id=%ju, payload=%s", delay,
		   (uintmax_t)id, (const char *)payload);

	xlog_info("get_done (in %" PRIu32 " ms): id=%ju, length=%zu", delay,
		  (uintmax_t)id, strlen(payload));

	/* Parse payload and process shared attributes. */
	/*
	 * Note: thingsboard returns a dict without "shared" key
	 * when there are no shared attributes.
	 */
	JSON_Value *root = json_parse_string(payload);
	if (root == NULL) {
		xlog_warning("failed to parse payload: %s",
			     (const char *)payload);
		return;
	}
	JSON_Object *obj = json_value_get_object(root);
	JSON_Value *shared = json_object_get_value(obj, "shared");
	dispatch_evp2_update_request(ctxt, shared);

	ctxt->transport_ctxt->initial_get_done = true;
	json_value_free(root);
}

static void
hub_tb_request_initial_configs(struct evp_agent_context *ctxt,
			       void (*callback)(EVP_RPC_ID id, void *cb_data,
						void *payload, uint32_t delay,
						int error))
{
	// XXX should we wait for SUBACKs before sending the following
	// GET request?

	// https://thingsboard.io/docs/reference/mqtt-api/#request-attribute-values-from-the-server
	struct request *req = request_alloc();
	req->id = 10000;
	req->topic_template = "v1/devices/me/attributes/request/%ju";
	req->payload = "{}";
	req->callback = callback;
	req->callback_data = ctxt;
	req->resend = true;
	req->timeout_ms = 0;
	if (request_insert(req)) {
		request_free(req);
	}
}

bool
hub_tb_is_ready_to_report(void)
{
	return true;
}

void
hub_evp1_tb_on_connected(struct evp_agent_context *ctxt,
			 struct transport_ctxt *transport,
			 const char *device_id, const char *client_id)
{
	hub_tb_subscribe_topics(transport);
	hub_tb_request_initial_configs(ctxt, get_done_evp1);
}

void
hub_evp2_tb_on_connected(struct evp_agent_context *ctxt,
			 struct transport_ctxt *transport,
			 const char *device_id, const char *client_id)
{
	hub_tb_subscribe_topics(transport);
	hub_tb_request_initial_configs(ctxt, get_done_evp2);
}

int
hub_tb_evp1_send_direct_command_response(
	struct transport_ctxt *ctxt, struct direct_command_response *response)
{
	JSON_Value *value =
		compose_evp1_direct_command_response_payload(response);
	char *payload = json_serialize_to_string(value);
	json_value_free(value);
	if (payload == NULL) {
		xlog_error("Invalid direct_command_response payload");
		return EINVAL;
	} else {
		int ret;
		struct request *req = request_alloc();
		req->topic_template = "v1/devices/me/rpc/response/%ju";
		req->id = response->reqid;
		req->payload = payload;
		req->payload_free = request_free_json_payload;
		if ((ret = request_insert(req))) {
			request_free(req);
		}
		return ret;
	}
}

int
hub_tb_evp2_send_direct_command_response(
	struct transport_ctxt *ctxt, struct direct_command_response *response)
{
	JSON_Value *value =
		compose_evp2_direct_command_response_payload(response);
	char *payload = json_serialize_to_string(value);
	json_value_free(value);
	if (payload == NULL) {
		xlog_error("Invalid direct_command_response payload");
		return EINVAL;
	} else {
		int ret;
		struct request *req = request_alloc();
		/*
		 * EVP2: MDC topic id needs to be mapped to request id in
		 * payload.
		 */
		struct reqid_map_entry *entry =
			reqid_map_find(response->reqid);
		if (entry) {
			req->id = entry->value;
		} else {
			xlog_error("ID %" PRIu64 " was not found in reqid map",
				   req->id);
		}
		req->topic_template = "v1/devices/me/rpc/response/%ju";
		req->payload = payload;
		req->payload_free = request_free_json_payload;
		if ((ret = request_insert(req))) {
			request_free(req);
		}
		return ret;
	}
}
