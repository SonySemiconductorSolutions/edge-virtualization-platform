/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <malloc.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <parson.h>

#include <internal/util.h>

#include "agent_internal.h"
#include "direct_command.h"
#include "evp/sdk.h"
#include "module_instance.h"
#include "module_log_cap.h"
#include "sdk_agent.h"
#include "sys/sys.h"
#include "xlog.h"

#define AGENT_PREFIX     "$agent/"
#define AGENT_PREFIX_LEN (sizeof(AGENT_PREFIX) - 1)

static int
send_rpc_response(const char *module_instance, EVP_RPC_ID id,
		  const char *response, EVP_RPC_RESPONSE_STATUS status,
		  void *user)
{
	struct evp_agent_context *ctxt = user;
	enum direct_command_response_status response_status;
	switch (status) {
	case EVP_RPC_RESPONSE_STATUS_OK:
		response_status = DIRECT_COMMAND_RESPONSE_STATUS_OK;
		break;
	case EVP_RPC_RESPONSE_STATUS_METHOD_NOT_FOUND:
		response_status =
			DIRECT_COMMAND_RESPONSE_STATUS_METHOD_NOT_FOUND;
		break;
	case EVP_RPC_RESPONSE_STATUS_ERROR:
	default:
		response_status = DIRECT_COMMAND_RESPONSE_STATUS_ERROR;
		break;
	}
	struct direct_command_response *res = direct_command_response_ctor(
		id, response, response_status, module_instance);
	if (res == NULL) {
		return -1;
	}
	int ret = ctxt->hub->send_direct_command_response(ctxt->transport_ctxt,
							  res);
	direct_command_response_dtor(res);
	return ret;
}

static int
send_sys_response(SYS_response_id id, const char *response,
		  enum SYS_response_status status, void *user)
{
	struct evp_agent_context *ctxt = user;
	enum direct_command_response_status response_status;

	switch (status) {
	case SYS_RESPONSE_STATUS_OK:
		response_status = DIRECT_COMMAND_RESPONSE_STATUS_OK;
		break;
	case SYS_RESPONSE_STATUS_METHOD_NOT_FOUND:
		response_status =
			DIRECT_COMMAND_RESPONSE_STATUS_METHOD_NOT_FOUND;
		break;
	case SYS_RESPONSE_STATUS_ERROR:
	default:
		response_status = DIRECT_COMMAND_RESPONSE_STATUS_ERROR;
		break;
	}

	struct direct_command_response *res = direct_command_response_ctor(
		id, response, response_status, sys_prefix);

	if (res == NULL) {
		return -1;
	}

	int ret = ctxt->hub->send_direct_command_response(ctxt->transport_ctxt,
							  res);
	direct_command_response_dtor(res);
	return ret;
}

static void
module_instance_agent_set(struct evp_agent_context *ctxt,
			  struct direct_command_request *cp)
{
	int rv = 0;
	const char *response = "{}";

	JSON_Value *params = json_parse_string(cp->params);
	if (params == NULL) {
		xlog_warning("failed to parse params: %s", cp->params);
		goto error;
	}
	JSON_Object *o = json_value_get_object(params);

	JSON_Value *log_enable_v = json_object_get_value(o, "log_enable");
	if (!log_enable_v) {
		response = "{\"error\":\"log_enable field not found\"}";
		goto error;
	}

	int log_enable = json_value_get_boolean(log_enable_v);
	if (log_enable < 0) {
		response = "{\"error\":\"log_enable value is not a boolean\"}";
		goto error;
	}

	rv = module_log_cap_set_enable(cp->instance, "stdout",
				       (bool)log_enable);
	if (rv) {
		response = "{\"error\":\"Instance not found\"}";
		goto error;
	}

	rv = module_log_cap_set_enable(cp->instance, "stderr",
				       (bool)log_enable);
	if (rv) {
		response = "{\"error\":\"Instance not found\"}";
	}

error:
	send_rpc_response(cp->instance, cp->reqid, response,
			  (rv == 0) ? EVP_RPC_RESPONSE_STATUS_OK
				    : EVP_RPC_RESPONSE_STATUS_ERROR,
			  ctxt);
	json_value_free(params);
}

static void
module_instance_agent_get(struct evp_agent_context *ctxt,
			  struct direct_command_request *cp)
{
	const char *response;
	bool out_enable = false;
	bool err_enable = false;
	int rv = 0;

	rv = module_log_cap_get_enable(cp->instance, "stdout", &out_enable);
	if (rv) {
		response = "{\"error\":\"Instance not found\"}";
		goto error;
	}

	rv = module_log_cap_get_enable(cp->instance, "stderr", &err_enable);
	if (rv) {
		response = "{\"error\":\"Instance not found\"}";
		goto error;
	}

	if (out_enable || err_enable) {
		response = "{\"log_enable\":true}";
	} else {
		response = "{\"log_enable\":false}";
	}
error:
	send_rpc_response(cp->instance, cp->reqid, response,
			  (rv == 0) ? EVP_RPC_RESPONSE_STATUS_OK
				    : EVP_RPC_RESPONSE_STATUS_ERROR,
			  ctxt);
}

static void
module_instance_agent_method(struct evp_agent_context *ctxt,
			     struct direct_command_request *cp)
{
	const char *method = &cp->method[AGENT_PREFIX_LEN];
	if (!strcmp(method, "set")) {
		module_instance_agent_set(ctxt, cp);
		return;
	}

	if (!strcmp(method, "get")) {
		module_instance_agent_get(ctxt, cp);
		return;
	}
}

struct direct_command_request *
parse_evp1_direct_command(EVP_RPC_ID id, JSON_Value *payload)
{
	/*
	 * {
	 *     "method": "ModuleMethodCall",
	 *     "params": {
	 *          "moduleInstance": "instance",
	 *          "moduleMethod": "Module Method Name",
	 *          "params": ...
	 *     }
	 * }
	 */
	const char *instance, *method;
	JSON_Object *o;
	JSON_Value *params;

	o = json_value_get_object(payload);
	method = json_object_get_string(o, "method");

	if (!method || strcmp(method, "ModuleMethodCall") != 0) {
		xlog_error("%s: invalid json payload", __func__);
		return NULL;
	}

	o = json_object_get_object(o, "params");
	instance = json_object_get_string(o, "moduleInstance");
	method = json_object_get_string(o, "moduleMethod");
	params = json_object_get_value(o, "params");

	if (instance == NULL || method == NULL || params == NULL) {
		xlog_error("%s: No required fields", __func__);
		return NULL;
	}

	char *blob = json_serialize_to_string_pretty(params);
	if (blob == NULL) {
		xlog_error("%s: Serialization failure", __func__);
		return NULL;
	}

	struct direct_command_request *req =
		direct_command_request_ctor(id, method, instance, blob);
	json_free_serialized_string(blob);

	return req;
}

struct direct_command_request *
parse_evp2_direct_command(JSON_Value *payload)
{
	/*
	 * {
	 *      "direct-command-request": {
	 *              "method": "Module Method Name",
	 *              "instance": "instance",
	 *              "params": ...
	 *      }
	 * }
	 */
	JSON_Object *o = json_value_get_object(payload);
	if (o == NULL) {
		xlog_error("%s: Not a JSON object", __func__);
		return NULL;
	}
	o = json_object_get_object(o, "direct-command-request");
	if (o == NULL) {
		xlog_error("%s: No required 'direct-command-request'",
			   __func__);
		return NULL;
	}

	const char *instance = json_object_get_string(o, "instance");
	const char *rpc_id = json_object_get_string(o, "reqid");
	const char *method = json_object_get_string(o, "method");
	const char *params = json_object_get_string(o, "params");

	if (!instance || !rpc_id || !method || !params) {
		xlog_error("%s: No required fields", __func__);
		return NULL;
	}

	uintmax_t aux;
	int r = string_to_uint(rpc_id, &aux);
	EVP_RPC_ID id = aux;
	if (r != 0 || id != aux) {
		xlog_error("%s: Invalid rpc id '%s'", __func__, rpc_id);
		return NULL;
	}

	struct direct_command_request *req =
		direct_command_request_ctor(id, method, instance, params);

	return req;
}

struct direct_command_request *
direct_command_request_ctor(EVP_RPC_ID id, const char *method,
			    const char *instance, const char *params)
{
	struct direct_command_request *req =
		xmalloc(sizeof(struct direct_command_request));
	req->reqid = id;
	req->method = xstrdup(method);
	req->instance = xstrdup(instance);
	req->params = xstrdup(params);
	return req;
}

void
direct_command_request_dtor(struct direct_command_request *obj)
{
	if (obj != NULL) {
		free(obj->method);
		free(obj->instance);
		free(obj->params);
		free(obj);
	}
}

void
evp_process_direct_command_request(struct evp_agent_context *ctxt,
				   struct direct_command_request *req)
{
	if (sys_is_sysapp(req->instance)) {
		sys_notify_ddc(ctxt->sys, req->method, req->params,
			       req->reqid);
		return;
	}

	if (!strncmp(req->method, AGENT_PREFIX, AGENT_PREFIX_LEN)) {
		module_instance_agent_method(ctxt, req);
		return;
	}

	module_instance_notify(NOTIFY_RPC_REQUEST, req->instance,
			       strlen(req->instance), req->reqid, req->method,
			       req->params, strlen(req->params));
	/*
	 * module_instance_notify will free the "blob" so we don't own
	 * the memory anymore
	 */
	req->params = NULL;
}

struct direct_command_response *
direct_command_response_ctor(EVP_RPC_ID id, const char *response,
			     enum direct_command_response_status status,
			     const char *instance)
{
	struct direct_command_response *res =
		xmalloc(sizeof(struct direct_command_response));
	res->reqid = id;
	res->status = status;
	res->response = response == NULL ? NULL : xstrdup(response);
	res->instance = instance == NULL ? NULL : xstrdup(instance);
	return res;
}

void
direct_command_response_dtor(struct direct_command_response *obj)
{
	if (obj != NULL) {
		free(obj->response);
		free(obj->instance);
		free(obj);
	}
}

void
direct_command_process(struct evp_agent_context *ctxt)
{
	sdk_collect_rpc_responses(send_rpc_response, ctxt);
	sys_collect_responses(ctxt->sys, send_sys_response, ctxt);
}

JSON_Value *
compose_evp1_direct_command_response_payload(
	struct direct_command_response *response)
{
	JSON_Value *wrapper;
	JSON_Object *obj;
	JSON_Status st;

	wrapper = json_value_init_object();
	if (wrapper == NULL)
		goto err;
	obj = json_value_get_object(wrapper);

	/*
	 * wrap the response as:
	 *
	 * {
	 *   "moduleInstance": <module instance name>,
	 *   "response": <a JSON value>
	 * }
	 */
	st = json_object_set_string(obj, "moduleInstance", response->instance);
	if (st != JSONSuccess)
		goto err;

	uint32_t status;
	JSON_Value *value;
	switch (response->status) {
	case DIRECT_COMMAND_RESPONSE_STATUS_OK:
		status = EVP_RPC_RESPONSE_STATUS_OK;
		value = json_parse_string(response->response);
		break;
	case DIRECT_COMMAND_RESPONSE_STATUS_METHOD_NOT_FOUND:
		/*
		 * The hub expects this.
		 * (Search DEVICE_RESPOMSE_UNKNOWN_METHOD in the hub code.)
		 *
		 * It can and should look at "status" instead.
		 * However, until it happens, we provide compatibility.
		 * Once it happens, we can remove this block to allow
		 * module instances to send its own response even with
		 * EVP_RPC_RESPONSE_STATUS_METHOD_NOT_FOUND.
		 */
		status = EVP_RPC_RESPONSE_STATUS_METHOD_NOT_FOUND;
		value = json_value_init_string("Unknown method");
		break;
	case DIRECT_COMMAND_RESPONSE_STATUS_ERROR:
	default:
		status = EVP_RPC_RESPONSE_STATUS_ERROR;
		value = json_parse_string(response->response);
		break;
	}

	// attach the response from the instance as a JSON value
	if (value != NULL) {
		st = json_object_set_value(obj, "response", value);
		if (st != JSONSuccess) {
			json_value_free(value);
			goto err;
		}
	} else {
		xlog_warning("failed to parse response: %s",
			     response->response);
		goto err;
	}

	// set the status
	st = json_object_set_number(obj, "status", status);
	if (st != JSONSuccess)
		goto err;

	return wrapper;

err:
	json_value_free(wrapper);
	return NULL;
}

JSON_Value *
compose_evp2_direct_command_response_payload(
	struct direct_command_response *response)
{
	JSON_Value *wrapper;
	JSON_Object *obj;
	JSON_Status st;

	wrapper = json_value_init_object();
	obj = json_value_get_object(wrapper);
	/*
	 * wrap the response as:
	 *
	 * {
	 *   "direct-command-response": {
	 *  	"response": "a string value",
	 *	"status" : "ok",
	 *      "reqid": 12435
	 *   }
	 * }
	 */
	JSON_Value *value = json_value_init_object();
	st = json_object_set_value(obj, "direct-command-response", value);
	if (st != JSONSuccess) {
		json_value_free(value);
		goto err;
	}
	obj = json_value_get_object(value);

	// set status and (optionally) errorMessage
	switch (response->status) {
	case DIRECT_COMMAND_RESPONSE_STATUS_OK:
		st = json_object_set_string(obj, "status", "ok");
		break;
	case DIRECT_COMMAND_RESPONSE_STATUS_METHOD_NOT_FOUND:
		st = json_object_set_string(obj, "status", "error");
		if (st == JSONSuccess) {
			st = json_object_set_string(obj, "errorMessage",
						    "Unknown method");
		}
		break;
	case DIRECT_COMMAND_RESPONSE_STATUS_ERROR:
	default:
		st = json_object_set_string(obj, "status", "error");
		if (st == JSONSuccess) {
			st = json_object_set_string(obj, "errorMessage",
						    "Unknown error");
		}
		break;
	}
	if (st != JSONSuccess)
		goto err;

	// set reqid string
	char *idstr;
	xasprintf(&idstr, "%ju", (uintmax_t)response->reqid);
	st = json_object_set_string(obj, "reqid", idstr);
	free(idstr);
	if (st != JSONSuccess) {
		goto err;
	}

	// attach the response from the instance as a string value
	if (response->response != NULL) {
		st = json_object_set_string(obj, "response",
					    response->response);
		if (st != JSONSuccess) {
			goto err;
		}
	}

	return wrapper;

err:
	xlog_error("Failed to compose direct_command_response");
	json_value_free(wrapper);
	return NULL;
}
