/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include <parson.h>

#include <internal/util.h>

#include "base64.h"
#include "blob.h"
#include "certificates.h"
#include "hub.h"
#include "models/mstp.h"
#include "mstp_schema.h"
#include "req.h"
#include "sdk_agent.h"
#include "xlog.h"

static JSON_Value *
hub_evp1_wrap_rpc_request(const char *method_name, JSON_Value *params)
{
	JSON_Value *v = json_value_init_object();
	JSON_Object *o = json_value_get_object(v);
	json_object_set_string(o, "method", method_name);
	json_object_set_value(o, "params", params);

	return v;
}

static JSON_Value *
hub_evp2_tb_wrap_rpc_request(const char *method_name, JSON_Value *params)
{
	JSON_Value *v = json_value_init_object();
	JSON_Object *o = json_value_get_object(v);

	json_object_set_string(o, "method", "evp-d2c");
	json_object_set_value(o, "params", json_value_init_object());
	o = json_object_get_object(o, "params");

	json_object_set_value(o, method_name, params);

	return v;
}

JSON_Value *
hub_evp1_storagetoken_request_payload_create(struct storagetoken_data *st_data)
{
	JSON_Value *params_v = json_value_init_object();
	JSON_Object *params_o = json_value_get_object(params_v);
	json_object_set_string(params_o, "filename", st_data->remote_name);
	json_object_set_string(params_o, "moduleInstanceName",
			       st_data->instance_name);
	if (st_data->storage_name != NULL) {
		json_object_set_string(params_o, "storageName",
				       st_data->storage_name);
	}

	return hub_evp1_wrap_rpc_request("StorageToken", params_v);
}

static JSON_Value *
hub_evp2_cmn_storagetoken_request_payload_create(
	struct storagetoken_data *st_data)
{
	JSON_Value *params_v = json_value_init_object();
	JSON_Object *params_o = json_value_get_object(params_v);
	char *reqid;
	xasprintf(&reqid, "%" PRIu64, st_data->reqid);
	json_object_set_string(params_o, "reqid", reqid);
	json_object_set_string(params_o, "filename", st_data->remote_name);
	json_object_set_string(params_o, "moduleInstanceId",
			       st_data->instance_name);
	if (st_data->storage_name != NULL) {
		json_object_set_string(params_o, "key", st_data->storage_name);
	}
	free(reqid);

	return params_v;
}

JSON_Value *
hub_evp2_tb_storagetoken_request_payload_create(
	struct storagetoken_data *st_data)
{
	JSON_Value *params_v =
		hub_evp2_cmn_storagetoken_request_payload_create(st_data);

	return hub_evp2_tb_wrap_rpc_request("storagetoken-request", params_v);
}

static int
parse_expiration_ms(const char *s, uint64_t *out)
{
	errno = 0;

	char *end;
	/* Decimal base is not explicitly required, but is nonetheless hinted
	 * by the on-wire schema. */
	unsigned long long v = strtoull(s, &end, 10);

	if (errno) {
		xlog_error("strtoull failed, s=%s errno %d", s, errno);
		return -1;
	}

	if (*end) {
		xlog_error("invalid number %s", s);
		return -1;
	}

	*out = v;
	return 0;
}

static int
parse_rpc_payload(const JSON_Object *o, struct storagetoken_response *resp)
{
	int ret = 0;
	int resp_status = 0;

	/* Get fields */
	const char *error_msg =
		json_object_get_string(o, "errorMessage"); // EVP2
	const char *url = json_object_get_string(o, "URL");

	/* Check valid JSON format */
	if (!error_msg && !url) {
		ret = EINVAL;
		goto out;
	}

	const char *expiration_ms =
		json_object_get_string(o, "expiresAtMillis");
	uint64_t ms = 0;

	if (expiration_ms && parse_expiration_ms(expiration_ms, &ms)) {
		xlog_error("parse_expiration_ms failed");
		ret = EINVAL;
		goto out;
	}

	/* Check if it is an error message */
	if (error_msg) {
		resp_status = EIO;
	}

	const char *resp_type_str = json_object_get_string(o, "responseType");
	enum storagetoken_response_type resp_type =
		STORAGETOKEN_RESPONSE_TYPE_SINGLE_FILE;

	if (resp_type_str) {
		if (!strcmp(resp_type_str, "multifile")) {
			resp_type = STORAGETOKEN_RESPONSE_TYPE_MULTI_FILE;
		} else if (!strcmp(resp_type_str, "singlefile")) {
			resp_type = STORAGETOKEN_RESPONSE_TYPE_SINGLE_FILE;
		} else {
			xlog_error("invalid response type value %s",
				   resp_type_str);
			ret = EINVAL;
			goto out;
		}
	}

	storagetoken_response_ctor(resp, resp_status, error_msg, url, ms,
				   resp_type);

	/* The headers are optional */
	const JSON_Object *headers = json_object_get_object(o, "headers");
	size_t n_headers = json_object_get_count(headers);
	if (n_headers) {
		size_t i;

		for (i = 0; i < n_headers; i++) {
			const char *header_name =
				json_object_get_name(headers, i);
			const char *header_value = json_value_get_string(
				json_object_get_value_at(headers, i));
			storagetoken_response_add_header(resp, header_name,
							 header_value);
		}
	}

out:
	return ret;
}

static JSON_Value *
hub_evp1_unwrap_rpc_response(const JSON_Object *o)
{
	JSON_Value *result = NULL;

	/* Expected format:
	 * {
	 *     "method": "<name>",
	 *     "params": {
	 *         <method dependent contents>
	 *     }
	 * }
	 *
	 * Also, the hub sometimes seems to respond with the following.
	 * The current implementation simply ignores those responses.
	 * (and maybe ends up with a timeout later)
	 *
	 * {
	 *     "error": "<free form description for human investigations (?)>"
	 * }
	 *
	 * Unfortunately, we don't have a comprehensive list of possible
	 * responses.  A list of observed responses are:
	 *
	 *    {"error":"timeout"}
	 *
	 *    {"error":"Tenant has no token provider"}
	 */

	/* Get fields */
	const char *method = json_object_get_string(o, "method");
	const JSON_Object *params = json_object_get_object(o, "params");
	if (method == NULL || params == NULL) {
		goto out;
	}

	result = json_value_deep_copy(json_object_get_wrapping_value(params));
out:
	return result;
}

int
hub_evp1_storagetoken_response_parse(const JSON_Object *payload,
				     struct storagetoken_response *resp)
{
	int ret;
	JSON_Value *v = hub_evp1_unwrap_rpc_response(payload);
	const JSON_Object *o = json_value_get_object(v);

	if (!o) {
		xlog_error("Failed to parse StorageToken response");
		ret = EINVAL;
	} else {
		ret = parse_rpc_payload(o, resp);
	}

	json_value_free(v);
	return ret;
}

static const JSON_Object *
hub_evp2_unwrap_rpc_response(const JSON_Object *o, const char *method)
{
	return json_object_get_object(o, method);
}

int
hub_evp2_storagetoken_response_parse(const JSON_Object *payload,
				     struct storagetoken_response *resp)
{
	const JSON_Object *o =
		hub_evp2_unwrap_rpc_response(payload, "storagetoken-response");

	if (o == NULL) {
		xlog_error("hub_evp2_unwrap_rpc_response failed");
		return EINVAL;
	}

	const char *status = json_object_get_string(o, "status");

	if (!status) {
		xlog_error("json_object_get_string failed");
		return EINVAL;
	}

	return parse_rpc_payload(o, resp);
}

int
hub_evp2_response_parse_reqid(const char *payload, uintmax_t *reqid)
{
	JSON_Value *v = json_parse_string(payload);
	if (!v) {
		xlog_error("%s: mSTP updates with invalid json", __func__);
		return -1;
	}

	int ret = -1;
	JSON_Object *o = json_value_get_object(v);
	const char *msg_name = json_object_get_name(o, 0);

	if (!msg_name) {
		goto out;
	}
	if (strcmp(msg_name, "storagetoken-response")) {
		xlog_error("%s: mSTP updates with unknown message payload",
			   __func__);
		goto out;
	}

	o = json_object_get_object(o, msg_name);
	const char *reqid_str = json_object_get_string(o, "reqid");

	if (reqid_str == NULL) {
		xlog_error("%s: No reqid field in response", __func__);
		goto out;
	}

	if (string_to_uint(reqid_str, reqid)) {
		xlog_error("%s: Invalid reqid value: %s", __func__, reqid_str);
		goto out;
	}

	ret = 0;

out:
	json_value_free(v);
	return ret;
}
