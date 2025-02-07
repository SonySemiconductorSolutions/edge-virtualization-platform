/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// these includes are required by cmocka and must precede <cmocka.h>
#include <cdefs.h>
#include <hub.h>
#include <mstp_schema.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>
#include <evp/agent.h>
#include <parson.h>

#include <internal/util.h>

#include "blob.h"
#include "blob_type_evp.h"
#include "fsutil.h"
#include "hub.h"
#include "req.h"

static EVP_RPC_ID g_reqid;
static struct request *g_req;

EVP_RPC_ID
__wrap_request_id_alloc(void) { return g_reqid; }

struct request *
__wrap_request_alloc(void)
{
	g_req = xcalloc(1, sizeof(*g_req));
	g_req->id = g_reqid;
	return g_req;
}

void
__wrap_blob_work_enqueue(struct blob_work *wk)
{
}

void
test_blob_type_evp_start_rpc(void **state)
{
	struct evp_agent_context *agent = *state;

	// Load request payload from file
	JSON_Value *request_json = json_parse_file(
		"src/evp2-tb/storagetoken-request_payload1.json");
	assert_non_null(request_json);

	JSON_Object *o;
	o = json_value_get_object(request_json);
	o = json_object_get_object(o, "params");
	o = json_object_get_object(o, "storagetoken-request");
	char *xpct_payload = json_serialize_to_string(request_json);

	const char *reqid = json_object_get_string(o, "reqid");
	assert_non_null(reqid);

	g_reqid = strtoull(reqid, NULL, 10);

	// Send storage token` request to hub
	struct blob_work wk = {
		.type = BLOB_TYPE_EVP_EXT,
		.op = BLOB_OP_PUT,
		.remote_name = json_object_get_string(o, "filename"),
		.module_instance_name =
			json_object_get_string(o, "moduleInstanceId"),
		.storage_name = json_object_get_string(o, "key"),
	};

	blob_type_evp_start_rpc(agent, &wk);

	assert_non_null(g_req);
	assert_string_equal(g_req->payload, xpct_payload);
	assert_int_equal(g_req->id, g_reqid);

	json_free_serialized_string(xpct_payload);

	// Load response payload from file
	size_t len = 0;
	char *response_payload = read_file(
		"src/evp2-tb/storagetoken-response_payload1.json", &len, true);
	JSON_Value *response_json = json_parse_string(response_payload);
	o = json_value_get_object(response_json);
	o = json_object_get_object(o, "storagetoken-response");

	// Prepare expected values
	const char *xpct_url = json_object_get_string(o, "URL");
	JSON_Object *o_headers = json_object_get_object(o, "headers");
	const char *header_key = json_object_get_name(o_headers, 0);
	const char *header_value =
		json_object_get_string(o_headers, header_key);
	char *xpct_header;
	xasprintf(&xpct_header, "%s: %s", header_key, header_value);

	// Mock the response from hub
	request_handle_response(agent, g_reqid, response_payload);

	assert_string_equal(wk.url, xpct_url);
	assert_int_equal(wk.nheaders, 1);
	assert_string_equal(wk.headers[0], xpct_header);

	// Cleanup

	// This normally cleaned up when blob work has been processed
	free(__UNCONST(wk.url));
	free(__UNCONST(wk.headers[0]));
	free(__UNCONST(wk.headers));

	free(response_payload);
	free(xpct_header);
	json_value_free(response_json);
	json_value_free(request_json);
}

void
test_blob_type_evp_null_storagename(void **state)
{
	struct evp_agent_context *agent = *state;

	// Load request payload from file
	JSON_Value *request_json = json_parse_file(
		"src/evp2-tb/storagetoken-request_payload2.json");
	assert_non_null(request_json);

	JSON_Object *o;
	o = json_value_get_object(request_json);
	o = json_object_get_object(o, "params");
	o = json_object_get_object(o, "storagetoken-request");
	char *xpct_payload = json_serialize_to_string(request_json);

	const char *reqid = json_object_get_string(o, "reqid");
	assert_non_null(reqid);

	g_reqid = strtoull(reqid, NULL, 10);

	// Send storage token` request to hub
	struct blob_work wk = {
		.type = BLOB_TYPE_EVP_EXT,
		.op = BLOB_OP_PUT,
		.remote_name = json_object_get_string(o, "filename"),
		.module_instance_name =
			json_object_get_string(o, "moduleInstanceId"),
		.storage_name = json_object_get_string(o, "key"),
	};

	blob_type_evp_start_rpc(agent, &wk);

	assert_non_null(g_req);
	assert_string_equal(g_req->payload, xpct_payload);
	assert_int_equal(g_req->id, g_reqid);

	json_free_serialized_string(xpct_payload);

	// Load response payload from file
	size_t len = 0;
	char *response_payload = read_file(
		"src/evp2-tb/storagetoken-response_payload2.json", &len, true);

	// Mock the response from hub
	request_handle_response(agent, g_reqid, response_payload);
	free(response_payload);

	assert_int_equal(wk.result, BLOB_RESULT_ERROR);

	json_value_free(request_json);
}

static int
setup(void **state)
{
	int ret;

	if ((ret = putenv("EVP_IOT_PLATFORM=tb")) ||
	    (ret = putenv("EVP_MQTT_HOST=test.mqtt.host.value")) ||
	    (ret = putenv("EVP_MQTT_PORT=1234")))
		return ret;

	struct evp_agent_context *ctxt = evp_agent_setup("test");
	evp_agent_start(ctxt);
	*state = ctxt;
	return 0;
}

static int
teardown(void **state)
{
	evp_agent_stop(*state);
	evp_agent_free(*state);
	return 0;
}

int
main(void)
{
	// define tests

	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_blob_type_evp_start_rpc),
		cmocka_unit_test(test_blob_type_evp_null_storagename),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup, teardown);
}
