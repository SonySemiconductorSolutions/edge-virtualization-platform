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

#include "agent_internal.h"
#include "hub.h"
#include "req.h"

struct request g_req = {.id = 33};

#define STTOK_REQ_FILENAME "https://fakeurl.io/evpcontainer/blob_test"
#define STTOK_REQ_INST_ID  "3cd184b68137"
#define STTOK_REQ_KEY      "default"

void
__wrap_save_json(const char *filename, const JSON_Value *v)
{
}

void
test_storagetoken_request_payload_create(void **state)
{
	/*
	 * {
	 *     "method": "evp-d2c",
	 *     "params": {
	 *         "storagetoken-request": {
	 *             "reqid": "33",
	 *             "filename": "test-3cd184b68137.dat",
	 *             "moduleInstanceId": "3cd184b68137",
	 *             "key": "default"
	 *         }
	 *     }
	 * }
	 */

	struct storagetoken_data st_data = {.instance_name = STTOK_REQ_INST_ID,
					    .remote_name = STTOK_REQ_FILENAME,
					    .storage_name = STTOK_REQ_KEY,
					    .reqid = 33};

	JSON_Value *v =
		hub_evp2_tb_storagetoken_request_payload_create(&st_data);
	JSON_Object *o;

	o = json_value_get_object(v);
	o = json_object_get_object(o, "params");
	o = json_object_get_object(o, "storagetoken-request");

	const char *reqid = json_object_get_string(o, "reqid");
	const char *filename = json_object_get_string(o, "filename");
	const char *moduleInstanceId =
		json_object_get_string(o, "moduleInstanceId");
	const char *key = json_object_get_string(o, "key");

	assert_ptr_not_equal(reqid, NULL);
	assert_ptr_not_equal(filename, NULL);
	assert_ptr_not_equal(moduleInstanceId, NULL);
	assert_ptr_not_equal(key, NULL);
	assert_string_equal(reqid, "33");
	assert_string_equal(filename, STTOK_REQ_FILENAME);
	assert_string_equal(moduleInstanceId, STTOK_REQ_INST_ID);
	assert_string_equal(key, STTOK_REQ_KEY);

	json_value_free(v);
}

#define STTOK_RESP_URL          "https://fakeurl.io/evpcontainer/blob_test"
#define STTOK_RESP_HEADER_NAME  "x-ms-blob-type"
#define STTOK_RESP_HEADER_VALUE "BlockBlob"

void
test_storagetoken_response_parse(void **state)
{
	const char *json = "{"
			   "  \"storagetoken-response\": {"
			   "    \"reqid\": \"42\","
			   "    \"status\": \"ok\","
			   "    \"URL\": \"" STTOK_RESP_URL "\","
			   "    \"headers\": {"
			   "      \"" STTOK_RESP_HEADER_NAME
			   "\": \"" STTOK_RESP_HEADER_VALUE "\""
			   "    }"
			   "  }"
			   "}";
	JSON_Value *v = json_parse_string(json);
	struct storagetoken_response resp;
	struct evp_agent_context *agent = *state;

	assert_non_null(v);
	const JSON_Object *o = json_value_get_object(v);
	assert_non_null(o);
	int ret = agent->hub->storagetoken_response_parse(o, &resp);

	assert_int_equal(ret, 0);
	assert_int_equal(resp.status, 0);
	assert_ptr_equal(resp.error, NULL);
	assert_ptr_not_equal(resp.url, NULL);
	assert_string_equal(resp.url, STTOK_RESP_URL);
	assert_ptr_not_equal(resp.headers, NULL);
	assert_ptr_not_equal(resp.headers[0], NULL);
	assert_string_equal(resp.headers[0], STTOK_RESP_HEADER_NAME
			    ": " STTOK_RESP_HEADER_VALUE);

	storagetoken_response_dtor(&resp);

	json_value_free(v);
}

void
test_hub_evp2_response_parse_reqid(void **state)
{
	const char *json = "{"
			   "  \"storagetoken-response\": {"
			   "    \"reqid\": \"10111\","
			   "    \"status\": \"ok\","
			   "    \"URL\": \"" STTOK_RESP_URL "\","
			   "    \"headers\": {"
			   "      \"" STTOK_RESP_HEADER_NAME
			   "\": \"" STTOK_RESP_HEADER_VALUE "\""
			   "    }"
			   "  }"
			   "}";
	uintmax_t reqid;
	int ret = hub_evp2_response_parse_reqid(json, &reqid);

	assert_int_equal(ret, 0);
	assert_int_equal(reqid, 10111);
}

void
test_parse_response_payload_invalid(void **state)
{
	JSON_Value *v;
	struct storagetoken_response resp;
	int ret;
	struct evp_agent_context *agent = *state;

	const char *json_no_status = "{"
				     "  \"storagetoken-response\": {"
				     "    \"reqid\": \"10111\","
				     "    \"URL\": \"" STTOK_RESP_URL "\","
				     "    \"headers\": {"
				     "      \"" STTOK_RESP_HEADER_NAME
				     "\": \"" STTOK_RESP_HEADER_VALUE "\""
				     "    }"
				     "  }"
				     "}";
	v = json_parse_string(json_no_status);
	assert_non_null(v);
	const JSON_Object *o = json_value_get_object(v);
	assert_non_null(o);
	ret = agent->hub->storagetoken_response_parse(o, &resp);
	assert_int_not_equal(ret, 0);
	json_value_free(v);

	const char *json_not_url = "{"
				   "  \"storagetoken-response\": {"
				   "    \"reqid\": \"10111\","
				   "    \"status\": \"ok\","
				   "    \"headers\": {"
				   "      \"" STTOK_RESP_HEADER_NAME
				   "\": \"" STTOK_RESP_HEADER_VALUE "\""
				   "    }"
				   "  }"
				   "}";

	v = json_parse_string(json_not_url);
	assert_non_null(v);
	o = json_value_get_object(v);
	assert_non_null(o);
	ret = agent->hub->storagetoken_response_parse(o, &resp);
	assert_int_not_equal(ret, 0);
	json_value_free(v);

	const char *json_url_empty = "{"
				     "  \"storagetoken-response\": {"
				     "    \"reqid\": \"10111\","
				     "    \"status\": \"ok\","
				     "    \"URL\": \"\","
				     "    \"headers\": {"
				     "      \"" STTOK_RESP_HEADER_NAME
				     "\": \"" STTOK_RESP_HEADER_VALUE "\""
				     "    }"
				     "  }"
				     "}";

	v = json_parse_string(json_url_empty);
	assert_non_null(v);
	o = json_value_get_object(v);
	assert_non_null(o);
	ret = agent->hub->storagetoken_response_parse(o, &resp);
	assert_int_equal(ret, 0);
	json_value_free(v);

	storagetoken_response_dtor(&resp);
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

	if (!ctxt)
		return -1;
	else if ((ret = evp_agent_start(ctxt)))
		return ret;

	*state = ctxt;
	return 0;
}

static int
teardown(void **state)
{
	struct evp_agent_context *agent = *state;

	int ret = evp_agent_stop(agent);
	evp_agent_free(agent);
	return ret;
}

int
main(void)
{
	// define tests

	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_storagetoken_request_payload_create),
		cmocka_unit_test(test_storagetoken_response_parse),
		cmocka_unit_test(test_hub_evp2_response_parse_reqid),
		cmocka_unit_test(test_parse_response_payload_invalid),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup, teardown);
}
