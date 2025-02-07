/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// these includes are required by cmocka and must precede <cmocka.h>
#include <cdefs.h>
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

#define MIN(a, b) (a > b ? b : a)

#define STORAGE_CERT_ID "certificate-id"

struct cert {
	char id[128];
	char buf[128];
	size_t len;
};

struct cert g_test_cert;

int
__wrap_cert_set(const char *id, const void *buf, size_t buflen,
		struct cert **certp)
{
	strncpy(g_test_cert.id, id, sizeof(g_test_cert.id));
	memcpy(g_test_cert.buf, buf, MIN(buflen, sizeof(g_test_cert.buf)));
	g_test_cert.len = buflen;
	*certp = &g_test_cert;
	return 0;
}

void
test_storagetoken_request_payload_create(void **state)
{
	/*
	 * {
	 *     "method": "StorageToken"
	 *     "params": {
	 * 	   "filename": "test-3cd184b68137.dat",
	 * 	   "moduleInstanceName": "3cd184b68137",
	 * 	   "storageName": "default"
	 *     }
	 * }
	 */
	const char *xpctd_filename = "test-3cd184b68137.dat";
	const char *xpctd_module = "3cd184b68137";
	const char *xpctd_storage = "default";
	JSON_Value *v;
	JSON_Object *o;
	struct storagetoken_data st_data = {.instance_name = xpctd_module,
					    .remote_name = xpctd_filename,
					    .storage_name = xpctd_storage,
					    .reqid = 0};

	v = hub_evp1_storagetoken_request_payload_create(&st_data);

	o = json_value_get_object(v);
	const char *method = json_object_get_string(o, "method");
	assert_ptr_not_equal(method, NULL);
	assert_string_equal(method, "StorageToken");

	o = json_object_get_object(o, "params");
	const char *filename = json_object_get_string(o, "filename");
	const char *module = json_object_get_string(o, "moduleInstanceName");
	const char *storage = json_object_get_string(o, "storageName");
	assert_ptr_not_equal(filename, NULL);
	assert_ptr_not_equal(module, NULL);
	assert_ptr_not_equal(storage, NULL);
	assert_string_equal(filename, xpctd_filename);
	assert_string_equal(module, xpctd_module);
	assert_string_equal(storage, xpctd_storage);

	json_value_free(v);
}

#define STTOK_RESP_URL          "https://fakeurl.io/evpcontainer/blob_test"
#define STTOK_RESP_HEADER_NAME  "x-ms-blob-type"
#define STTOK_RESP_HEADER_VALUE "BlockBlob"

void
test_storagetoken_response_parse(void **state)
{
	const char *json = "{"
			   "  \"method\": \"StorageToken\","
			   "  \"params\": {"
			   "    \"status\": \"ok\","
			   "    \"URL\": \"" STTOK_RESP_URL "\","
			   "    \"headers\": {"
			   "      \"" STTOK_RESP_HEADER_NAME
			   "\": \"" STTOK_RESP_HEADER_VALUE "\""
			   "    },"
			   "    \"cert\": \"" STORAGE_CERT_ID "\""
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

static int
setup(void **state)
{
	int ret;

	if ((ret = putenv("EVP_MQTT_HOST=test.mqtt.host.value")) ||
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
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup, teardown);
}
