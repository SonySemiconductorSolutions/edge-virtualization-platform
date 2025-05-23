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

#include <internal/queue.h>
#include <internal/util.h>

#include "agent_internal.h"
#include "agent_test.h"
#include "blob.h"
#include "blob_type_evp.h"
#include "hub.h"
#include "path.h"
#include "req.h"
#include "transport.h"

#define STTOK_REQ_FILENAME "https://fakeurl.io/evpcontainer/blob_test"
#define STTOK_REQ_INST_ID  "3cd184b68137"
#define STTOK_REQ_KEY      "default"
#define STTOK_RESP_URL                                                        \
	"https://fakeurl.io/evpcontainer/?token=1234567890abcdef"
#define STTOK_RESP_HEADER_NAME       "x-ms-blob-type"
#define STTOK_RESP_HEADER_VALUE      "BlockBlob"
#define STTOK_RESP_EXPIRES_AT_MILLIS 1000
#define STTOK_RESP_EXPIRES_AT_MILLIS_STR                                      \
	___STRING(STTOK_RESP_EXPIRES_AT_MILLIS)

/* clang-format off */
static const char json_cache[] =
"["
"	{"
"		\"instanceName\": \"" STTOK_REQ_INST_ID "\","
"		\"storageName\": \"" STTOK_REQ_KEY "\","
"		\"storagetoken-response\": {"
"			\"reqid\": \"10111\","
"			\"status\": \"ok\","
"			\"expiresAtMillis\": \"" STTOK_RESP_EXPIRES_AT_MILLIS_STR "\","
"                       \"responseType\": \"multifile\","
"			\"URL\": \"" STTOK_RESP_URL "\","
"			\"headers\": {"
"				\"" STTOK_RESP_HEADER_NAME "\": \"" STTOK_RESP_HEADER_VALUE "\""
"			}"
"		}"
"	}"
"]";
/* clang-format on */

void
__wrap_save_json(const char *filename, const JSON_Value *v)
{
	JSON_Value *exp = json_parse_string(json_cache);

	assert_non_null(exp);
	function_called();
	assert_int_equal(json_value_equals(v, exp), 1);
	check_expected(filename);
	json_value_free(exp);
}

JSON_Value *
__wrap_json_parse_file(const char *path)
{
	function_called();
	check_expected(path);

	return (JSON_Value *)mock();
}

static bool mock__gettime_ms = false;
uint64_t __real_gettime_ms(void);
uint64_t
__wrap_gettime_ms(void)
{
	if (mock__gettime_ms) {
		return mock();
	}
	return __real_gettime_ms();
}

void
test_cache_store(void **state)
{
	static const char db[] = "[]";
	JSON_Value *orig = json_parse_string(db);
	const char *cache_path = path_get(CACHE_PATH_ID);

	assert_non_null(cache_path);
	assert_non_null(orig);
	expect_string(__wrap_json_parse_file, path, cache_path);
	expect_function_call(__wrap_json_parse_file);
	will_return(__wrap_json_parse_file, orig);

	const char *json_resp = "{"
				"  \"storagetoken-response\": {"
				"    \"reqid\": \"10111\","
				"    \"status\": \"ok\","
				"    \"expiresAtMillis\": \"1000\","
				"    \"responseType\": \"multifile\","
				"    \"URL\": \"" STTOK_RESP_URL "\","
				"    \"headers\": {"
				"      \"" STTOK_RESP_HEADER_NAME
				"\": \"" STTOK_RESP_HEADER_VALUE "\""
				"    }"
				"  }"
				"}";
	JSON_Value *v = json_parse_string(json_resp);
	assert_non_null(json_resp);
	expect_string(__wrap_save_json, filename, cache_path);
	expect_function_call(__wrap_save_json);
	assert_int_equal(
		blob_type_evp_store(
			&(struct blob_work){
				.module_instance_name = STTOK_REQ_INST_ID,
				.remote_name = STTOK_REQ_FILENAME,
				.storage_name = STTOK_REQ_KEY,
			},
			v),
		0);
	json_value_free(v);
}

void
test_cache_get(void **state)
{
	JSON_Value *v = json_parse_string(json_cache);
	assert_non_null(v);
	/* json_value_free will be called by cache_get. */
	const char *cache_path = path_get(CACHE_PATH_ID);
	assert_non_null(cache_path);
	expect_string(__wrap_json_parse_file, path, cache_path);
	expect_function_call(__wrap_json_parse_file);
	will_return(__wrap_json_parse_file, v);
	// Enable gettime_ms mocking
	mock__gettime_ms = true;
	will_return(__wrap_gettime_ms, 100);
	struct storagetoken_response resp;
	int rv = blob_type_evp_load(
		*state,
		&(struct blob_work){
			.module_instance_name = STTOK_REQ_INST_ID,
			.remote_name = STTOK_REQ_FILENAME,
			.storage_name = STTOK_REQ_KEY,
		},
		&resp);
	assert_int_equal(rv, 0);
	assert_int_equal(resp.status, 0);
	assert_int_equal(resp.expiration_ms, STTOK_RESP_EXPIRES_AT_MILLIS);
	assert_string_equal(resp.url, STTOK_RESP_URL);
	assert_string_equal(resp.headers[0], STTOK_RESP_HEADER_NAME
			    ": " STTOK_RESP_HEADER_VALUE);
	free(__UNCONST(resp.url));
	free(__UNCONST(resp.headers[0]));
	free(__UNCONST(resp.headers));
}

static int
setup(void **state)
{
	agent_test_setup();
	path_init(getenv("EVP_DATA_DIR"));
	struct evp_agent_context *ctxt = *state = evp_agent_setup("TEST");
	ctxt->hub = evp_hub_setup("tb");
	ctxt->transport_ctxt = transport_setup(NULL, NULL, ctxt, NULL);
	return 0;
}

static int
teardown(void **state)
{
	evp_agent_free(*state);
	path_free();
	return 0;
}

int
main(void)
{
	// define tests

	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_cache_store),
		cmocka_unit_test(test_cache_get),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup, teardown);
}
