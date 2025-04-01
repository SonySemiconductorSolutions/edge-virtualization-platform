/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <evp/sdk.h>

#include <internal/util.h>

#include "agent_test.h"
#include "hub.h"
#include "path.h"
#include "sdk_local_wasm.h"
#include "wasm_export.h"
#include "xlog.h"

#define TEST_HTTP_GET_URL  "https://baz/boo"
#define TEST_HTTP_PUT_URL  "http://foobar"
#define TEST_HTTP_GET_FILE "foobar.txt"
#define TEST_HTTP_PUT_FILE "boofar.bin"

#define HTTP_STATUS_OK 200

/* dummy.wat contents:
 * ```
 * (module (memory 1))
 * ```
 * assemble with `wat2wasm` and dump with `xxd -i`
 */
unsigned char dummy_wasm[] = {0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00,
			      0x00, 0x05, 0x03, 0x01, 0x00, 0x01};
unsigned int dummy_wasm_len = 13;

struct context {
	// EVP
	struct evp_agent_context *agent;
	struct EVP_client *sdk;
	struct agent_deployment d;

	// WASM
	int wasm_handle;
	wasm_exec_env_t wasm_exec_env;
	wasm_module_t wasm_module;
	wasm_module_inst_t wasm_module_inst;
};

struct EVP_BlobRequestHttp_wasm {
	uint32_t url;
};

struct EVP_BlobLocalStore_wasm {
	uint32_t filename;
	uint32_t io_cb;
	uint32_t blob_len;
};

enum test_direct_command_payloads {
	DEPLOYMENT_MANIFEST_1,
};

#define TEST_PROCESS_EVENT_TIMEOUT 10000

#define TEST_INSTANCE_ID1 "backdoor-mdc"
#define TEST_METHOD_NAME1 "test-method"
#define RPC_TEST_ID       543210

#define TEST_DEPLOYMENT_ID1      "2dc1a1c3-531b-4693-abba-a4a039bb827d"
#define TEST_MODULE_INSTANCE_ID1 "07fe77d5-7117-4326-9042-47fda5dd9bf5"
#define TEST_MODULE_ID1          "b91fe3e8-df6d-41b7-90cb-72f8b92bdf5e"

#define EVP1_DEPLOYMENT_MANIFEST_1                                            \
	"\"{ "                                                                \
	"        \\\"deploymentId\\\": "                                      \
	"\\\"" TEST_DEPLOYMENT_ID1 "\\\","                                    \
	"        \\\"instanceSpecs\\\": {"                                    \
	"            \\\"" TEST_MODULE_INSTANCE_ID1 "\\\": {"                 \
	"                \\\"moduleId\\\": "                                  \
	"\\\"" TEST_MODULE_ID1 "\\\","                                        \
	"                \\\"entryPoint\\\": \\\"" TEST_INSTANCE_ID1 "\\\","  \
	"                \\\"version\\\": 1,"                                 \
	"                \\\"publish\\\": {},"                                \
	"                \\\"subscribe\\\": {}"                               \
	"            }"                                                       \
	"        },"                                                          \
	"        \\\"modules\\\": {"                                          \
	"            \\\"" TEST_MODULE_ID1 "\\\": {"                          \
	"                \\\"moduleImpl\\\": \\\"spawn\\\","                  \
	"                \\\"downloadUrl\\\": \\\"\\\","                      \
	"                \\\"hash\\\": \\\"\\\""                              \
	"            }"                                                       \
	"        },"                                                          \
	"        \\\"publishTopics\\\": {},"                                  \
	"        \\\"subscribeTopics\\\": {}"                                 \
	"}\""

#define EVP2_DEPLOYMENT_MANIFEST_1                                            \
	"{"                                                                   \
	"        \"deploymentId\": \"" TEST_DEPLOYMENT_ID1 "\","              \
	"        \"instanceSpecs\": {"                                        \
	"            \"" TEST_MODULE_INSTANCE_ID1 "\": {"                     \
	"                \"moduleId\": "                                      \
	"\"" TEST_MODULE_ID1 "\","                                            \
	"                \"publish\": {},"                                    \
	"                \"subscribe\": {}"                                   \
	"            }"                                                       \
	"        },"                                                          \
	"        \"modules\": {"                                              \
	"            \"" TEST_MODULE_ID1 "\": {"                              \
	"                \"entryPoint\": \"" TEST_INSTANCE_ID1 "\","          \
	"                \"moduleImpl\": \"spawn\","                          \
	"                \"downloadUrl\": \"\","                              \
	"                \"hash\": \"\""                                      \
	"            }"                                                       \
	"        },"                                                          \
	"        \"publishTopics\": {},"                                      \
	"        \"subscribeTopics\": {}"                                     \
	"}"

#define TEST_BLOB_HTTP_REQUEST_INDEX            0x1ee70001
#define TEST_BLOB_HTTP_LOCAL_STORE_INDEX        0x1ee70002
#define TEST_BLOB_HTTP_CALLBACK_INDEX           0x1ee70003
#define TEST_BLOB_HTTP_CALLBACK_USER_DATA_INDEX 0x1ee70004

static struct {
	int call;
	struct evp_agent_notification_blob_result args;
	void *user_data;
} on_blob_result_mock;

static void
on_blob_result_expect(int result, int http_status, int error, void *user_data)
{
	on_blob_result_mock.call = 1;
	on_blob_result_mock.args.result = result;
	on_blob_result_mock.args.http_status = http_status;
	on_blob_result_mock.args.error = error;
	on_blob_result_mock.user_data = user_data;
}

static int
on_blob_result(const void *args, void *user_data)
{
	const struct evp_agent_notification_blob_result *r = args;
	assert_int_equal(on_blob_result_mock.args.result, r->result);
	assert_int_equal(on_blob_result_mock.args.http_status, r->http_status);
	assert_int_equal(on_blob_result_mock.args.error, r->error);
	assert_int_not_equal(on_blob_result_mock.call, 0);
	on_blob_result_mock.call--;
	return 0;
}

static void
blob_cb(EVP_BLOB_CALLBACK_REASON reason, const void *vp, void *userData)
{
	const struct EVP_BlobResultAzureBlob *result = vp;
	check_expected(reason);
	check_expected(result->result);
	check_expected(result->http_status);
	check_expected(result->error);
}

bool
__wrap_wasm_runtime_call_indirect(struct WASMExecEnv *exec_env,
				  uint32_t element_indices, uint32_t argc,
				  uint32_t argv[])
{

	switch (element_indices) {
	case TEST_BLOB_HTTP_CALLBACK_INDEX:
		{

			fprintf(stderr, "CALLED BLOB HTTP CALLBACK\n");
			int ret;
			assert_int_equal(argc, 3);

			// module inst
			wasm_module_inst_t module_inst =
				wasm_runtime_get_module_inst(exec_env);

			// Reason
			EVP_BLOB_CALLBACK_REASON reason = argv[0];

			// result
			ret = validate_app_str_addr(argv[1]);
			assert_true(ret);

			const void *result = addr_app_to_native(argv[1]);

			// user data
			uint32_t user_data = argv[2];

			blob_cb(reason, result, (void *)(uintptr_t)user_data);

			break;
		}
	default:
		fail_msg("invalid element_index");
	}

	return true;
}

int
session_setup(void)
{
	agent_test_setup();

	// register evp1 payloads
	agent_register_payload(DEPLOYMENT_MANIFEST_1, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_DEPLOYMENT_MANIFEST_1);

	// register TB payloads
	agent_register_payload(DEPLOYMENT_MANIFEST_1, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_DEPLOYMENT_MANIFEST_1);

	return 0;
}

int
suite_setup(void **state)
{
	struct context *ctxt = *state = malloc(sizeof(*ctxt));
	assert_non_null(ctxt);

	*ctxt = (struct context){0};

	session_setup();

	// start agent
	ctxt->agent = agent_test_start();
	assert_non_null(ctxt->agent);

	ctxt->d = (struct agent_deployment){.ctxt = ctxt->agent};

	assert_int_equal(
		evp_agent_notification_subscribe(ctxt->agent, "blob/result",
						 on_blob_result, NULL),
		0);

	// create backdoor instance
	ctxt->sdk = evp_agent_add_instance(ctxt->agent, TEST_INSTANCE_ID1);
	assert_non_null(ctxt->sdk);

	// send initial deployment
	agent_ensure_deployment(&ctxt->d,
				agent_get_payload(DEPLOYMENT_MANIFEST_1),
				TEST_DEPLOYMENT_ID1);

	char error_buf[64];

	// load module
	ctxt->wasm_module = wasm_runtime_load(dummy_wasm, dummy_wasm_len,
					      error_buf, sizeof(error_buf));

	assert_int_not_equal(ctxt->wasm_module, 0);

	// start wasm module: create WASM module_instance
	ctxt->wasm_module_inst = wasm_runtime_instantiate(
		ctxt->wasm_module, 8192, 16384, error_buf, sizeof(error_buf));

	wasm_runtime_set_custom_data(ctxt->wasm_module_inst, ctxt->sdk);

	// get execution environment
	ctxt->wasm_exec_env =
		wasm_runtime_get_exec_env_singleton(ctxt->wasm_module_inst);

	ctxt->wasm_handle = EVP_initialize_wasm(ctxt->wasm_exec_env);

	assert_int_equal(ctxt->wasm_handle, 0x1234);

	return 0;
}

int
suite_teardown(void **state)
{
	struct context *ctxt = *state;

	// cleanup wasm runtime
	wasm_runtime_deinstantiate(ctxt->wasm_module_inst);
	wasm_runtime_unload(ctxt->wasm_module);

	// stop module
	evp_agent_stop_instance(ctxt->agent, TEST_MODULE_INSTANCE_ID1);

	agent_test_exit();

	free(ctxt);
	*state = NULL;

	return 0;
}

static uint32_t
wasm_init_local_store(wasm_module_inst_t module_inst,
		      struct EVP_BlobLocalStore *store)
{
	struct EVP_BlobLocalStore_wasm *wasm_obj;
	char *filename = NULL;
	uint32_t offset = module_malloc(sizeof(*wasm_obj), (void **)&wasm_obj);
	if (store->filename) {
		uint32_t filename_sz = strlen(store->filename);
		wasm_obj->filename =
			module_malloc(filename_sz, (void **)&filename);
		strncpy(filename, store->filename, filename_sz);
	} else {
		wasm_obj->filename = 0;
	}
	wasm_obj->io_cb = 0; // TODO support store->io_cb;
	wasm_obj->blob_len = store->blob_len;

	return offset;
}

static uint32_t
wasm_init_blob_request(wasm_module_inst_t module_inst,
		       struct EVP_BlobRequestHttp *request)
{
	struct EVP_BlobRequestHttp_wasm *wasm_obj;
	char *url = NULL;
	uint32_t offset = module_malloc(sizeof(*wasm_obj), (void **)&wasm_obj);
	uint32_t url_sz = strlen(request->url);
	wasm_obj->url = module_malloc(url_sz, (void **)&url);
	strncpy(url, request->url, url_sz);

	return offset;
}

static void
wasm_deinit_blob_request(wasm_module_inst_t module_inst, uint32_t offset)
{
	struct EVP_BlobRequestHttp_wasm *wasm_obj = addr_app_to_native(offset);
	module_free(wasm_obj->url);
	module_free(offset);
}

static void
wasm_deinit_local_store(wasm_module_inst_t module_inst, uint32_t offset)
{
	struct EVP_BlobLocalStore_wasm *wasm_obj = addr_app_to_native(offset);
	module_free(wasm_obj->filename);
	module_free(offset);
}

void
blob_http_get_memory(void **state)
{
	struct context *ctxt = *state;
	wasm_module_inst_t module_inst = ctxt->wasm_module_inst;

	EVP_RESULT result;
	static struct EVP_BlobRequestHttp request;
	static struct EVP_BlobLocalStore local_store;
	local_store.io_cb = 0;
	local_store.blob_len = 0;
	local_store.filename = NULL;
	request.url = TEST_HTTP_GET_URL;

	on_blob_result_expect(EVP_BLOB_RESULT_SUCCESS, HTTP_STATUS_OK, 0,
			      NULL);

	uint32_t wasm_request = wasm_init_blob_request(module_inst, &request);
	uint32_t wasm_store = wasm_init_local_store(module_inst, &local_store);

	result = EVP_blobOperation_wasm(ctxt->wasm_exec_env, ctxt->wasm_handle,
					EVP_BLOB_TYPE_HTTP, EVP_BLOB_OP_GET,
					wasm_request, wasm_store,
					TEST_BLOB_HTTP_CALLBACK_INDEX, 0);
	assert_int_equal(result, EVP_OK);
	agent_poll(verify_equals, "GET " TEST_HTTP_GET_URL);
	// Blob download to memory is allowed

	// Expect processed blob to succeed
	expect_value(blob_cb, reason, EVP_BLOB_CALLBACK_REASON_DONE);
	expect_value(blob_cb, result->result, EVP_BLOB_RESULT_SUCCESS);
	expect_value(blob_cb, result->http_status, HTTP_STATUS_OK);
	expect_value(blob_cb, result->error, 0);
	result = EVP_processEvent_wasm(ctxt->wasm_exec_env, ctxt->wasm_handle,
				       1000);
	assert_int_equal(result, EVP_OK);
	assert_int_equal(on_blob_result_mock.call, 0);

	// Free app allocated objects
	wasm_deinit_blob_request(module_inst, wasm_request);
	wasm_deinit_local_store(module_inst, wasm_store);
}

void
blob_http_get_file(void **state)
{
	struct context *ctxt = *state;
	wasm_module_inst_t module_inst = ctxt->wasm_module_inst;

	EVP_RESULT result;
	static struct EVP_BlobRequestHttp request;
	static struct EVP_BlobLocalStore local_store;
	local_store.io_cb = 0;
	local_store.blob_len = 0;
	xasprintf((char **)&local_store.filename, "%s/%s",
		  path_get(MODULE_INSTANCE_PATH_ID), TEST_HTTP_GET_FILE);
	request.url = TEST_HTTP_GET_URL;

	on_blob_result_expect(EVP_BLOB_RESULT_SUCCESS, HTTP_STATUS_OK, 0,
			      NULL);

	uint32_t wasm_request = wasm_init_blob_request(module_inst, &request);
	uint32_t wasm_store = wasm_init_local_store(module_inst, &local_store);

	result = EVP_blobOperation_wasm(ctxt->wasm_exec_env, ctxt->wasm_handle,
					EVP_BLOB_TYPE_HTTP, EVP_BLOB_OP_GET,
					wasm_request, wasm_store,
					TEST_BLOB_HTTP_CALLBACK_INDEX, 0);
	assert_int_equal(result, EVP_OK);
	agent_poll(verify_equals, "GET " TEST_HTTP_GET_URL);

	// Expect processed blob to succeed
	expect_value(blob_cb, reason, EVP_BLOB_CALLBACK_REASON_DONE);
	expect_value(blob_cb, result->result, EVP_BLOB_RESULT_SUCCESS);
	expect_value(blob_cb, result->http_status, HTTP_STATUS_OK);
	expect_value(blob_cb, result->error, 0);
	result = EVP_processEvent_wasm(ctxt->wasm_exec_env, ctxt->wasm_handle,
				       TEST_PROCESS_EVENT_TIMEOUT);
	assert_int_equal(result, EVP_OK);
	assert_int_equal(on_blob_result_mock.call, 0);

	// Free app allocated objects
	wasm_deinit_blob_request(module_inst, wasm_request);
	wasm_deinit_local_store(module_inst, wasm_store);
	free(__UNCONST(local_store.filename));
}

void
blob_http_put_file(void **state)
{
	struct context *ctxt = *state;
	wasm_module_inst_t module_inst = ctxt->wasm_module_inst;

	EVP_RESULT result;
	static struct EVP_BlobRequestHttp request;
	static struct EVP_BlobLocalStore local_store;
	local_store.io_cb = 0;
	local_store.blob_len = 0;
	xasprintf((char **)&local_store.filename, "%s/%s",
		  path_get(MODULE_INSTANCE_PATH_ID), TEST_HTTP_PUT_FILE);
	request.url = TEST_HTTP_PUT_URL;

	on_blob_result_expect(EVP_BLOB_RESULT_SUCCESS, HTTP_STATUS_OK, 0,
			      NULL);

	// Create file to put
	assert_int_equal(0, systemf("echo 'Some content file' > %s/%s",
				    path_get(MODULE_INSTANCE_PATH_ID),
				    TEST_HTTP_PUT_FILE));

	uint32_t wasm_request = wasm_init_blob_request(module_inst, &request);
	uint32_t wasm_store = wasm_init_local_store(module_inst, &local_store);

	result = EVP_blobOperation_wasm(ctxt->wasm_exec_env, ctxt->wasm_handle,
					EVP_BLOB_TYPE_HTTP, EVP_BLOB_OP_PUT,
					wasm_request, wasm_store,
					TEST_BLOB_HTTP_CALLBACK_INDEX, 0);
	assert_int_equal(result, EVP_OK);
	agent_poll(verify_equals, "PUT " TEST_HTTP_PUT_URL);

	// Expect processed blob to succeed
	expect_value(blob_cb, reason, EVP_BLOB_CALLBACK_REASON_DONE);
	expect_value(blob_cb, result->result, EVP_BLOB_RESULT_SUCCESS);
	expect_value(blob_cb, result->http_status, HTTP_STATUS_OK);
	expect_value(blob_cb, result->error, 0);
	result = EVP_processEvent_wasm(ctxt->wasm_exec_env, ctxt->wasm_handle,
				       1000);
	assert_int_equal(result, EVP_OK);
	assert_int_equal(on_blob_result_mock.call, 0);

	// Free app allocated objects
	wasm_deinit_blob_request(module_inst, wasm_request);
	wasm_deinit_local_store(module_inst, wasm_store);
	free(__UNCONST(local_store.filename));
}

int
main(void)
{
	// define tests
	const struct CMUnitTest blob_http[] = {
		cmocka_unit_test(blob_http_get_memory),
		cmocka_unit_test(blob_http_get_file),
		cmocka_unit_test(blob_http_put_file),
	};
	// suite_setup and run tests
	return cmocka_run_group_tests(blob_http, suite_setup, suite_teardown);
}
