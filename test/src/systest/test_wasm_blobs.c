/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <evp/sdk.h>

#include <internal/util.h>

#include "agent_internal.h"
#include "agent_test.h"
#include "hub.h"
#include "path.h"
#include "req.h"
#include "sdk_local_wasm.h"
#include "wasm_export.h"
#include "wasm_utils.h"
#include "xlog.h"

// Common for all blob types
#define TEST_PUT_FILE "boofar.bin"
#define TEST_GET_FILE "foobar.txt"

// HTTP blob type
#define TEST_HTTP_GET_URL "https://baz/boo"
#define TEST_HTTP_PUT_URL "http://foobar"

// EVP blob type
#define TEST_EVP_PUT_REMOTE_NAME  "remote_name_value_request"
#define TEST_EVP_PUT_STORAGE_NAME "storage_name_value"
#define TEST_EVP_PUT_SAS                                                      \
	"https://evpstoragecontainer.blob.core.windows.net/evpcontainer/"     \
	"blob_test"

#define TEST_EVP_PUT_SAS_2 "A_EXAMPLE_SAS_TEST_2"

#define TEST_AZURE_PUT_SAS TEST_EVP_PUT_SAS
#define TEST_AZURE_GET_SAS TEST_EVP_PUT_SAS

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
	struct agent_deployment d;
	struct EVP_client *sdk;
	EVP_RPC_ID reqid;
	sem_t sem;

	// WASM
	int wasm_handle;
	wasm_exec_env_t wasm_exec_env;
	wasm_module_t wasm_module;
	wasm_module_inst_t wasm_module_inst;
} g_state;

/*
 * this strcut will be reused for:
 * 	- http
 *  - azure
 */
struct EVP_BlobRequestHttp_wasm {
	uint32_t url;
};

struct EVP_BlobRequestEvpExt_wasm {
	uint32_t remote_name;
	uint32_t storage_name;
};

struct EVP_BlobLocalStore_wasm {
	uint32_t filename;
	uint32_t io_cb;
	uint32_t blob_len;
};

enum test_direct_command_payloads {
	DEPLOYMENT_MANIFEST_1,
	STP_RESPONSE_1,
	STP_RESPONSE_2,
};

struct test {
	struct evp_agent_context *ctxt;
	struct agent_deployment d;
};

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

#define EVP1_STP_RESPONSE_1                                                   \
	"{"                                                                   \
	"\"method\":\"StorageToken\","                                        \
	"\"params\":{"                                                        \
	"\"URL\":\"" TEST_EVP_PUT_SAS "\","                                   \
	"\"headers\":{\"x-ms-blob-type\":"                                    \
	"\"BlockBlob\"},"                                                     \
	"\"cert\":\"56176780-9747-11ed-9bd5-"                                 \
	"5f138e81521e\""                                                      \
	"}"                                                                   \
	"}"

#define TB_STP_RESPONSE_1                                                     \
	"{"                                                                   \
	"\"storagetoken-response\":{"                                         \
	"\"reqid\":\"%s\","                                                   \
	"\"status\":\"ok\","                                                  \
	"\"URL\":\"" TEST_EVP_PUT_SAS "\","                                   \
	"\"headers\":{\"x-ms-blob-type\":"                                    \
	"\"BlockBlob\"}"                                                      \
	"}"                                                                   \
	"}"

#define EVP1_STP_RESPONSE_2                                                   \
	"{"                                                                   \
	"\"method\":\"StorageToken\","                                        \
	"\"params\":{"                                                        \
	"\"URL\":\"" TEST_EVP_PUT_SAS_2 "\","                                 \
	"\"headers\":{\"x-ms-blob-type\":"                                    \
	"\"BlockBlob\"},"                                                     \
	"\"cert\":\"56176780-9747-11ed-9bd5-"                                 \
	"5f138e81521e\""                                                      \
	"}"                                                                   \
	"}"

#define TB_STP_RESPONSE_2                                                     \
	"{"                                                                   \
	"\"storagetoken-response\":{"                                         \
	"\"reqid\":\"%s\","                                                   \
	"\"status\":\"ok\","                                                  \
	"\"URL\":\"" TEST_EVP_PUT_SAS_2 "\","                                 \
	"\"headers\":{\"x-ms-blob-type\":"                                    \
	"\"BlockBlob\"}"                                                      \
	"}"                                                                   \
	"}"

#define TEST_BLOB_HTTP_CALLBACK_INDEX 0x1ee70001

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

static int
session_setup(void)
{
	agent_test_setup();

	// DEPLOYMENT_MANIFEST_1 = initial deployment
	agent_register_payload(DEPLOYMENT_MANIFEST_1, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_DEPLOYMENT_MANIFEST_1);
	agent_register_payload(DEPLOYMENT_MANIFEST_1, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_DEPLOYMENT_MANIFEST_1);

	// STP_RESPONSE_1 = response for EVP request  used in
	// blob_evp_ext_put_file
	agent_register_payload(STP_RESPONSE_1, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_STP_RESPONSE_1);
	agent_register_payload(STP_RESPONSE_1, EVP_HUB_TYPE_EVP2_TB,
			       TB_STP_RESPONSE_1);

	// STP_RESPONSE_2 = response for EVP request used in
	// blob_evp_ext_default_put_file
	agent_register_payload(STP_RESPONSE_2, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_STP_RESPONSE_2);
	agent_register_payload(STP_RESPONSE_2, EVP_HUB_TYPE_EVP2_TB,
			       TB_STP_RESPONSE_2);

	return 0;
}

int
suite_setup(void **state)
{
	struct context *ctxt = *state = &g_state;

	session_setup();

	// start agent
	ctxt->agent = agent_test_start();
	ctxt->d = (struct agent_deployment){.ctxt = ctxt->agent};

	// create backdoor instance
	ctxt->sdk = evp_agent_add_instance(ctxt->agent, TEST_INSTANCE_ID1);
	assert_non_null(ctxt->sdk);

	assert_int_equal(sem_init(&ctxt->sem, 0, 0), 0);

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
	assert_int_equal(sem_destroy(&ctxt->sem), 0);
	*state = NULL;

	return 0;
}

static uint32_t
wasm_init_local_store(wasm_module_inst_t module_inst,
		      struct EVP_BlobLocalStore *store)
{
	struct EVP_BlobLocalStore_wasm *wasm_obj;
	uint32_t offset = module_malloc(sizeof(*wasm_obj), (void **)&wasm_obj);
	if (store->filename) {
		wasm_obj->filename =
			evp_wasm_string_create(module_inst, store->filename);
	} else {
		wasm_obj->filename = 0;
	}
	wasm_obj->io_cb = 0; // TODO support store->io_cb;
	wasm_obj->blob_len = store->blob_len;

	return offset;
}

static uint32_t
wasm_init_blob_request(wasm_module_inst_t module_inst, void *blob_request,
		       EVP_BLOB_TYPE blob_type)
{

	uint32_t offset = 0;
	switch (blob_type) {
	case EVP_BLOB_TYPE_HTTP:
	case EVP_BLOB_TYPE_AZURE_BLOB:
		{
			struct EVP_BlobRequestHttp *request = blob_request;
			struct EVP_BlobRequestHttp_wasm *wasm_obj;
			offset = module_malloc(sizeof(*wasm_obj),
					       (void **)&wasm_obj);

			wasm_obj->url = evp_wasm_string_create(module_inst,
							       request->url);

			break;
		}
	case EVP_BLOB_TYPE_EVP_EXT:
		{
			struct EVP_BlobRequestEvpExt *request = blob_request;
			struct EVP_BlobRequestEvpExt_wasm *wasm_obj;
			offset = module_malloc(sizeof(*wasm_obj),
					       (void **)&wasm_obj);

			wasm_obj->remote_name = evp_wasm_string_create(
				module_inst, request->remote_name);
			wasm_obj->storage_name = evp_wasm_string_create(
				module_inst, request->storage_name);

			break;
		}
	default:
		xlog_error("Blob type %d still not supported", blob_type);
		assert_true(false);
	}

	return offset;
}

static void
wasm_deinit_blob_request(wasm_module_inst_t module_inst, uint32_t offset,
			 EVP_BLOB_TYPE blob_type)
{

	switch (blob_type) {
	case EVP_BLOB_TYPE_HTTP:
	case EVP_BLOB_TYPE_AZURE_BLOB:
		{
			struct EVP_BlobRequestHttp_wasm *wasm_obj =
				addr_app_to_native(offset);
			module_free(wasm_obj->url);
			break;
		}

	case EVP_BLOB_TYPE_EVP_EXT:
		{
			struct EVP_BlobRequestEvpExt_wasm *wasm_obj =
				addr_app_to_native(offset);
			module_free(wasm_obj->remote_name);
			module_free(wasm_obj->storage_name);
			break;
		}

	default:
		xlog_error("Blob type %d still not supported", blob_type);
		assert_true(false);
	}

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

	uint32_t wasm_request = wasm_init_blob_request(module_inst, &request,
						       EVP_BLOB_TYPE_HTTP);
	uint32_t wasm_store = wasm_init_local_store(module_inst, &local_store);

	result = EVP_blobOperation_wasm(ctxt->wasm_exec_env, ctxt->wasm_handle,
					EVP_BLOB_TYPE_HTTP, EVP_BLOB_OP_GET,
					wasm_request, wasm_store,
					TEST_BLOB_HTTP_CALLBACK_INDEX, 0);
	assert_int_equal(result, EVP_OK);
	// Blob download to memory is allowed

	// Expect processed blob to succeed
	expect_value(blob_cb, reason, EVP_BLOB_CALLBACK_REASON_DONE);
	expect_value(blob_cb, result->result, EVP_BLOB_RESULT_SUCCESS);
	expect_value(blob_cb, result->http_status, HTTP_STATUS_OK);
	expect_value(blob_cb, result->error, 0);
	result = EVP_processEvent_wasm(ctxt->wasm_exec_env, ctxt->wasm_handle,
				       1000);
	assert_int_equal(result, EVP_OK);

	// Free app allocated objects
	wasm_deinit_blob_request(module_inst, wasm_request,
				 EVP_BLOB_TYPE_HTTP);
	wasm_deinit_local_store(module_inst, wasm_store);
}

void
blob_http_put_memory(void **state)
{
	xlog_info("GOOD CASE: Blob PUT operations from memory are supported "
		  "(Note: for wasm 0 bytes)");

	struct context *ctxt = *state;
	wasm_module_inst_t module_inst = ctxt->wasm_module_inst;

	EVP_RESULT result;
	static struct EVP_BlobRequestHttp request;
	static struct EVP_BlobLocalStore local_store;
	local_store.io_cb = 0;
	local_store.blob_len = 0;
	local_store.filename = NULL;
	request.url = TEST_HTTP_PUT_URL;

	uint32_t wasm_request = wasm_init_blob_request(module_inst, &request,
						       EVP_BLOB_TYPE_HTTP);
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

	// Free app allocated objects
	wasm_deinit_blob_request(module_inst, wasm_request,
				 EVP_BLOB_TYPE_HTTP);
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
		  path_get(MODULE_INSTANCE_PATH_ID), TEST_GET_FILE);
	request.url = TEST_HTTP_GET_URL;

	uint32_t wasm_request = wasm_init_blob_request(module_inst, &request,
						       EVP_BLOB_TYPE_HTTP);
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
				       1000);
	assert_int_equal(result, EVP_OK);

	// Free app allocated objects
	wasm_deinit_blob_request(module_inst, wasm_request,
				 EVP_BLOB_TYPE_HTTP);
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
		  path_get(MODULE_INSTANCE_PATH_ID), TEST_PUT_FILE);
	request.url = TEST_HTTP_PUT_URL;

	// Create file to put
	assert_int_equal(0, systemf("echo 'Some content file' > %s",
				    local_store.filename));

	uint32_t wasm_request = wasm_init_blob_request(module_inst, &request,
						       EVP_BLOB_TYPE_HTTP);
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

	// Free app allocated objects
	wasm_deinit_blob_request(module_inst, wasm_request,
				 EVP_BLOB_TYPE_HTTP);
	wasm_deinit_local_store(module_inst, wasm_store);
	free(__UNCONST(local_store.filename));
}

void
blob_evp_ext_put_file(void **state)
{
	struct context *ctxt = *state;
	wasm_module_inst_t module_inst = ctxt->wasm_module_inst;

	EVP_RESULT result;
	static struct EVP_BlobRequestEvpExt request;
	static struct EVP_BlobLocalStore local_store;
	local_store.io_cb = 0;
	local_store.blob_len = 0;
	xasprintf((char **)&local_store.filename, "%s/%s",
		  path_get(MODULE_INSTANCE_PATH_ID), TEST_PUT_FILE);
	request.remote_name = TEST_EVP_PUT_REMOTE_NAME;
	request.storage_name = TEST_EVP_PUT_STORAGE_NAME;

	// Create file to put
	assert_int_equal(0, systemf("echo 'file content' > %s/%s",
				    path_get(MODULE_INSTANCE_PATH_ID),
				    TEST_PUT_FILE));

	uint32_t wasm_request = wasm_init_blob_request(module_inst, &request,
						       EVP_BLOB_TYPE_EVP_EXT);
	uint32_t wasm_store = wasm_init_local_store(module_inst, &local_store);

	result = EVP_blobOperation_wasm(ctxt->wasm_exec_env, ctxt->wasm_handle,
					EVP_BLOB_TYPE_EVP_EXT, EVP_BLOB_OP_PUT,
					wasm_request, wasm_store,
					TEST_BLOB_HTTP_CALLBACK_INDEX, 0);
	assert_int_equal(result, EVP_OK);

	// At this point the agent sends a StorageToken request, check it
	static struct multi_check test_set_device_state1[] = {
		{.value = TEST_EVP_PUT_REMOTE_NAME},
		{.value = TEST_EVP_PUT_STORAGE_NAME},
		{.value = NULL}, // List termination
	};
	agent_poll(verify_contains_in_unordered_set, test_set_device_state1);

	// Send the RPC reponse (as HUB does)
	char *reqid, *response;

	assert_int_equal(sem_wait(&ctxt->sem), 0);
	xasprintf(&reqid, "%ju", g_state.reqid);
	response = agent_get_payload_formatted(STP_RESPONSE_1, reqid);
	assert_non_null(response);
	agent_send_storagetoken_response(ctxt->agent, response, reqid);
	free(reqid);
	free(response);

	// Now the agent will dot he blob operation
	agent_poll(verify_equals, "PUT " TEST_EVP_PUT_SAS);

	// Expect processed blob to succeed
	expect_value(blob_cb, reason, EVP_BLOB_CALLBACK_REASON_DONE);
	expect_value(blob_cb, result->result, EVP_BLOB_RESULT_SUCCESS);
	expect_value(blob_cb, result->http_status, HTTP_STATUS_OK);
	expect_value(blob_cb, result->error, 0);
	result = EVP_processEvent_wasm(ctxt->wasm_exec_env, ctxt->wasm_handle,
				       1000);
	assert_int_equal(result, EVP_OK);

	// Free app allocated objects
	wasm_deinit_blob_request(module_inst, wasm_request,
				 EVP_BLOB_TYPE_EVP_EXT);
	wasm_deinit_local_store(module_inst, wasm_store);
	free(__UNCONST(local_store.filename));
}

void
blob_evp_ext_default_put_file(void **state)
{

	xlog_info("GOOD CASE: if the storage_name is null the storage_name "
		  "field is not send");

	struct context *ctxt = *state;
	wasm_module_inst_t module_inst = ctxt->wasm_module_inst;

	EVP_RESULT result;
	static struct EVP_BlobRequestEvpExt request;
	static struct EVP_BlobLocalStore local_store;
	local_store.io_cb = 0;
	local_store.blob_len = 0;
	xasprintf((char **)&local_store.filename, "%s/%s",
		  path_get(MODULE_INSTANCE_PATH_ID), TEST_PUT_FILE);
	request.remote_name = TEST_EVP_PUT_REMOTE_NAME;
	request.storage_name = NULL;

	// Create file to put
	assert_int_equal(0, systemf("echo 'file content' > %s/%s",
				    path_get(MODULE_INSTANCE_PATH_ID),
				    TEST_PUT_FILE));

	uint32_t wasm_request = wasm_init_blob_request(module_inst, &request,
						       EVP_BLOB_TYPE_EVP_EXT);
	uint32_t wasm_store = wasm_init_local_store(module_inst, &local_store);

	result = EVP_blobOperation_wasm(ctxt->wasm_exec_env, ctxt->wasm_handle,
					EVP_BLOB_TYPE_EVP_EXT, EVP_BLOB_OP_PUT,
					wasm_request, wasm_store,
					TEST_BLOB_HTTP_CALLBACK_INDEX, 0);
	assert_int_equal(result, EVP_OK);

	// At this point the agent sends a StorageToken request WITHOUT
	// storage_bame, check it
	expect_unexpect_t val = {.expect = TEST_EVP_PUT_REMOTE_NAME,
				 .unexpect = "storage_name"};
	agent_poll(verify_contains_except, &val);

	// Send the RPC reponse (as HUB does)
	char *reqid, *response;

	assert_int_equal(sem_wait(&ctxt->sem), 0);
	xasprintf(&reqid, "%ju", g_state.reqid);
	response = agent_get_payload_formatted(STP_RESPONSE_2, reqid);
	assert_non_null(response);
	agent_send_storagetoken_response(ctxt->agent, response, reqid);
	free(reqid);
	free(response);

	// Now the agent will dot he blob operation
	agent_poll(verify_equals, "PUT " TEST_EVP_PUT_SAS_2);

	// Expect processed blob to succeed
	expect_value(blob_cb, reason, EVP_BLOB_CALLBACK_REASON_DONE);
	expect_value(blob_cb, result->result, EVP_BLOB_RESULT_SUCCESS);
	expect_value(blob_cb, result->http_status, HTTP_STATUS_OK);
	expect_value(blob_cb, result->error, 0);
	result = EVP_processEvent_wasm(ctxt->wasm_exec_env, ctxt->wasm_handle,
				       1000);
	assert_int_equal(result, EVP_OK);

	// Free app allocated objects
	wasm_deinit_blob_request(module_inst, wasm_request,
				 EVP_BLOB_TYPE_EVP_EXT);
	wasm_deinit_local_store(module_inst, wasm_store);
	free(__UNCONST(local_store.filename));
}

void
blob_evp_ext_get_file(void **state)
{
	xlog_info("BAD CASE: be sure that EVP_BLOB_EXT GET operation is not "
		  "supported and error is returned.");
	struct context *ctxt = *state;
	wasm_module_inst_t module_inst = ctxt->wasm_module_inst;

	EVP_RESULT result;
	static struct EVP_BlobRequestEvpExt request;
	static struct EVP_BlobLocalStore local_store;
	local_store.io_cb = 0;
	local_store.blob_len = 0;
	xasprintf((char **)&local_store.filename, "%s/%s",
		  path_get(MODULE_INSTANCE_PATH_ID), TEST_GET_FILE);
	request.remote_name = TEST_EVP_PUT_REMOTE_NAME;
	request.storage_name = TEST_EVP_PUT_REMOTE_NAME;

	uint32_t wasm_request = wasm_init_blob_request(module_inst, &request,
						       EVP_BLOB_TYPE_EVP_EXT);
	uint32_t wasm_store = wasm_init_local_store(module_inst, &local_store);

	result = EVP_blobOperation_wasm(ctxt->wasm_exec_env, ctxt->wasm_handle,
					EVP_BLOB_TYPE_EVP_EXT, EVP_BLOB_OP_GET,
					wasm_request, wasm_store,
					TEST_BLOB_HTTP_CALLBACK_INDEX, 0);
	assert_int_equal(result, EVP_NOTSUP);

	// Free app allocated objects
	wasm_deinit_blob_request(module_inst, wasm_request,
				 EVP_BLOB_TYPE_EVP_EXT);
	wasm_deinit_local_store(module_inst, wasm_store);
	free(__UNCONST(local_store.filename));
}

void
blob_azure_put_file(void **state)
{
	struct context *ctxt = *state;
	wasm_module_inst_t module_inst = ctxt->wasm_module_inst;

	EVP_RESULT result;
	static struct EVP_BlobRequestAzureBlob request;
	static struct EVP_BlobLocalStore local_store;
	local_store.io_cb = 0;
	local_store.blob_len = 0;
	xasprintf((char **)&local_store.filename, "%s/%s",
		  path_get(MODULE_INSTANCE_PATH_ID), TEST_PUT_FILE);
	request.url = TEST_AZURE_PUT_SAS;

	// Create file to put
	assert_int_equal(0, systemf("echo 'file content' > %s/%s",
				    path_get(MODULE_INSTANCE_PATH_ID),
				    TEST_PUT_FILE));

	uint32_t wasm_request = wasm_init_blob_request(
		module_inst, &request, EVP_BLOB_TYPE_AZURE_BLOB);
	uint32_t wasm_store = wasm_init_local_store(module_inst, &local_store);

	result = EVP_blobOperation_wasm(
		ctxt->wasm_exec_env, ctxt->wasm_handle,
		EVP_BLOB_TYPE_AZURE_BLOB, EVP_BLOB_OP_PUT, wasm_request,
		wasm_store, TEST_BLOB_HTTP_CALLBACK_INDEX, 0);
	assert_int_equal(result, EVP_OK);

	// Now the agent will do the blob operation
	agent_poll(verify_equals, "PUT " TEST_EVP_PUT_SAS);

	// Expect processed blob to succeed
	expect_value(blob_cb, reason, EVP_BLOB_CALLBACK_REASON_DONE);
	expect_value(blob_cb, result->result, EVP_BLOB_RESULT_SUCCESS);
	expect_value(blob_cb, result->http_status, HTTP_STATUS_OK);
	expect_value(blob_cb, result->error, 0);
	result = EVP_processEvent_wasm(ctxt->wasm_exec_env, ctxt->wasm_handle,
				       1000);
	assert_int_equal(result, EVP_OK);

	// Free app allocated objects
	wasm_deinit_blob_request(module_inst, wasm_request,
				 EVP_BLOB_TYPE_AZURE_BLOB);
	wasm_deinit_local_store(module_inst, wasm_store);
	free(__UNCONST(local_store.filename));
}

void
blob_azure_get_file(void **state)
{
	struct context *ctxt = *state;
	wasm_module_inst_t module_inst = ctxt->wasm_module_inst;

	EVP_RESULT result;
	static struct EVP_BlobRequestAzureBlob request;
	static struct EVP_BlobLocalStore local_store;
	local_store.io_cb = 0;
	local_store.blob_len = 0;
	xasprintf((char **)&local_store.filename, "%s/%s",
		  path_get(MODULE_INSTANCE_PATH_ID), TEST_GET_FILE);
	request.url = TEST_AZURE_GET_SAS;

	uint32_t wasm_request = wasm_init_blob_request(
		module_inst, &request, EVP_BLOB_TYPE_AZURE_BLOB);
	uint32_t wasm_store = wasm_init_local_store(module_inst, &local_store);

	result = EVP_blobOperation_wasm(
		ctxt->wasm_exec_env, ctxt->wasm_handle,
		EVP_BLOB_TYPE_AZURE_BLOB, EVP_BLOB_OP_GET, wasm_request,
		wasm_store, TEST_BLOB_HTTP_CALLBACK_INDEX, 0);
	assert_int_equal(result, EVP_OK);

	// Now the agent will do the blob operation
	agent_poll(verify_equals, "GET " TEST_AZURE_GET_SAS);

	// Expect processed blob to succeed
	expect_value(blob_cb, reason, EVP_BLOB_CALLBACK_REASON_DONE);
	expect_value(blob_cb, result->result, EVP_BLOB_RESULT_SUCCESS);
	expect_value(blob_cb, result->http_status, HTTP_STATUS_OK);
	expect_value(blob_cb, result->error, 0);
	result = EVP_processEvent_wasm(ctxt->wasm_exec_env, ctxt->wasm_handle,
				       1000);
	assert_int_equal(result, EVP_OK);

	// Free app allocated objects
	wasm_deinit_blob_request(module_inst, wasm_request,
				 EVP_BLOB_TYPE_AZURE_BLOB);
	wasm_deinit_local_store(module_inst, wasm_store);
	free(__UNCONST(local_store.filename));
}

int
__wrap_evp_send_storagetoken_request(struct evp_agent_context *agent,
				     struct request *req, JSON_Value *v)
{
	int __real_evp_send_storagetoken_request(
		struct evp_agent_context * agent, struct request * req,
		JSON_Value * v);

	g_state.reqid = req->id;
	assert_int_equal(sem_post(&g_state.sem), 0);
	xlog_info(__func__);
	return __real_evp_send_storagetoken_request(agent, req, v);
}

int
main(void)
{
	// define tests
	const struct CMUnitTest blob_http[] = {
		cmocka_unit_test(blob_evp_ext_put_file),
		cmocka_unit_test(blob_evp_ext_default_put_file),

		cmocka_unit_test(blob_http_get_memory),
		cmocka_unit_test(blob_http_put_memory),
		cmocka_unit_test(blob_http_get_file),
		cmocka_unit_test(blob_http_put_file),
		cmocka_unit_test(blob_azure_put_file),
		cmocka_unit_test(blob_azure_get_file),

		// bad cases
		cmocka_unit_test(blob_evp_ext_get_file),
	};
	// suite_setup and run tests
	return cmocka_run_group_tests(blob_http, suite_setup, suite_teardown);
}
