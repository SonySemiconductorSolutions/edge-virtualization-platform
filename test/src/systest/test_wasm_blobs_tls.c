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

#include "webclient/webclient.h"

#include "agent_test.h"
#include "hub.h"
#include "path.h"
#include "req.h"
#include "sdk_local_wasm.h"
#include "tls.h"
#include "wasm_export.h"
#include "wasm_utils.h"
#include "websrv/proxy.h"
#include "websrv/websrv.h"
#include "xlog.h"

#define _STRING(v) #v
#define STRING(v)  _STRING(v)

// #define TEST_DEFAULT_EVENT_TIMEOUT -1
#define TEST_DEFAULT_EVENT_TIMEOUT 2000

// HTTP blob type
#define TEST_HTTP_GET_RESOURCE "/boo"
#define TEST_HTTP_PUT_RESOURCE "/"

#define TEST_HTTP_SERVER_PORT    0
#define TEST_PROXY_FRONTEND_PORT 0
#define TEST_ROOT_URL_FMT        "https://localhost:%hu"
#define TEST_HTTP_GET_URL_FMT    TEST_ROOT_URL_FMT TEST_HTTP_GET_RESOURCE
#define TEST_HTTP_PUT_URL_FMT    TEST_ROOT_URL_FMT TEST_HTTP_PUT_RESOURCE

// EVP blob type
#define TEST_EVP_PUT_REMOTE_NAME  "remote_name_value_request"
#define TEST_EVP_PUT_STORAGE_NAME "storage_name_value"
#define TEST_EVP_PUT_SAS_FMT      TEST_HTTP_PUT_URL_FMT

#define TEST_AZURE_PUT_SAS_FMT TEST_HTTP_PUT_URL_FMT
#define TEST_AZURE_GET_SAS_FMT TEST_HTTP_GET_URL_FMT

/*
 * The reqId counter is owen by the agent.
 * It is incremented in each req
 * So for each TC the number will be different
 */
#define REQID_FMT     "%s"
#define REQID_EVP1    REQID_FMT
#define REQID_EVP2_TB REQID_FMT

#define MAGIC_USERDATA 0xdeadbeef

/* dummy.wat contents:
 * ```
 * (module (memory 1))
 * ```
 * assemble with `wat2wasm` and dump with `xxd -i`
 */
unsigned char dummy_wasm[] = {0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00,
			      0x00, 0x05, 0x03, 0x01, 0x00, 0x01};
unsigned int dummy_wasm_len = 13;

bool g_network_ssl_timeout_error = false;

struct context {
	// Paths
	char *put_file;
	char *get_file;

	// EVP
	struct evp_agent_context *agent;
	struct EVP_client *sdk;

	// WASM
	int wasm_handle;
	wasm_exec_env_t wasm_exec_env;
	wasm_module_t wasm_module;
	wasm_module_inst_t wasm_module_inst;

	// WEB server
	uint16_t backend_port;
	uint16_t frontend_port;

	// Requests
	char *reqid;
	EVP_RPC_ID reqid_offset;
};

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
	DEPLOYMENT_MANIFEST,
	STP_RESPONSE,
};

#define TEST_INSTANCE_ID1        "backdoor-mdc"
#define TEST_METHOD_NAME1        "test-method"
#define TEST_DEPLOYMENT_ID1      "2dc1a1c3-531b-4693-abba-a4a039bb827d"
#define TEST_MODULE_INSTANCE_ID1 "07fe77d5-7117-4326-9042-47fda5dd9bf5"
#define TEST_MODULE_ID1          "b91fe3e8-df6d-41b7-90cb-72f8b92bdf5e"

#define EVP1_DEPLOYMENT_MANIFEST                                              \
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

#define EVP2_DEPLOYMENT_MANIFEST                                              \
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

#define EVP1_STP_RESPONSE                                                     \
	"{"                                                                   \
	"\"method\":\"StorageToken\","                                        \
	"\"params\":{"                                                        \
	"\"URL\":\"" TEST_EVP_PUT_SAS_FMT "\","                               \
	"\"headers\":{\"x-ms-blob-type\":"                                    \
	"\"BlockBlob\"},"                                                     \
	"\"cert\":\"56176780-9747-11ed-9bd5-"                                 \
	"5f138e81521e\""                                                      \
	"}"                                                                   \
	"}"

#define TB_STP_RESPONSE                                                       \
	"{"                                                                   \
	"\"storagetoken-response\":{"                                         \
	"\"status\":\"ok\","                                                  \
	"\"URL\":\"" TEST_EVP_PUT_SAS_FMT "\","                               \
	"\"headers\":{\"x-ms-blob-type\":"                                    \
	"\"BlockBlob\"}"                                                      \
	"},"                                                                  \
	"\"reqid\":\"" REQID_EVP2_TB "\""                                     \
	"}"

#define TEST_BLOB_HTTP_CALLBACK_INDEX        0x1ee70001
#define TEST_BLOB_HTTP_GET_IO_CALLBACK_INDEX 0x1ee70002
#define TEST_BLOB_HTTP_PUT_IO_CALLBACK_INDEX 0x1ee70003

int __real_webclient_perform(FAR struct webclient_context *ctx);
int
__wrap_webclient_perform(FAR struct webclient_context *ctx)
{
	char *str;
	xasprintf(&str, "%s %s", ctx->method, ctx->url);
	agent_write_to_pipe(str);
	free(str);
	for (size_t i = 0; i < ctx->nheaders; ++i) {
		agent_write_to_pipe(ctx->headers[i]);
	}
	return __real_webclient_perform(ctx);
}

static void
blob_cb(EVP_BLOB_CALLBACK_REASON reason, const void *vp, void *userData)
{
	const struct EVP_BlobResultAzureBlob *result = vp;
	check_expected(reason);
	check_expected(result->result);
	check_expected(result->http_status);
	check_expected(result->error);
	check_expected(userData);
}

static EVP_BLOB_IO_RESULT
blob_get_io_cb(void *buf, size_t buflen, void *userData)
{
	fprintf(stderr, "%s: buf=%p, buflen=%zu (\"%.*s\"), userData=%p\n",
		__func__, buf, buflen, (int)buflen, (const char *)buf,
		userData);
	check_expected(userData);
	return EVP_BLOB_IO_RESULT_SUCCESS;
}

static EVP_BLOB_IO_RESULT
blob_put_io_cb(void *buf, size_t buflen, void *userData)
{
	memset(buf, 'F', buflen);
	check_expected(userData);
	return EVP_BLOB_IO_RESULT_SUCCESS;
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

			const void *result = wasm_runtime_addr_app_to_native(
				module_inst, argv[1]);

			// user data
			uint32_t user_data = argv[2];

			blob_cb(reason, result, (void *)(uintptr_t)user_data);

			break;
		}
	case TEST_BLOB_HTTP_GET_IO_CALLBACK_INDEX:
		{

			fprintf(stderr, "CALLED BLOB IO GET HTTP CALLBACK\n");
			assert_int_equal(argc, 3);

			// module inst
			wasm_module_inst_t module_inst =
				wasm_runtime_get_module_inst(exec_env);

			size_t n = argv[1];

			assert_int_not_equal(wasm_runtime_validate_app_addr(
						     module_inst, argv[0], n),
					     0);

			void *buf = wasm_runtime_addr_app_to_native(
				module_inst, argv[0]);

			assert_non_null(buf);

			argv[0] = blob_get_io_cb(buf, n,
						 (void *)(uintptr_t)argv[2]);

			break;
		}
	case TEST_BLOB_HTTP_PUT_IO_CALLBACK_INDEX:
		{

			fprintf(stderr, "CALLED BLOB IO PUT HTTP CALLBACK\n");
			assert_int_equal(argc, 3);

			// module inst
			wasm_module_inst_t module_inst =
				wasm_runtime_get_module_inst(exec_env);

			size_t n = argv[1];

			assert_int_not_equal(wasm_runtime_validate_app_addr(
						     module_inst, argv[0], n),
					     0);

			void *buf = wasm_runtime_addr_app_to_native(
				module_inst, argv[0]);

			assert_non_null(buf);

			argv[0] = blob_put_io_cb(buf, n,
						 (void *)(uintptr_t)argv[2]);

			break;
		}
	default:
		fail_msg("invalid element_index");
	}

	return true;
}

int
session_setup(void **state)
{
	putenv("EVP_HTTPS_CA_CERT=certs/ca-cert.pem");

	agent_test_setup();

	// DEPLOYMENT_MANIFEST = initial deployment
	agent_register_payload(DEPLOYMENT_MANIFEST, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_DEPLOYMENT_MANIFEST);
	agent_register_payload(DEPLOYMENT_MANIFEST, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_DEPLOYMENT_MANIFEST);

	// STP_RESPONSE = response for EVP request  used in
	// blob_evp_ext_put_file
	agent_register_payload(STP_RESPONSE, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_STP_RESPONSE);
	agent_register_payload(STP_RESPONSE, EVP_HUB_TYPE_EVP2_TB,
			       TB_STP_RESPONSE);

	return 0;
}

int
suite_setup(void **state)
{
	struct context *ctxt = *state = malloc(sizeof(*ctxt));

	ctxt->reqid_offset = 0;

	xasprintf(&ctxt->put_file, "%s/%s/boofar.bin",
		  path_get(MODULE_INSTANCE_PATH_ID), TEST_MODULE_INSTANCE_ID1);
	xasprintf(&ctxt->get_file, "%s/%s/boofar.txt",
		  path_get(MODULE_INSTANCE_PATH_ID), TEST_MODULE_INSTANCE_ID1);

	assert_int_equal(websrv_setup(TEST_HTTP_SERVER_PORT), 0);
	assert_int_equal(websrv_add_route(TEST_HTTP_GET_RESOURCE, HTTP_OP_GET,
					  on_get_user_string,
					  "This is a response"),
			 0);
	assert_int_equal(websrv_add_route(TEST_HTTP_PUT_RESOURCE, HTTP_OP_PUT,
					  on_put_default, NULL),
			 0);
	assert_int_equal(websrv_get_port(&ctxt->backend_port), 0);
	struct proxy_cfg proxy_cfg = {
		.backend_port = ctxt->backend_port,
		.frontend_port = TEST_PROXY_FRONTEND_PORT,
	};
	assert_int_equal(proxy_start(&proxy_cfg), 0);
	assert_int_equal(websrv_start(), 0);

	ctxt->frontend_port = proxy_cfg.frontend_port;

	// start agent
	ctxt->agent = agent_test_start();
	assert_non_null(ctxt->agent);

	struct agent_deployment d = {.ctxt = ctxt->agent};

	// create backdoor instance
	ctxt->sdk = evp_agent_add_instance(ctxt->agent, TEST_INSTANCE_ID1);
	assert_non_null(ctxt->sdk);

	// send initial deployment
	agent_ensure_deployment(&d, agent_get_payload(DEPLOYMENT_MANIFEST),
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
	free(ctxt->put_file);
	free(ctxt->get_file);
	free(ctxt);

	*state = NULL;

	proxy_stop();
	websrv_stop();
	websrv_teardown();

	return 0;
}

int
setup_test(void **state)
{
	struct context *ctxt = *state;
	g_network_ssl_timeout_error = false;

	// Allocate request id to get the current value.
	// Next agent used request will be +1
	// Add offset of reqid due to suite setup requests
	EVP_RPC_ID reqid = request_id_alloc() + 1 + ctxt->reqid_offset;
	// Clear requid_offset at first setup
	ctxt->reqid_offset = 0;

	xasprintf(&ctxt->reqid, "%lu", reqid);
	return 0;
}

int
setup_test_ssl_timeout_ok(void **state)
{
	g_network_ssl_timeout_error = false;
	return 0;
}

int
setup_test_ssl_timeout_error(void **state)
{
	g_network_ssl_timeout_error = true;
	return 0;
}

int
setup_teardown(void **state)
{
	struct context *ctxt = *state;
	free(ctxt->reqid);
	return 0;
}

static uint32_t
wasm_init_local_store(struct context *ctxt, struct EVP_BlobLocalStore *store,
		      uint32_t cb)
{
	struct EVP_BlobLocalStore_wasm *wasm_obj;
	uint32_t offset = wasm_runtime_module_malloc(
		ctxt->wasm_module_inst, sizeof(*wasm_obj), (void **)&wasm_obj);
	if (store->filename) {
		wasm_obj->filename = evp_wasm_string_create(
			ctxt->wasm_module_inst, store->filename);
	} else {
		wasm_obj->filename = 0;
	}
	wasm_obj->io_cb = cb;
	wasm_obj->blob_len = store->blob_len;

	return offset;
}

static uint32_t
wasm_init_blob_request(struct context *ctxt, void *blob_request,
		       EVP_BLOB_TYPE blob_type)
{

	uint32_t offset = 0;
	switch (blob_type) {
	case EVP_BLOB_TYPE_HTTP:
	case EVP_BLOB_TYPE_AZURE_BLOB:
		{
			struct EVP_BlobRequestHttp *request = blob_request;
			struct EVP_BlobRequestHttp_wasm *wasm_obj;
			offset = wasm_runtime_module_malloc(
				ctxt->wasm_module_inst, sizeof(*wasm_obj),
				(void **)&wasm_obj);

			wasm_obj->url = evp_wasm_string_create(
				ctxt->wasm_module_inst, request->url);

			break;
		}
	case EVP_BLOB_TYPE_EVP_EXT:
		{
			struct EVP_BlobRequestEvpExt *request = blob_request;
			struct EVP_BlobRequestEvpExt_wasm *wasm_obj;
			offset = wasm_runtime_module_malloc(
				ctxt->wasm_module_inst, sizeof(*wasm_obj),
				(void **)&wasm_obj);

			wasm_obj->remote_name = evp_wasm_string_create(
				ctxt->wasm_module_inst, request->remote_name);
			wasm_obj->storage_name = evp_wasm_string_create(
				ctxt->wasm_module_inst, request->storage_name);

			break;
		}
	case EVP_BLOB_TYPE_HTTP_EXT:
		{
			offset = EVP_BlobRequestHttpExt_initialize_wasm(
				ctxt->wasm_exec_env);
			break;
		}
	default:
		xlog_error("Blob type %d still not supported", blob_type);
		assert_true(false);
	}

	return offset;
}

static void
wasm_deinit_blob_request(struct context *ctxt, uint32_t offset,
			 EVP_BLOB_TYPE blob_type)
{

	switch (blob_type) {
	case EVP_BLOB_TYPE_HTTP:
	case EVP_BLOB_TYPE_AZURE_BLOB:
		{
			struct EVP_BlobRequestHttp_wasm *wasm_obj =
				wasm_runtime_addr_app_to_native(
					ctxt->wasm_module_inst, offset);
			wasm_runtime_module_free(ctxt->wasm_module_inst,
						 wasm_obj->url);
			break;
		}

	case EVP_BLOB_TYPE_EVP_EXT:
		{
			struct EVP_BlobRequestEvpExt_wasm *wasm_obj =
				wasm_runtime_addr_app_to_native(
					ctxt->wasm_module_inst, offset);
			wasm_runtime_module_free(ctxt->wasm_module_inst,
						 wasm_obj->remote_name);
			wasm_runtime_module_free(ctxt->wasm_module_inst,
						 wasm_obj->storage_name);
			break;
		}
	case EVP_BLOB_TYPE_HTTP_EXT:
		{
			EVP_BlobRequestHttpExt_free_wasm(ctxt->wasm_exec_env,
							 offset);
			break;
		}

	default:
		xlog_error("Blob type %d still not supported", blob_type);
		assert_true(false);
	}

	wasm_runtime_module_free(ctxt->wasm_module_inst, offset);
}

static void
wasm_deinit_local_store(struct context *ctxt, uint32_t offset)
{
	struct EVP_BlobLocalStore_wasm *wasm_obj =
		wasm_runtime_addr_app_to_native(ctxt->wasm_module_inst,
						offset);
	wasm_runtime_module_free(ctxt->wasm_module_inst, wasm_obj->filename);
	wasm_runtime_module_free(ctxt->wasm_module_inst, offset);
}

void
blob_http_get_memory(void **state)
{
	struct context *ctxt = *state;

	EVP_RESULT result;
	char *url;
	xasprintf(&url, TEST_HTTP_GET_URL_FMT, ctxt->frontend_port);
	struct EVP_BlobRequestHttp request = {url};
	struct EVP_BlobLocalStore local_store = {0};

	uint32_t wasm_request =
		wasm_init_blob_request(ctxt, &request, EVP_BLOB_TYPE_HTTP);
	uint32_t wasm_store = wasm_init_local_store(
		ctxt, &local_store, TEST_BLOB_HTTP_GET_IO_CALLBACK_INDEX);

	result = EVP_blobOperation_wasm(
		ctxt->wasm_exec_env, ctxt->wasm_handle, EVP_BLOB_TYPE_HTTP,
		EVP_BLOB_OP_GET, wasm_request, wasm_store,
		TEST_BLOB_HTTP_CALLBACK_INDEX, MAGIC_USERDATA);
	free(url);
	assert_int_equal(result, EVP_OK);
	// Blob download to memory is allowed

	expect_value(blob_get_io_cb, userData, MAGIC_USERDATA);
	result = EVP_processEvent_wasm(ctxt->wasm_exec_env, ctxt->wasm_handle,
				       TEST_DEFAULT_EVENT_TIMEOUT);
	assert_int_equal(result, EVP_OK);

	// Expect processed blob to succeed
	expect_value(blob_cb, reason, EVP_BLOB_CALLBACK_REASON_DONE);
	expect_value(blob_cb, result->result, EVP_BLOB_RESULT_SUCCESS);
	expect_value(blob_cb, result->http_status, 200);
	expect_value(blob_cb, result->error, 0);
	expect_value(blob_cb, userData, MAGIC_USERDATA);
	result = EVP_processEvent_wasm(ctxt->wasm_exec_env, ctxt->wasm_handle,
				       TEST_DEFAULT_EVENT_TIMEOUT);

	// Free app allocated objects
	wasm_deinit_blob_request(ctxt, wasm_request, EVP_BLOB_TYPE_HTTP);
	wasm_deinit_local_store(ctxt, wasm_store);
}

void
blob_http_put_memory(void **state)
{
	xlog_info("GOOD CASE: Blob PUT operations from memory are supported "
		  "(Note: for wasm 0 bytes)");

	struct context *ctxt = *state;

	EVP_RESULT result;
	char *url;
	xasprintf(&url, TEST_HTTP_PUT_URL_FMT, ctxt->frontend_port);
	struct EVP_BlobRequestHttp request = {url};
	static struct EVP_BlobLocalStore local_store;
	local_store.io_cb = 0;
	local_store.blob_len = 16;
	local_store.filename = NULL;
	uint32_t wasm_request =
		wasm_init_blob_request(ctxt, &request, EVP_BLOB_TYPE_HTTP);
	uint32_t wasm_store = wasm_init_local_store(
		ctxt, &local_store, TEST_BLOB_HTTP_PUT_IO_CALLBACK_INDEX);

	result = EVP_blobOperation_wasm(
		ctxt->wasm_exec_env, ctxt->wasm_handle, EVP_BLOB_TYPE_HTTP,
		EVP_BLOB_OP_PUT, wasm_request, wasm_store,
		TEST_BLOB_HTTP_CALLBACK_INDEX, MAGIC_USERDATA);
	free(url);
	assert_int_equal(result, EVP_OK);

	expect_value(blob_put_io_cb, userData, MAGIC_USERDATA);
	result = EVP_processEvent_wasm(ctxt->wasm_exec_env, ctxt->wasm_handle,
				       TEST_DEFAULT_EVENT_TIMEOUT);
	assert_int_equal(result, EVP_OK);

	// Expect processed blob to succeed
	expect_value(blob_cb, reason, EVP_BLOB_CALLBACK_REASON_DONE);
	expect_value(blob_cb, result->result, EVP_BLOB_RESULT_SUCCESS);
	expect_value(blob_cb, result->http_status, 200);
	expect_value(blob_cb, result->error, 0);
	expect_value(blob_cb, userData, MAGIC_USERDATA);
	result = EVP_processEvent_wasm(ctxt->wasm_exec_env, ctxt->wasm_handle,
				       TEST_DEFAULT_EVENT_TIMEOUT);
	assert_int_equal(result, EVP_OK);

	// Free app allocated objects
	wasm_deinit_blob_request(ctxt, wasm_request, EVP_BLOB_TYPE_HTTP);
	wasm_deinit_local_store(ctxt, wasm_store);
}

void
blob_http_get_file(void **state)
{
	struct context *ctxt = *state;

	EVP_RESULT result;
	char *url;
	xasprintf(&url, TEST_HTTP_GET_URL_FMT, ctxt->frontend_port);
	struct EVP_BlobRequestHttp request = {url};
	static struct EVP_BlobLocalStore local_store;
	local_store.io_cb = 0;
	local_store.blob_len = 0;
	local_store.filename = ctxt->get_file;

	uint32_t wasm_request =
		wasm_init_blob_request(ctxt, &request, EVP_BLOB_TYPE_HTTP);
	uint32_t wasm_store = wasm_init_local_store(ctxt, &local_store, 0);

	result = EVP_blobOperation_wasm(
		ctxt->wasm_exec_env, ctxt->wasm_handle, EVP_BLOB_TYPE_HTTP,
		EVP_BLOB_OP_GET, wasm_request, wasm_store,
		TEST_BLOB_HTTP_CALLBACK_INDEX, MAGIC_USERDATA);
	free(url);
	assert_int_equal(result, EVP_OK);

	// Expect processed blob to succeed
	expect_value(blob_cb, reason, EVP_BLOB_CALLBACK_REASON_DONE);
	expect_value(blob_cb, result->result, EVP_BLOB_RESULT_SUCCESS);
	expect_value(blob_cb, result->http_status, 200);
	expect_value(blob_cb, result->error, 0);
	expect_value(blob_cb, userData, MAGIC_USERDATA);
	result = EVP_processEvent_wasm(ctxt->wasm_exec_env, ctxt->wasm_handle,
				       TEST_DEFAULT_EVENT_TIMEOUT);
	assert_int_equal(result, EVP_OK);

	// Free app allocated objects
	wasm_deinit_blob_request(ctxt, wasm_request, EVP_BLOB_TYPE_HTTP);
	wasm_deinit_local_store(ctxt, wasm_store);
}

void
blob_http_put_file(void **state)
{
	struct context *ctxt = *state;

	EVP_RESULT result;
	char *url;
	xasprintf(&url, TEST_HTTP_PUT_URL_FMT, ctxt->frontend_port);
	struct EVP_BlobRequestHttp request = {url};
	static struct EVP_BlobLocalStore local_store;
	local_store.io_cb = 0;
	local_store.blob_len = 16;
	local_store.filename = ctxt->put_file;

	// Create file to put
	assert_int_equal(0, systemf("mkdir -p `dirname %s`", ctxt->put_file));
	assert_int_equal(
		0, systemf("echo 'Some content file' > %s", ctxt->put_file));

	uint32_t wasm_request =
		wasm_init_blob_request(ctxt, &request, EVP_BLOB_TYPE_HTTP);
	uint32_t wasm_store = wasm_init_local_store(ctxt, &local_store, 0);

	result = EVP_blobOperation_wasm(
		ctxt->wasm_exec_env, ctxt->wasm_handle, EVP_BLOB_TYPE_HTTP,
		EVP_BLOB_OP_PUT, wasm_request, wasm_store,
		TEST_BLOB_HTTP_CALLBACK_INDEX, MAGIC_USERDATA);
	free(url);
	assert_int_equal(result, EVP_OK);

	// Expect processed blob to succeed
	expect_value(blob_cb, reason, EVP_BLOB_CALLBACK_REASON_DONE);
	expect_value(blob_cb, result->result, EVP_BLOB_RESULT_SUCCESS);
	expect_value(blob_cb, result->http_status, 200);
	expect_value(blob_cb, result->error, 0);
	expect_value(blob_cb, userData, MAGIC_USERDATA);
	result = EVP_processEvent_wasm(ctxt->wasm_exec_env, ctxt->wasm_handle,
				       TEST_DEFAULT_EVENT_TIMEOUT);
	assert_int_equal(result, EVP_OK);

	// Free app allocated objects
	wasm_deinit_blob_request(ctxt, wasm_request, EVP_BLOB_TYPE_HTTP);
	wasm_deinit_local_store(ctxt, wasm_store);
}

void
blob_http_ext_get_memory(void **state)
{
	struct context *ctxt = *state;

	EVP_RESULT result;
	struct EVP_BlobLocalStore local_store = {0};

	uint32_t wasm_request =
		wasm_init_blob_request(ctxt, NULL, EVP_BLOB_TYPE_HTTP_EXT);

	char *url;
	xasprintf(&url, TEST_AZURE_GET_SAS_FMT, ctxt->frontend_port);
	uint32_t url_addr =
		evp_wasm_string_create(ctxt->wasm_module_inst, url);
	EVP_BlobRequestHttpExt_setUrl_wasm(ctxt->wasm_exec_env, wasm_request,
					   url_addr);
	wasm_runtime_module_free(ctxt->wasm_module_inst, url_addr);
	uint32_t wasm_store = wasm_init_local_store(
		ctxt, &local_store, TEST_BLOB_HTTP_GET_IO_CALLBACK_INDEX);

	result = EVP_blobOperation_wasm(
		ctxt->wasm_exec_env, ctxt->wasm_handle, EVP_BLOB_TYPE_HTTP_EXT,
		EVP_BLOB_OP_GET, wasm_request, wasm_store,
		TEST_BLOB_HTTP_CALLBACK_INDEX, MAGIC_USERDATA);
	free(url);
	assert_int_equal(result, EVP_OK);
	// Blob download to memory is allowed

	expect_value(blob_get_io_cb, userData, MAGIC_USERDATA);
	result = EVP_processEvent_wasm(ctxt->wasm_exec_env, ctxt->wasm_handle,
				       TEST_DEFAULT_EVENT_TIMEOUT);
	assert_int_equal(result, EVP_OK);

	// Expect processed blob to succeed
	expect_value(blob_cb, reason, EVP_BLOB_CALLBACK_REASON_DONE);
	expect_value(blob_cb, result->result, EVP_BLOB_RESULT_SUCCESS);
	expect_value(blob_cb, result->http_status, 200);
	expect_value(blob_cb, result->error, 0);
	expect_value(blob_cb, userData, MAGIC_USERDATA);
	result = EVP_processEvent_wasm(ctxt->wasm_exec_env, ctxt->wasm_handle,
				       TEST_DEFAULT_EVENT_TIMEOUT);
	assert_int_equal(result, EVP_OK);

	// Free app allocated objects
	wasm_deinit_blob_request(ctxt, wasm_request, EVP_BLOB_TYPE_HTTP_EXT);
	wasm_deinit_local_store(ctxt, wasm_store);
}

void
blob_http_ext_put_memory(void **state)
{
	xlog_info("GOOD CASE: Blob PUT operations from memory are supported "
		  "(Note: for wasm 0 bytes)");

	struct context *ctxt = *state;

	EVP_RESULT result;
	static struct EVP_BlobLocalStore local_store;
	local_store.io_cb = 0;
	local_store.blob_len = 16;
	local_store.filename = NULL;

	uint32_t wasm_request =
		wasm_init_blob_request(ctxt, NULL, EVP_BLOB_TYPE_HTTP_EXT);
	char *url;
	xasprintf(&url, TEST_AZURE_PUT_SAS_FMT, ctxt->frontend_port);
	uint32_t url_addr =
		evp_wasm_string_create(ctxt->wasm_module_inst, url);
	EVP_BlobRequestHttpExt_setUrl_wasm(ctxt->wasm_exec_env, wasm_request,
					   url_addr);
	wasm_runtime_module_free(ctxt->wasm_module_inst, url_addr);
	uint32_t wasm_store = wasm_init_local_store(
		ctxt, &local_store, TEST_BLOB_HTTP_PUT_IO_CALLBACK_INDEX);

	result = EVP_blobOperation_wasm(
		ctxt->wasm_exec_env, ctxt->wasm_handle, EVP_BLOB_TYPE_HTTP_EXT,
		EVP_BLOB_OP_PUT, wasm_request, wasm_store,
		TEST_BLOB_HTTP_CALLBACK_INDEX, MAGIC_USERDATA);
	free(url);
	assert_int_equal(result, EVP_OK);

	expect_value(blob_put_io_cb, userData, MAGIC_USERDATA);
	result = EVP_processEvent_wasm(ctxt->wasm_exec_env, ctxt->wasm_handle,
				       TEST_DEFAULT_EVENT_TIMEOUT);
	assert_int_equal(result, EVP_OK);

	// Expect processed blob to succeed
	expect_value(blob_cb, reason, EVP_BLOB_CALLBACK_REASON_DONE);
	expect_value(blob_cb, result->result, EVP_BLOB_RESULT_SUCCESS);
	expect_value(blob_cb, result->http_status, 200);
	expect_value(blob_cb, result->error, 0);
	expect_value(blob_cb, userData, MAGIC_USERDATA);
	result = EVP_processEvent_wasm(ctxt->wasm_exec_env, ctxt->wasm_handle,
				       TEST_DEFAULT_EVENT_TIMEOUT);
	assert_int_equal(result, EVP_OK);

	// Free app allocated objects
	wasm_deinit_blob_request(ctxt, wasm_request, EVP_BLOB_TYPE_HTTP_EXT);
	wasm_deinit_local_store(ctxt, wasm_store);
}

void
blob_http_ext_get_file(void **state)
{
	struct context *ctxt = *state;

	EVP_RESULT result;
	static struct EVP_BlobLocalStore local_store;
	local_store.io_cb = 0;
	local_store.blob_len = 0;
	local_store.filename = ctxt->get_file;

	char *url;
	xasprintf(&url, TEST_AZURE_GET_SAS_FMT, ctxt->frontend_port);
	uint32_t wasm_request =
		wasm_init_blob_request(ctxt, NULL, EVP_BLOB_TYPE_HTTP_EXT);
	uint32_t url_addr =
		evp_wasm_string_create(ctxt->wasm_module_inst, url);
	EVP_BlobRequestHttpExt_setUrl_wasm(ctxt->wasm_exec_env, wasm_request,
					   url_addr);
	wasm_runtime_module_free(ctxt->wasm_module_inst, url_addr);
	uint32_t wasm_store = wasm_init_local_store(ctxt, &local_store, 0);

	result = EVP_blobOperation_wasm(
		ctxt->wasm_exec_env, ctxt->wasm_handle, EVP_BLOB_TYPE_HTTP_EXT,
		EVP_BLOB_OP_GET, wasm_request, wasm_store,
		TEST_BLOB_HTTP_CALLBACK_INDEX, MAGIC_USERDATA);
	free(url);
	assert_int_equal(result, EVP_OK);

	// Expect processed blob to succeed
	expect_value(blob_cb, reason, EVP_BLOB_CALLBACK_REASON_DONE);
	expect_value(blob_cb, result->result, EVP_BLOB_RESULT_SUCCESS);
	expect_value(blob_cb, result->http_status, 200);
	expect_value(blob_cb, result->error, 0);
	expect_value(blob_cb, userData, MAGIC_USERDATA);
	result = EVP_processEvent_wasm(ctxt->wasm_exec_env, ctxt->wasm_handle,
				       TEST_DEFAULT_EVENT_TIMEOUT);
	assert_int_equal(result, EVP_OK);

	// Free app allocated objects
	wasm_deinit_blob_request(ctxt, wasm_request, EVP_BLOB_TYPE_HTTP_EXT);
	wasm_deinit_local_store(ctxt, wasm_store);
}

void
blob_http_ext_put_file(void **state)
{
	struct context *ctxt = *state;

	EVP_RESULT result;
	static struct EVP_BlobLocalStore local_store;
	local_store.io_cb = 0;
	local_store.blob_len = 0;
	local_store.filename = ctxt->put_file;

	// Create file to put
	assert_int_equal(0, systemf("mkdir -p `dirname %s`", ctxt->put_file));
	assert_int_equal(
		0, systemf("echo 'Some content file' > %s", ctxt->put_file));

	char *url;
	xasprintf(&url, TEST_AZURE_PUT_SAS_FMT, ctxt->frontend_port);
	uint32_t wasm_request =
		wasm_init_blob_request(ctxt, NULL, EVP_BLOB_TYPE_HTTP_EXT);
	uint32_t url_addr =
		evp_wasm_string_create(ctxt->wasm_module_inst, url);
	EVP_BlobRequestHttpExt_setUrl_wasm(ctxt->wasm_exec_env, wasm_request,
					   url_addr);
	wasm_runtime_module_free(ctxt->wasm_module_inst, url_addr);
	uint32_t wasm_store = wasm_init_local_store(ctxt, &local_store, 0);

	result = EVP_blobOperation_wasm(
		ctxt->wasm_exec_env, ctxt->wasm_handle, EVP_BLOB_TYPE_HTTP_EXT,
		EVP_BLOB_OP_PUT, wasm_request, wasm_store,
		TEST_BLOB_HTTP_CALLBACK_INDEX, MAGIC_USERDATA);
	free(url);
	assert_int_equal(result, EVP_OK);

	// Expect processed blob to succeed
	expect_value(blob_cb, reason, EVP_BLOB_CALLBACK_REASON_DONE);
	expect_value(blob_cb, result->result, EVP_BLOB_RESULT_SUCCESS);
	expect_value(blob_cb, result->http_status, 200);
	expect_value(blob_cb, result->error, 0);
	expect_value(blob_cb, userData, MAGIC_USERDATA);
	result = EVP_processEvent_wasm(ctxt->wasm_exec_env, ctxt->wasm_handle,
				       TEST_DEFAULT_EVENT_TIMEOUT);
	assert_int_equal(result, EVP_OK);

	// Free app allocated objects
	wasm_deinit_blob_request(ctxt, wasm_request, EVP_BLOB_TYPE_HTTP_EXT);
	wasm_deinit_local_store(ctxt, wasm_store);
}

void
blob_evp_ext_put_file(void **state)
{
	struct context *ctxt = *state;

	EVP_RESULT result;
	struct EVP_BlobRequestEvpExt request;
	static struct EVP_BlobLocalStore local_store;
	local_store.io_cb = 0;
	local_store.blob_len = 0;
	local_store.filename = ctxt->put_file;
	request.remote_name = TEST_EVP_PUT_REMOTE_NAME;
	request.storage_name = TEST_EVP_PUT_STORAGE_NAME;

	// Create file to put
	assert_int_equal(0, systemf("mkdir -p `dirname %s`", ctxt->put_file));
	assert_int_equal(0,
			 systemf("echo 'file content' > %s", ctxt->put_file));

	uint32_t wasm_request =
		wasm_init_blob_request(ctxt, &request, EVP_BLOB_TYPE_EVP_EXT);
	uint32_t wasm_store = wasm_init_local_store(ctxt, &local_store, 0);

	result = EVP_blobOperation_wasm(
		ctxt->wasm_exec_env, ctxt->wasm_handle, EVP_BLOB_TYPE_EVP_EXT,
		EVP_BLOB_OP_PUT, wasm_request, wasm_store,
		TEST_BLOB_HTTP_CALLBACK_INDEX, MAGIC_USERDATA);
	assert_int_equal(result, EVP_OK);

	// At this point the agent sends a StorageToken request, check it
	static struct multi_check test_set_device_state1[] = {
		{.value = TEST_EVP_PUT_REMOTE_NAME},
		{.value = TEST_EVP_PUT_STORAGE_NAME},
		{.value = NULL}, // List termination
	};
	agent_poll(verify_contains_in_unordered_set, test_set_device_state1);

	// Send the RPC reponse (as HUB does)
	char *payload;
	payload = agent_get_payload_formatted(
		STP_RESPONSE, ctxt->frontend_port, ctxt->reqid);
	agent_send_storagetoken_response(ctxt->agent, payload, ctxt->reqid);
	free(payload);

	// Now the agent will do the blob operation

	char *put_check;
	xasprintf(&put_check, "PUT " TEST_AZURE_PUT_SAS_FMT,
		  ctxt->frontend_port);
	agent_poll(verify_equals, put_check);
	free(put_check);

	// Expect processed blob to succeed
	expect_value(blob_cb, reason, EVP_BLOB_CALLBACK_REASON_DONE);
	expect_value(blob_cb, result->result, EVP_BLOB_RESULT_SUCCESS);
	expect_value(blob_cb, result->http_status, 200);
	expect_value(blob_cb, result->error, 0);
	expect_value(blob_cb, userData, MAGIC_USERDATA);
	result = EVP_processEvent_wasm(ctxt->wasm_exec_env, ctxt->wasm_handle,
				       TEST_DEFAULT_EVENT_TIMEOUT);
	assert_int_equal(result, EVP_OK);

	// Free app allocated objects
	wasm_deinit_blob_request(ctxt, wasm_request, EVP_BLOB_TYPE_EVP_EXT);
	wasm_deinit_local_store(ctxt, wasm_store);
}

void
blob_evp_ext_default_put_file(void **state)
{

	xlog_info("GOOD CASE: if the storage_name is null the storage_name "
		  "field is not sent");

	struct context *ctxt = *state;

	EVP_RESULT result;
	static struct EVP_BlobRequestEvpExt request;
	static struct EVP_BlobLocalStore local_store;
	local_store.io_cb = 0;
	local_store.blob_len = 0;
	local_store.filename = ctxt->put_file;
	request.remote_name = TEST_EVP_PUT_REMOTE_NAME;
	request.storage_name = NULL;

	// Create file to put
	assert_int_equal(0, systemf("mkdir -p `dirname %s`", ctxt->put_file));
	assert_int_equal(0,
			 systemf("echo 'file content' > %s", ctxt->put_file));

	uint32_t wasm_request =
		wasm_init_blob_request(ctxt, &request, EVP_BLOB_TYPE_EVP_EXT);
	uint32_t wasm_store = wasm_init_local_store(ctxt, &local_store, 0);

	result = EVP_blobOperation_wasm(
		ctxt->wasm_exec_env, ctxt->wasm_handle, EVP_BLOB_TYPE_EVP_EXT,
		EVP_BLOB_OP_PUT, wasm_request, wasm_store,
		TEST_BLOB_HTTP_CALLBACK_INDEX, MAGIC_USERDATA);
	assert_int_equal(result, EVP_OK);

	// At this point the agent sends a StorageToken request WITHOUT
	// storage_name, check it
	expect_unexpect_t val = {.expect = TEST_EVP_PUT_REMOTE_NAME,
				 .unexpect = "storage_name"};
	agent_poll(verify_contains_except, &val);

	// Send the RPC response (as HUB does)
	char *payload;
	payload = agent_get_payload_formatted(
		STP_RESPONSE, ctxt->frontend_port, ctxt->reqid);
	agent_send_storagetoken_response(ctxt->agent, payload, ctxt->reqid);
	free(payload);

	// Now the agent will dot he blob operation
	char *put_check;
	xasprintf(&put_check, "PUT " TEST_AZURE_PUT_SAS_FMT,
		  ctxt->frontend_port);
	agent_poll(verify_equals, put_check);
	free(put_check);

	// Expect processed blob to succeed
	expect_value(blob_cb, reason, EVP_BLOB_CALLBACK_REASON_DONE);
	expect_value(blob_cb, result->result, EVP_BLOB_RESULT_SUCCESS);
	expect_value(blob_cb, result->http_status, 200);
	expect_value(blob_cb, result->error, 0);
	expect_value(blob_cb, userData, MAGIC_USERDATA);
	result = EVP_processEvent_wasm(ctxt->wasm_exec_env, ctxt->wasm_handle,
				       TEST_DEFAULT_EVENT_TIMEOUT);
	assert_int_equal(result, EVP_OK);

	// Free app allocated objects
	wasm_deinit_blob_request(ctxt, wasm_request, EVP_BLOB_TYPE_EVP_EXT);
	wasm_deinit_local_store(ctxt, wasm_store);
}

void
blob_evp_ext_get_file(void **state)
{
	xlog_info("BAD CASE: be sure that EVP_BLOB_EXT GET operation is not "
		  "supported and error is returned.");
	struct context *ctxt = *state;

	EVP_RESULT result;
	static struct EVP_BlobRequestEvpExt request;
	static struct EVP_BlobLocalStore local_store;
	local_store.io_cb = 0;
	local_store.blob_len = 0;
	local_store.filename = ctxt->get_file;
	request.remote_name = TEST_EVP_PUT_REMOTE_NAME;
	request.storage_name = TEST_EVP_PUT_REMOTE_NAME;

	uint32_t wasm_request =
		wasm_init_blob_request(ctxt, &request, EVP_BLOB_TYPE_EVP_EXT);
	uint32_t wasm_store = wasm_init_local_store(ctxt, &local_store, 0);

	result = EVP_blobOperation_wasm(
		ctxt->wasm_exec_env, ctxt->wasm_handle, EVP_BLOB_TYPE_EVP_EXT,
		EVP_BLOB_OP_GET, wasm_request, wasm_store,
		TEST_BLOB_HTTP_CALLBACK_INDEX, MAGIC_USERDATA);
	assert_int_equal(result, EVP_NOTSUP);

	// Free app allocated objects
	wasm_deinit_blob_request(ctxt, wasm_request, EVP_BLOB_TYPE_EVP_EXT);
	wasm_deinit_local_store(ctxt, wasm_store);
}

void
blob_azure_put_file(void **state)
{
	struct context *ctxt = *state;

	EVP_RESULT result;
	static struct EVP_BlobRequestAzureBlob request;
	static struct EVP_BlobLocalStore local_store;
	local_store.io_cb = 0;
	local_store.blob_len = 0;
	local_store.filename = ctxt->put_file;

	char *url;
	xasprintf(&url, TEST_AZURE_PUT_SAS_FMT, ctxt->frontend_port);
	request.url = url;

	// Create file to put
	assert_int_equal(0, systemf("mkdir -p `dirname %s`", ctxt->put_file));
	assert_int_equal(0,
			 systemf("echo 'file content' > %s", ctxt->put_file));

	uint32_t wasm_request = wasm_init_blob_request(
		ctxt, &request, EVP_BLOB_TYPE_AZURE_BLOB);
	uint32_t wasm_store = wasm_init_local_store(ctxt, &local_store, 0);

	result = EVP_blobOperation_wasm(
		ctxt->wasm_exec_env, ctxt->wasm_handle,
		EVP_BLOB_TYPE_AZURE_BLOB, EVP_BLOB_OP_PUT, wasm_request,
		wasm_store, TEST_BLOB_HTTP_CALLBACK_INDEX, MAGIC_USERDATA);
	free(url);
	assert_int_equal(result, EVP_OK);

	// Expect processed blob to succeed
	expect_value(blob_cb, reason, EVP_BLOB_CALLBACK_REASON_DONE);
	expect_value(blob_cb, result->result, EVP_BLOB_RESULT_SUCCESS);
	expect_value(blob_cb, result->http_status, 200);
	expect_value(blob_cb, result->error, 0);
	expect_value(blob_cb, userData, MAGIC_USERDATA);
	result = EVP_processEvent_wasm(ctxt->wasm_exec_env, ctxt->wasm_handle,
				       TEST_DEFAULT_EVENT_TIMEOUT);
	assert_int_equal(result, EVP_OK);

	// Free app allocated objects
	wasm_deinit_blob_request(ctxt, wasm_request, EVP_BLOB_TYPE_AZURE_BLOB);
	wasm_deinit_local_store(ctxt, wasm_store);
}

void
blob_azure_get_file(void **state)
{
	struct context *ctxt = *state;

	EVP_RESULT result;
	static struct EVP_BlobRequestAzureBlob request;
	static struct EVP_BlobLocalStore local_store;
	local_store.io_cb = 0;
	local_store.blob_len = 0;
	local_store.filename = ctxt->get_file;

	char *url;
	xasprintf(&url, TEST_AZURE_GET_SAS_FMT, ctxt->frontend_port);
	request.url = url;

	uint32_t wasm_request = wasm_init_blob_request(
		ctxt, &request, EVP_BLOB_TYPE_AZURE_BLOB);
	uint32_t wasm_store = wasm_init_local_store(ctxt, &local_store, 0);

	result = EVP_blobOperation_wasm(
		ctxt->wasm_exec_env, ctxt->wasm_handle,
		EVP_BLOB_TYPE_AZURE_BLOB, EVP_BLOB_OP_GET, wasm_request,
		wasm_store, TEST_BLOB_HTTP_CALLBACK_INDEX, MAGIC_USERDATA);
	free(url);
	assert_int_equal(result, EVP_OK);

	// Expect processed blob to succeed
	expect_value(blob_cb, reason, EVP_BLOB_CALLBACK_REASON_DONE);
	expect_value(blob_cb, result->result, EVP_BLOB_RESULT_SUCCESS);
	expect_value(blob_cb, result->http_status, 200);
	expect_value(blob_cb, result->error, 0);
	expect_value(blob_cb, userData, MAGIC_USERDATA);
	result = EVP_processEvent_wasm(ctxt->wasm_exec_env, ctxt->wasm_handle,
				       TEST_DEFAULT_EVENT_TIMEOUT);
	assert_int_equal(result, EVP_OK);

	// Free app allocated objects
	wasm_deinit_blob_request(ctxt, wasm_request, EVP_BLOB_TYPE_AZURE_BLOB);
	wasm_deinit_local_store(ctxt, wasm_store);
}

int __real_mbedtls_ssl_write(mbedtls_ssl_context *ssl,
			     const unsigned char *buf, size_t len);

int
__wrap_mbedtls_ssl_write(mbedtls_ssl_context *ssl, const unsigned char *buf,
			 size_t len)
{

	if (g_network_ssl_timeout_error) {

		return MBEDTLS_ERR_SSL_TIMEOUT;
	} else {
		return __real_mbedtls_ssl_write(ssl, buf, len);
	}
}

static int
on_network_error(const void *args, void *user_data)
{
	const char *error = args;

	char *txt;
	xasprintf(&txt, "%s/%s", __func__, error);

	agent_write_to_pipe(txt);
	free(txt);
	return 0;
}

void
network_ssl_timeout(void **state)
{
	struct context *ctxt = *state;

	assert_int_equal(
		evp_agent_notification_subscribe(ctxt->agent, "network/error",
						 on_network_error, NULL),
		0);

	EVP_RESULT result;
	static struct EVP_BlobRequestAzureBlob request;
	static struct EVP_BlobLocalStore local_store;
	local_store.io_cb = 0;
	local_store.blob_len = 0;
	local_store.filename = ctxt->get_file;

	char *url;
	xasprintf(&url, TEST_AZURE_GET_SAS_FMT, ctxt->frontend_port);
	request.url = url;

	uint32_t wasm_request = wasm_init_blob_request(
		ctxt, &request, EVP_BLOB_TYPE_AZURE_BLOB);
	uint32_t wasm_store = wasm_init_local_store(ctxt, &local_store, 0);

	result = EVP_blobOperation_wasm(
		ctxt->wasm_exec_env, ctxt->wasm_handle,
		EVP_BLOB_TYPE_AZURE_BLOB, EVP_BLOB_OP_GET, wasm_request,
		wasm_store, TEST_BLOB_HTTP_CALLBACK_INDEX, MAGIC_USERDATA);
	free(url);
	assert_int_equal(result, EVP_OK);

	// Expect processed blob to succeed
	expect_value(blob_cb, reason, EVP_BLOB_CALLBACK_REASON_DONE);
	expect_value(blob_cb, result->result, EVP_BLOB_RESULT_ERROR);
	expect_value(blob_cb, result->http_status, 0);
	expect_value(blob_cb, result->error, 5);
	expect_value(blob_cb, userData, MAGIC_USERDATA);
	result = EVP_processEvent_wasm(ctxt->wasm_exec_env, ctxt->wasm_handle,
				       TEST_DEFAULT_EVENT_TIMEOUT);
	assert_int_equal(result, EVP_OK);

	// Free app allocated objects
	wasm_deinit_blob_request(ctxt, wasm_request, EVP_BLOB_TYPE_AZURE_BLOB);
	wasm_deinit_local_store(ctxt, wasm_store);
}

int
main(void)
{
	session_setup(NULL);

	// define tests
	const struct CMUnitTest blob_http[] = {

		cmocka_unit_test_setup_teardown(blob_evp_ext_put_file,
						setup_test, setup_teardown),
		cmocka_unit_test_setup_teardown(blob_evp_ext_default_put_file,
						setup_test, setup_teardown),

		cmocka_unit_test_setup(blob_http_get_memory,
				       setup_test_ssl_timeout_ok),
		cmocka_unit_test_setup(blob_http_put_memory,
				       setup_test_ssl_timeout_ok),
		cmocka_unit_test_setup(blob_http_get_file,
				       setup_test_ssl_timeout_ok),
		cmocka_unit_test_setup(blob_http_put_file,
				       setup_test_ssl_timeout_ok),
		cmocka_unit_test_setup(blob_azure_put_file,
				       setup_test_ssl_timeout_ok),
		cmocka_unit_test_setup(blob_azure_get_file,
				       setup_test_ssl_timeout_ok),
		cmocka_unit_test_setup(blob_http_ext_get_memory,
				       setup_test_ssl_timeout_ok),
		cmocka_unit_test_setup(blob_http_ext_put_memory,
				       setup_test_ssl_timeout_ok),
		cmocka_unit_test_setup(blob_http_ext_get_file,
				       setup_test_ssl_timeout_ok),
		cmocka_unit_test_setup(blob_http_ext_put_file,
				       setup_test_ssl_timeout_ok),

		// bad cases
		cmocka_unit_test_setup(blob_evp_ext_get_file,
				       setup_test_ssl_timeout_ok),
		cmocka_unit_test_setup(network_ssl_timeout,
				       setup_test_ssl_timeout_error),
	};
	// suite_setup and run tests
	return cmocka_run_group_tests(blob_http, suite_setup, suite_teardown);
}
