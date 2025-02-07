/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <internal/util.h>

#include "agent_test.h"
#include "evp/sdk.h"
#include "hub.h"
#include "sdk_local_wasm.h"
#include "wasm_export.h"
#include "xlog.h"

/* dummy.wat contents:
 * ```
 * (module (memory 1))
 * ```
 * assemble with `wat2wasm` and dump with `xxd -i`
 */
unsigned char dummy_wasm[] = {0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00,
			      0x00, 0x05, 0x03, 0x01, 0x00, 0x01};
unsigned int dummy_wasm_len = 13;

enum test_direct_command_payloads {
	DEPLOYMENT_MANIFEST_1,
	DIRECT_COMMAND_REQ_1,
	DIRECT_COMMAND_PARAMS_1
};

#define TEST_INSTANCE_ID1  "backdoor-mdc"
#define TEST_METHOD_NAME1  "test-method"
#define TEST_RPC_RESPONSE1 "This is the test response, a normal string"
#define RPC_TEST_ID        543210

#define TB_TEST_RPC_REQUEST_PARAMS      "\"{\\\"param1\\\": \\\"input1\\\"}\""
#define EVP2_TB_TEST_RPC_REQUEST_PARAMS "{\"param1\": \"input1\"}"

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

#define EVP1_MDC_REQ_1                                                        \
	"{"                                                                   \
	"        \"method\": \"ModuleMethodCall\","                           \
	"        \"params\": {"                                               \
	"                \"moduleInstance\": "                                \
	"\"" TEST_MODULE_INSTANCE_ID1 "\","                                   \
	"                \"moduleMethod\": \"" TEST_METHOD_NAME1 "\","        \
	"                \"params\": " TB_TEST_RPC_REQUEST_PARAMS "}"         \
	"}"

#define XSTR(x) #x
#define STR(x)  XSTR(x)

#define EVP2_TB_MDC_REQ_1                                                     \
	"{"                                                                   \
	"\"direct-command-request\": {"                                       \
	"\"reqid\": \"" STR(                                                  \
		RPC_TEST_ID) "\","                                            \
			     "\"method\": "                                   \
			     "\"" TEST_METHOD_NAME1 "\","                     \
			     "\"instance\": "                                 \
			     "\"" TEST_MODULE_INSTANCE_ID1 "\","              \
			     ""                                               \
			     "\"params\": " TB_TEST_RPC_REQUEST_PARAMS "}"    \
			     "}"

#define TEST_RPC_REQUEST_CALLBACK_INDEX  0xbeefbeef
#define TEST_RPC_RESPONSE_CALLBACK_INDEX 0xfeedbab3
#define TEST_RPC_CALLBACK_USER_DATA      31337

static void
rpc_request_cb(EVP_RPC_ID id, const char *method, const char *params,
	       void *userData)
{
	check_expected(id);
	check_expected(method);
	check_expected(params);
	check_expected(userData);
}

static void
rpc_response_cb(EVP_RPC_RESPONSE_CALLBACK_REASON reason, void *userData)
{
	check_expected(reason);
	check_expected(userData);
}

bool
__wrap_wasm_runtime_call_indirect(struct WASMExecEnv *exec_env,
				  uint32_t element_indices, uint32_t argc,
				  uint32_t argv[])
{

	switch (element_indices) {
	case TEST_RPC_REQUEST_CALLBACK_INDEX:
		{

			fprintf(stderr, "CALLED REQUEST CALLBACK\n");
			int ret;
			assert_int_equal(argc, 5);

			// module inst
			wasm_module_inst_t module_inst =
				wasm_runtime_get_module_inst(exec_env);

			// method name
			ret = wasm_runtime_validate_app_str_addr(module_inst,
								 argv[2]);
			assert_true(ret);

			const char *method_name =
				wasm_runtime_addr_app_to_native(module_inst,
								argv[2]);

			// params
			ret = wasm_runtime_validate_app_str_addr(module_inst,
								 argv[3]);
			assert_true(ret);

			const char *params = wasm_runtime_addr_app_to_native(
				module_inst, argv[3]);

			uint32_t rpc_id = argv[0];
			uint32_t user_data = argv[4];

			rpc_request_cb(rpc_id, method_name, params,
				       (void *)(uintptr_t)user_data);

			break;
		}
	case TEST_RPC_RESPONSE_CALLBACK_INDEX:

		fprintf(stderr, "CALLED RESPONSE CALLBACK\n");

		assert_int_equal(argc, 2);
		rpc_response_cb(argv[0], (void *)(uintptr_t)argv[1]);
		break;
	default:
		fail_msg("invalid element_index");
	}

	return true;
}

void
test_wasm_mdc(void **state)
{
	/* This should test the the RPC functionality.
	 *
	 * First we register the RPC callback, then we
	 * Make a request, and finally send a response
	 */

	// start agent
	struct evp_agent_context *ctxt = agent_test_start();
	struct agent_deployment d = {.ctxt = ctxt};

	// create backdoor instance
	struct EVP_client *sdk_handle =
		evp_agent_add_instance(ctxt, TEST_INSTANCE_ID1);
	assert_non_null(sdk_handle);

	// send initial deployment
	agent_ensure_deployment(&d, agent_get_payload(DEPLOYMENT_MANIFEST_1),
				TEST_DEPLOYMENT_ID1);

	char error_buf[64];

	// load module
	wasm_module_t wasm_module = wasm_runtime_load(
		dummy_wasm, dummy_wasm_len, error_buf, sizeof(error_buf));

	assert_int_not_equal(wasm_module, 0);

	// start wasm module: create WASM module_instance
	wasm_module_inst_t wasm_module_inst = wasm_runtime_instantiate(
		wasm_module, 8192, 16384, error_buf, sizeof(error_buf));

	wasm_runtime_set_custom_data(wasm_module_inst, sdk_handle);

	// get execution environment
	wasm_exec_env_t wasm_exec_env =
		wasm_runtime_get_exec_env_singleton(wasm_module_inst);

	uint32_t handle_wasm = EVP_initialize_wasm(wasm_exec_env);

	assert_int_equal(handle_wasm, 0x1234);

	EVP_RESULT result = EVP_setRpcCallback_wasm(
		wasm_exec_env, handle_wasm, TEST_RPC_REQUEST_CALLBACK_INDEX,
		TEST_RPC_CALLBACK_USER_DATA);
	assert_int_equal(result, EVP_OK);

	// Send the RPC request
	agent_send_direct_command_req(
		ctxt, agent_get_payload(DIRECT_COMMAND_REQ_1), 543210);

	// verify request callback
	expect_value(rpc_request_cb, id, RPC_TEST_ID);
	expect_string(rpc_request_cb, method, TEST_METHOD_NAME1);
	expect_string(rpc_request_cb, params,
		      agent_get_payload(DIRECT_COMMAND_PARAMS_1));
	expect_value(rpc_request_cb, userData, TEST_RPC_CALLBACK_USER_DATA);

	result = EVP_processEvent_wasm(wasm_exec_env, handle_wasm, 1000);
	assert_int_equal(result, EVP_OK);

	// direct command response
	EVP_RPC_RESPONSE_STATUS status = EVP_RPC_RESPONSE_STATUS_OK;
	result = EVP_sendRpcResponse_wasm(
		wasm_exec_env, handle_wasm, RPC_TEST_ID,
		"\"" TEST_RPC_RESPONSE1 "\"", status,
		TEST_RPC_RESPONSE_CALLBACK_INDEX, TEST_RPC_CALLBACK_USER_DATA);
	assert_int_equal(result, EVP_OK);
	agent_poll(verify_contains, TEST_RPC_RESPONSE1);

	// verify response callback
	expect_value(rpc_response_cb, reason,
		     EVP_RPC_RESPONSE_CALLBACK_REASON_SENT);
	expect_value(rpc_response_cb, userData, TEST_RPC_CALLBACK_USER_DATA);
	result = EVP_processEvent_wasm(wasm_exec_env, handle_wasm, 1000);
	assert_int_equal(result, EVP_OK);

	// cleanup wasm runtime
	wasm_runtime_deinstantiate(wasm_module_inst);
	wasm_runtime_unload(wasm_module);

	// stop module
	evp_agent_stop_instance(ctxt, TEST_MODULE_INSTANCE_ID1);
}

int
setup(void **state)
{
	agent_test_setup();

	// register evp1 payloads
	agent_register_payload(DEPLOYMENT_MANIFEST_1, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_DEPLOYMENT_MANIFEST_1);
	agent_register_payload(DIRECT_COMMAND_REQ_1, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_MDC_REQ_1);
	agent_register_payload(DIRECT_COMMAND_PARAMS_1, EVP_HUB_TYPE_EVP1_TB,
			       TB_TEST_RPC_REQUEST_PARAMS);
	// register TB payloads
	agent_register_payload(DEPLOYMENT_MANIFEST_1, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_DEPLOYMENT_MANIFEST_1);
	agent_register_payload(DIRECT_COMMAND_REQ_1, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_TB_MDC_REQ_1);
	agent_register_payload(DIRECT_COMMAND_PARAMS_1, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_TB_TEST_RPC_REQUEST_PARAMS);
	return 0;
}

int
teardown(void **state)
{
	agent_test_exit();
	return 0;
}

int
main(void)
{
	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_wasm_mdc),
	};
	// setup and run tests
	return cmocka_run_group_tests(tests, setup, teardown);
}
