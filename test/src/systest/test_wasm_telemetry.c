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
#include "wasm_utils.h"
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
	TELEMETRY_1,
	TELEMETRY_2,
};

#define TEST_INSTANCE_ID1 "backdoor-mdc"
#define TEST_METHOD_NAME1 "test-method"

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

/* Keep the whitespaces out of json */
#define EVP1_TELEMETRY_EXPECTED_1                                             \
	"{"                                                                   \
	"\"" TEST_MODULE_INSTANCE_ID1 "/first-key\":\"value1\","              \
	"\"" TEST_MODULE_INSTANCE_ID1 "/second-key\":\"value2\""              \
	"}"

#define EVP2_TB_TELEMETRY_EXPECTED_1 EVP1_TELEMETRY_EXPECTED_1

#define TEST_CALLBACK 0xbeefdead
#define TEST_UDATA    0xdeadbeef

typedef struct EVP_telemetry_entry_wasm {
	uint32_t key;
	uint32_t value;
} EVP_telemetry_entry_wasm;

static uint32_t
fill_telemetries(wasm_module_inst_t inst,
		 struct EVP_telemetry_entry_wasm **oep, int *n)
{
	size_t siz;
	void *ptr;
	EVP_telemetry_entry_wasm *ep;
	uint32_t off;

	siz = 2 * sizeof(EVP_telemetry_entry_wasm);
	off = wasm_runtime_module_malloc(inst, siz, &ptr);
	*oep = ep = ptr;
	*n = 2;

	ep[0].key = evp_wasm_string_create(inst, "first-key");
	ep[0].value = evp_wasm_string_create(inst, "\"value1\"");

	ep[1].key = evp_wasm_string_create(inst, "second-key");
	ep[1].value = evp_wasm_string_create(inst, "\"value2\"");

	return off;
}

bool
__wrap_wasm_runtime_call_indirect(struct WASMExecEnv *exec_env, uint32_t off,
				  uint32_t argc, uint32_t argv[])
{
	assert_int_equal(off, TEST_CALLBACK);
	assert_int_equal(argc, 2);
	assert_int_equal(argv[0], EVP_TELEMETRY_CALLBACK_REASON_SENT);
	assert_int_equal(argv[1], TEST_UDATA);

	return true;
}

void
test_wasm_telemetry(void **state)
{
	int n;
	EVP_RESULT result;
	uint32_t telemetries;
	struct EVP_telemetry_entry_wasm *ep;

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

	telemetries = fill_telemetries(wasm_module_inst, &ep, &n);
	result =
		EVP_sendTelemetry_wasm(wasm_exec_env, handle_wasm, telemetries,
				       n, TEST_CALLBACK, TEST_UDATA);
	assert_int_equal(result, EVP_OK);

	result = EVP_processEvent_wasm(wasm_exec_env, handle_wasm, 1000);
	assert_int_equal(result, EVP_OK);

	agent_poll(verify_contains, agent_get_payload(TELEMETRY_1));

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

	// Deployment
	agent_register_payload(DEPLOYMENT_MANIFEST_1, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_DEPLOYMENT_MANIFEST_1);
	agent_register_payload(DEPLOYMENT_MANIFEST_1, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_DEPLOYMENT_MANIFEST_1);

	// Expected telemetry
	agent_register_payload(TELEMETRY_1, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_TELEMETRY_EXPECTED_1);
	agent_register_payload(TELEMETRY_1, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_TB_TELEMETRY_EXPECTED_1);

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
		cmocka_unit_test(test_wasm_telemetry),
	};
	// setup and run tests
	return cmocka_run_group_tests(tests, setup, teardown);
}
