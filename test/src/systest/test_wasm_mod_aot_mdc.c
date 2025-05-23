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

enum test_direct_command_payloads {
	DEPLOYMENT_MANIFEST_1,
	EMPTY_DEPLOYMENT_MANIFEST_1,
	DIRECT_COMMAND_REQ_1,
	DIRECT_COMMAND_PARAMS_1
};

#define TEST_EMPTY_DEPLOYMENT_ID1 "4fa905ae-e103-46ab-a8b9-73be07599709"
#define TEST_DEPLOYMENT_ID1       "2dc1a1c3-531b-4693-abba-a4a039bb827d"
#define TEST_MODULE_ID1           "b91fe3e8-df6d-41b7-90cb-72f8b92bdf5e"
#define TEST_INSTANCE_ID1         "mdc-instance"

#define TEST_METHOD_NAME1  "echo"
#define TEST_RPC_RESPONSE1 "This is the test response, a normal string"
#define RPC_REQUEST_ID     543210

#define MODULE_PATH "../test_modules/rpc.wasm.x86_64.aot"

#define MODULE_HASH                                                           \
	"579fca500ec9f67a661e8b1a3a59a114a97029c46776d6ad9502fb183f1a1f7d"

#define PARAM "param1"
#define INPUT "input1"

#define TB_TEST_RPC_REQUEST_PARAMS      "\"{\\\"" PARAM "\\\": \\\"" INPUT "\\\"}\""
#define EVP2_TB_TEST_RPC_REQUEST_PARAMS "{\"" PARAM "\": \"" INPUT "\"}"

#define EVP1_DEPLOYMENT_MANIFEST_1                                            \
	"\"{ "                                                                \
	"        \\\"deploymentId\\\": "                                      \
	"\\\"" TEST_DEPLOYMENT_ID1 "\\\","                                    \
	"        \\\"instanceSpecs\\\": {"                                    \
	"            \\\"" TEST_INSTANCE_ID1 "\\\": {"                        \
	"                \\\"moduleId\\\": "                                  \
	"\\\"" TEST_MODULE_ID1 "\\\","                                        \
	"                \\\"entryPoint\\\": \\\"main\\\","                   \
	"                \\\"version\\\": 1,"                                 \
	"                \\\"publish\\\": {},"                                \
	"                \\\"subscribe\\\": {}"                               \
	"            }"                                                       \
	"        },"                                                          \
	"        \\\"modules\\\": {"                                          \
	"            \\\"" TEST_MODULE_ID1 "\\\": {"                          \
	"                \\\"moduleImpl\\\": \\\"wasm\\\","                   \
	"                \\\"downloadUrl\\\": \\\"file://" MODULE_PATH        \
	"\\\","                                                               \
	"                \\\"hash\\\": \\\"" MODULE_HASH "\\\""               \
	"            }"                                                       \
	"        },"                                                          \
	"        \\\"publishTopics\\\": {},"                                  \
	"        \\\"subscribeTopics\\\": {}"                                 \
	"}\""

#define EVP1_EMPTY_DEPLOYMENT_MANIFEST_1                                      \
	"\"{ "                                                                \
	"        \\\"deploymentId\\\": "                                      \
	"\\\"" TEST_EMPTY_DEPLOYMENT_ID1 "\\\","                              \
	"        \\\"instanceSpecs\\\": {},"                                  \
	"        \\\"modules\\\": {},"                                        \
	"        \\\"publishTopics\\\": {},"                                  \
	"        \\\"subscribeTopics\\\": {}"                                 \
	"}\""

#define EVP2_DEPLOYMENT_MANIFEST_1                                            \
	"{"                                                                   \
	"        \"deploymentId\": \"" TEST_DEPLOYMENT_ID1 "\","              \
	"        \"instanceSpecs\": {"                                        \
	"            \"" TEST_INSTANCE_ID1 "\": {"                            \
	"                \"moduleId\": "                                      \
	"\"" TEST_MODULE_ID1 "\","                                            \
	"                \"publish\": {},"                                    \
	"                \"subscribe\": {}"                                   \
	"            }"                                                       \
	"        },"                                                          \
	"        \"modules\": {"                                              \
	"            \"" TEST_MODULE_ID1 "\": {"                              \
	"                \"entryPoint\": \"main\","                           \
	"                \"moduleImpl\": \"wasm\","                           \
	"                \"downloadUrl\": "                                   \
	"\"file://" MODULE_PATH "\","                                         \
	"                \"hash\": "                                          \
	"\"" MODULE_HASH ""                                                   \
	"\""                                                                  \
	"            }"                                                       \
	"        },"                                                          \
	"        \"publishTopics\": {},"                                      \
	"        \"subscribeTopics\": {}"                                     \
	"}"

#define EVP2_EMPTY_DEPLOYMENT_MANIFEST_1                                      \
	"{"                                                                   \
	"        \"deploymentId\": \"" TEST_EMPTY_DEPLOYMENT_ID1 "\","        \
	"        \"instanceSpecs\": {},"                                      \
	"        \"modules\": {},"                                            \
	"        \"publishTopics\": {},"                                      \
	"        \"subscribeTopics\": {}"                                     \
	"}"

#define EVP1_MDC_REQ_1                                                        \
	"{"                                                                   \
	"        \"method\": \"ModuleMethodCall\","                           \
	"        \"params\": {"                                               \
	"                \"moduleInstance\": "                                \
	"\"" TEST_INSTANCE_ID1 "\","                                          \
	"                \"moduleMethod\": \"" TEST_METHOD_NAME1 "\","        \
	"                \"params\": " TB_TEST_RPC_REQUEST_PARAMS "}"         \
	"}"

#define XSTR(x) #x
#define STR(x)  XSTR(x)

#define EVP2_TB_MDC_REQ_1                                                     \
	"{"                                                                   \
	"\"direct-command-request\": {"                                       \
	"\"reqid\": \"" STR(                                                  \
		RPC_REQUEST_ID) "\","                                         \
				"\"method\": "                                \
				"\"" TEST_METHOD_NAME1 "\","                  \
				"\"instance\": "                              \
				"\"" TEST_INSTANCE_ID1 "\","                  \
				""                                            \
				"\"params\": " TB_TEST_RPC_REQUEST_PARAMS "}" \
				"}"

#define TEST_RPC_REQUEST_CALLBACK_INDEX  0xbeefbeef
#define TEST_RPC_RESPONSE_CALLBACK_INDEX 0xfeedbab3
#define TEST_RPC_CALLBACK_USER_DATA      31337

void
test_wasm_mod_mdc(void **state)
{
	/* This should test the the RPC functionality.
	 *
	 * First we register the RPC callback, then we
	 * Make a request, and finally send a response
	 */

	// start agent
	struct evp_agent_context *ctxt = agent_test_start();
	struct agent_deployment d = {.ctxt = ctxt};

	// send initial deployment
	agent_ensure_deployment(&d, agent_get_payload(DEPLOYMENT_MANIFEST_1),
				TEST_DEPLOYMENT_ID1);

	// Send the RPC request
	agent_send_direct_command_req(
		ctxt, agent_get_payload(DIRECT_COMMAND_REQ_1), RPC_REQUEST_ID);

	// Wait for the response
	if (EVP_HUB_TYPE_EVP1_TB == agent_test_get_hub_type()) {
		agent_poll(verify_json,
			   "moduleInstance=%s,"
			   "status=%f,"
			   "response=#{" PARAM "=%s}",
			   TEST_INSTANCE_ID1, (double)0, INPUT);
	} else if (EVP_HUB_TYPE_EVP2_TB == agent_test_get_hub_type()) {
		agent_poll(verify_json,
			   "direct-command-response.status=%s,"
			   "direct-command-response.reqid=%s,"
			   "direct-command-response.response=#{" PARAM "=%s}",
			   "ok", STR(RPC_REQUEST_ID), INPUT);
	} else {
		agent_poll(verify_json,
			   "type=%s,"
			   "text=#{"
			   "direct-command-response.status=%s,"
			   "direct-command-response.reqid=%s,"
			   "direct-command-response.response=%s}",
			   "MDC_response", "ok", STR(RPC_REQUEST_ID), "{}");
	}

	// send empty deployment
	agent_ensure_deployment(&d,
				agent_get_payload(EMPTY_DEPLOYMENT_MANIFEST_1),
				TEST_EMPTY_DEPLOYMENT_ID1);
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
	agent_register_payload(EMPTY_DEPLOYMENT_MANIFEST_1,
			       EVP_HUB_TYPE_EVP1_TB,
			       EVP1_EMPTY_DEPLOYMENT_MANIFEST_1);

	// register TB payloads
	agent_register_payload(DEPLOYMENT_MANIFEST_1, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_DEPLOYMENT_MANIFEST_1);
	agent_register_payload(DIRECT_COMMAND_REQ_1, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_TB_MDC_REQ_1);
	agent_register_payload(DIRECT_COMMAND_PARAMS_1, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_TB_TEST_RPC_REQUEST_PARAMS);
	agent_register_payload(EMPTY_DEPLOYMENT_MANIFEST_1,
			       EVP_HUB_TYPE_EVP2_TB,
			       EVP2_EMPTY_DEPLOYMENT_MANIFEST_1);

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
		cmocka_unit_test(test_wasm_mod_mdc),
	};
	// setup and run tests
	return cmocka_run_group_tests(tests, setup, teardown);
}
