/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <config.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <parson.h>

#include <internal/util.h>

#include "agent_internal.h"
#include "agent_test.h"
#include "evp/sdk.h"
#include "hub.h"
#include "module_instance.h"
#include "mqtt_custom.h"

enum test_direct_command_payloads {
	DEPLOYMENT_MANIFEST_1,
	DIRECT_COMMAND_REQ_1,
	DIRECT_COMMAND_PARAMS_1
};

#define TEST_DEPLOYMENT_ID1 "2dc1a1c3-531b-4693-abba-a4a039bb827d"
#define TEST_INSTANCE_ID1   "07fe77d5-7117-4326-9042-47fda5dd9bf5"
#define TEST_MODULE_ID      "b91fe3e8-df6d-41b7-90cb-72f8b92bdf5e"
#define TEST_METHOD_NAME1   "test-method"
#define TEST_RPC_RESPONSE1  "This is the test response, a normal string"
// Use 0 to be sure that reqid 0 is well supported
#define TEST_REQID_MDC_REQ1 0

#define TB_TEST_RPC_REQUEST_PARAMS      "\"{\\\"param1\\\": \\\"input1\\\"}\""
#define EVP2_TB_TEST_RPC_REQUEST_PARAMS "{\"param1\": \"input1\"}"

#define EVP1_DEPLOYMENT_MANIFEST_1                                            \
	"\"{ "                                                                \
	"        \\\"deploymentId\\\": "                                      \
	"\\\"" TEST_DEPLOYMENT_ID1 "\\\","                                    \
	"        \\\"instanceSpecs\\\": {"                                    \
	"            \\\"" TEST_INSTANCE_ID1 "\\\": {"                        \
	"                \\\"moduleId\\\": "                                  \
	"\\\"" TEST_MODULE_ID "\\\","                                         \
	"                \\\"entryPoint\\\": \\\"backdoor-mdc\\\","           \
	"                \\\"version\\\": 1,"                                 \
	"                \\\"publish\\\": {},"                                \
	"                \\\"subscribe\\\": {}"                               \
	"            }"                                                       \
	"        },"                                                          \
	"        \\\"modules\\\": {"                                          \
	"            \\\"" TEST_MODULE_ID "\\\": {"                           \
	"                \\\"moduleImpl\\\": \\\"spawn\\\","                  \
	"                \\\"downloadUrl\\\": \\\"\\\","                      \
	"                \\\"hash\\\": \\\"\\\""                              \
	"            }"                                                       \
	"        },"                                                          \
	"        \\\"publishTopics\\\": {},"                                  \
	"        \\\"subscribeTopics\\\": {}"                                 \
	"}\""

#define EVP1_MDC_REQ_1                                                        \
	"{"                                                                   \
	"        \"method\": \"ModuleMethodCall\","                           \
	"        \"params\": {"                                               \
	"                \"moduleInstance\": "                                \
	"\"" TEST_INSTANCE_ID1 "\","                                          \
	"                \"moduleMethod\": \"test-method\","                  \
	"                \"params\": " TB_TEST_RPC_REQUEST_PARAMS "}"         \
	"}"

#define EVP2_DEPLOYMENT_MANIFEST_1                                            \
	"{"                                                                   \
	"        \"deploymentId\": \"" TEST_DEPLOYMENT_ID1 "\","              \
	"        \"instanceSpecs\": {"                                        \
	"            \"" TEST_INSTANCE_ID1 "\": {"                            \
	"                \"moduleId\": "                                      \
	"\"" TEST_MODULE_ID "\","                                             \
	"                \"publish\": {},"                                    \
	"                \"subscribe\": {}"                                   \
	"            }"                                                       \
	"        },"                                                          \
	"        \"modules\": {"                                              \
	"            \"" TEST_MODULE_ID "\": {"                               \
	"                \"entryPoint\": \"backdoor-mdc\","                   \
	"                \"moduleImpl\": \"spawn\","                          \
	"                \"downloadUrl\": \"\","                              \
	"                \"hash\": \"\""                                      \
	"            }"                                                       \
	"        },"                                                          \
	"        \"publishTopics\": {},"                                      \
	"        \"subscribeTopics\": {}"                                     \
	"}"

#define EVP2_TB_MDC_REQ_1                                                     \
	"{"                                                                   \
	"        \"direct-command-request\": {"                               \
	"                \"reqid\": \"" ___STRING(                            \
		TEST_REQID_MDC_REQ1) "\","                                    \
				     "                \"method\": "           \
				     "\"test-method\","                       \
				     "                \"instance\": "         \
				     "\"" TEST_INSTANCE_ID1 "\","             \
				     "                "                       \
				     "\"params\":"                            \
				     " " TB_TEST_RPC_REQUEST_PARAMS "}"       \
				     "}"

struct test {
	struct evp_agent_context *ctxt;
	struct agent_deployment d;
};

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

void
test_direct_command(void **state)
{
	// start agent
	struct test *t = *state;
	struct evp_agent_context *ctxt = t->ctxt;

	// create backdoor instance
	EVP_RESULT result;
	const char userRequestData[] = "some module request callback data";
	const char userResponseData[] = "some module response callback data";
	struct EVP_client *sdk_handle =
		evp_agent_add_instance(ctxt, "backdoor-mdc");
	assert_non_null(sdk_handle);
	result = EVP_setRpcCallback(sdk_handle, rpc_request_cb,
				    (void *)userRequestData);
	assert_int_equal(result, EVP_OK);

	agent_ensure_deployment(&t->d,
				agent_get_payload(DEPLOYMENT_MANIFEST_1),
				TEST_DEPLOYMENT_ID1);

	agent_send_direct_command_req(ctxt,
				      agent_get_payload(DIRECT_COMMAND_REQ_1),
				      TEST_REQID_MDC_REQ1);

	// verify request callback
	expect_value(rpc_request_cb, id, TEST_REQID_MDC_REQ1);
	expect_string(rpc_request_cb, method, TEST_METHOD_NAME1);
	expect_string(rpc_request_cb, params,
		      agent_get_payload(DIRECT_COMMAND_PARAMS_1));
	expect_memory(rpc_request_cb, userData, userRequestData,
		      sizeof(userRequestData));
	EVP_processEvent(sdk_handle, 1000);

	// direct command response
	// todo: test invalid JSON in response (fails quietly on EVP1)
	EVP_RPC_RESPONSE_STATUS status = EVP_RPC_RESPONSE_STATUS_OK;
	result = EVP_sendRpcResponse(
		sdk_handle, TEST_REQID_MDC_REQ1, "\"" TEST_RPC_RESPONSE1 "\"",
		status, rpc_response_cb, (void *)userResponseData);
	assert_int_equal(result, EVP_OK);
	agent_poll(verify_contains, TEST_RPC_RESPONSE1);

	// verify response callback
	expect_value(rpc_response_cb, reason,
		     EVP_RPC_RESPONSE_CALLBACK_REASON_SENT);
	expect_memory(rpc_response_cb, userData, userResponseData,
		      sizeof(userResponseData));
	EVP_processEvent(sdk_handle, 1000);
}

void
test_direct_command_toobig(void **state)
{
	// start agent
	struct test *t = *state;
	struct evp_agent_context *ctxt = t->ctxt;

	// create backdoor instance
	EVP_RESULT result;
	struct EVP_client *sdk_handle =
		evp_agent_add_instance(ctxt, "backdoor-mdc");
	assert_non_null(sdk_handle);
	char blob[CONFIG_EVP_MQTT_SEND_BUFF_SIZE + 1];

	memset(blob, 'A', sizeof blob - 1);
	blob[sizeof blob - 1] = '\0';

	// direct command response
	// todo: test invalid JSON in response (fails quietly on EVP1)
	EVP_RPC_RESPONSE_STATUS status = EVP_RPC_RESPONSE_STATUS_OK;
	result = EVP_sendRpcResponse(sdk_handle, 654321, blob, status,
				     rpc_response_cb, NULL);
	assert_int_equal(result, EVP_TOOBIG);
}

void
test_direct_command_empty(void **state)
{
	// start agent
	struct test *t = *state;
	struct evp_agent_context *ctxt = t->ctxt;

	// create backdoor instance
	EVP_RESULT result;
	struct EVP_client *sdk_handle =
		evp_agent_add_instance(ctxt, "backdoor-mdc");
	assert_non_null(sdk_handle);

	// direct command response
	// todo: test invalid JSON in response (fails quietly on EVP1)
	EVP_RPC_RESPONSE_STATUS status = EVP_RPC_RESPONSE_STATUS_OK;
	result = EVP_sendRpcResponse(sdk_handle, 0, NULL, status,
				     rpc_response_cb, NULL);
	assert_int_equal(result, EVP_INVAL);
}

int
setup(void **state)
{
	agent_test_setup();
	// register EVP1 payloads
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

	// start agent
	struct evp_agent_context *ctxt = agent_test_start();

	if (!ctxt) {
		fprintf(stderr, "%s: agent_test_start failed\n", __func__);
		return -1;
	}

	static struct test t;

	t = (struct test){.ctxt = ctxt, .d = {.ctxt = ctxt}};

	*state = &t;
	return 0;
}

int
teardown(void **state)
{
	// wait for agent to finish
	agent_test_exit();
	return 0;
}

int
main(void)
{
	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_direct_command),
		cmocka_unit_test(test_direct_command_toobig),
		cmocka_unit_test(test_direct_command_empty),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup, teardown);
}
