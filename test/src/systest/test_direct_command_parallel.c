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

#include <evp/sdk.h>
#include <parson.h>

#include <internal/util.h>

#include "agent_test.h"
#include "hub.h"
#include "module_instance.h"
#include "mqtt_custom.h"

enum test_direct_command_payloads {
	DEPLOYMENT_MANIFEST_1,
	DIRECT_COMMAND_PARAMS_1,
	DIRECT_COMMAND_PARAMS_PARSED_1,
};

#define TEST_DEPLOYMENT_ID1 "2dc1a1c3-531b-4693-abba-a4a039bb827d"
#define TEST_INSTANCE_ID1   "07fe77d5-7117-4326-9042-47fda5dd9bf5"
#define TEST_METHOD_NAME1   "test-method"
#define TEST_RPC_RESPONSE1  "This is the test response, a normal string"

// smartrest_encode_string() doesn't handle escaped JSON well
#define TB_TEST_RPC_REQUEST_PARAMS        "\"{\\\"param1\\\": \\\"input1\\\"}\""
#define TB_TEST_RPC_REQUEST_PARAMS_PARSED "{\"param1\": \"input1\"}"

#define EVP1_DEPLOYMENT_MANIFEST_1                                            \
	"\"{ "                                                                \
	"        \\\"deploymentId\\\": "                                      \
	"\\\"2dc1a1c3-531b-4693-abba-a4a039bb827d\\\","                       \
	"        \\\"instanceSpecs\\\": {"                                    \
	"            \\\"07fe77d5-7117-4326-9042-47fda5dd9bf5\\\": {"         \
	"                \\\"moduleId\\\": "                                  \
	"\\\"b91fe3e8-df6d-41b7-90cb-72f8b92bdf5e\\\","                       \
	"                \\\"entryPoint\\\": \\\"backdoor-mdc\\\","           \
	"                \\\"version\\\": 1,"                                 \
	"                \\\"publish\\\": {},"                                \
	"                \\\"subscribe\\\": {}"                               \
	"            }"                                                       \
	"        },"                                                          \
	"        \\\"modules\\\": {"                                          \
	"            \\\"b91fe3e8-df6d-41b7-90cb-72f8b92bdf5e\\\": {"         \
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
	"        \"deploymentId\": \"2dc1a1c3-531b-4693-abba-a4a039bb827d\"," \
	"        \"instanceSpecs\": {"                                        \
	"            \"07fe77d5-7117-4326-9042-47fda5dd9bf5\": {"             \
	"                \"moduleId\": "                                      \
	"\"b91fe3e8-df6d-41b7-90cb-72f8b92bdf5e\","                           \
	"                \"publish\": {},"                                    \
	"                \"subscribe\": {}"                                   \
	"            }"                                                       \
	"        },"                                                          \
	"        \"modules\": {"                                              \
	"            \"b91fe3e8-df6d-41b7-90cb-72f8b92bdf5e\": {"             \
	"                \"entryPoint\": \"backdoor-mdc\","                   \
	"                \"moduleImpl\": \"spawn\","                          \
	"                \"downloadUrl\": \"\","                              \
	"                \"hash\": \"\""                                      \
	"            }"                                                       \
	"        },"                                                          \
	"        \"publishTopics\": {},"                                      \
	"        \"subscribeTopics\": {}"                                     \
	"}"

// MDC multiple requests table
struct mdc_table {
	size_t n;
	EVP_RPC_ID *id;
	char **params;
	// Boolean flags (but cmocka's *_in_set() functions wants it as
	// unsigned long):
	unsigned long *req_callback_dispatched;
};

char *
agent_payload_mdc_evp1(EVP_RPC_ID reqid, const char *instance_id,
		       const char *method, const char *params)
{
#define EVP1_MDC_BASE                                                         \
	"{"                                                                   \
	"        \"method\": \"ModuleMethodCall\","                           \
	"        \"params\": {"                                               \
	"                \"moduleInstance\": "                                \
	"\"%s\","                                                             \
	"                \"moduleMethod\": \"%s\","                           \
	"                \"params\": %s }"                                    \
	"}"

	char *out;
	(void)reqid;
	xasprintf(&out, EVP1_MDC_BASE, instance_id, method, params);
	return out;
}

char *
agent_payload_mdc_evp2(EVP_RPC_ID reqid, const char *instance_id,
		       const char *method, const char *params)
{
#define EVP2_MDC_BASE                                                         \
	"{"                                                                   \
	"        \"direct-command-request\": {"                               \
	"                \"reqid\": \"%lu\","                                 \
	"                \"method\": \"%s\","                                 \
	"                \"instance\": "                                      \
	"\"%s\","                                                             \
	"                \"params\": %s}"                                     \
	"}"

	char *out;
	xasprintf(&out, EVP2_MDC_BASE, reqid, method, instance_id, params);
	return out;
}

char *
agent_payload_mdc(EVP_RPC_ID reqid, const char *instance_id,
		  const char *method, const char *params)
{
	enum evp_hub_type hub = agent_test_get_hub_type();
	if (hub == EVP_HUB_TYPE_EVP1_TB) {
		return agent_payload_mdc_evp1(reqid, instance_id, method,
					      params);
	} else if (hub == EVP_HUB_TYPE_EVP2_TB) {
		return agent_payload_mdc_evp2(reqid, instance_id, method,
					      params);
	}
	return NULL;
}

static void
rpc_request_cb(EVP_RPC_ID id, const char *method, const char *params,
	       void *userData)
{
	check_expected(id);
	check_expected(method);
	check_expected(params);

	struct mdc_table *table = userData;
	for (size_t i = 0; i < table->n; i++) {
		if (id == table->id[i]) {
			table->req_callback_dispatched[i] =
				(unsigned long)true;
		}
	}
}

static void
rpc_response_cb(EVP_RPC_RESPONSE_CALLBACK_REASON reason, void *userData)
{
	check_expected(reason);
}

void
test_direct_commands_parallel(void **state)
{
	// start agent
	struct evp_agent_context *ctxt = *state;
	assert_non_null(ctxt);
	struct agent_deployment d = {.ctxt = ctxt};

	// create module instance
	EVP_RESULT result;
	struct EVP_client *sdk_handle =
		evp_agent_add_instance(ctxt, "backdoor-mdc");
	assert_non_null(sdk_handle);
	agent_ensure_deployment(&d, agent_get_payload(DEPLOYMENT_MANIFEST_1),
				TEST_DEPLOYMENT_ID1);

	// Prepare multiple MDC requests
	struct mdc_table table = {.n = 22};
	EVP_RPC_ID ids[22];
	unsigned long flags[22];
	char *params[22];
	table.id = ids;
	table.req_callback_dispatched = flags;
	table.params = params;
	result = EVP_setRpcCallback(sdk_handle, rpc_request_cb, &table);
	assert_int_equal(result, EVP_OK);

	for (size_t i = 0; i < table.n; i++) {
		table.id[i] = 987601 + i;
		table.req_callback_dispatched[i] = (unsigned long)false;
		const char *params =
			agent_get_payload(DIRECT_COMMAND_PARAMS_1);
		table.params[i] = agent_payload_mdc(
			table.id[i], TEST_INSTANCE_ID1, "test-method", params);
	}

	// Inject the MDC requests
	for (size_t i = 0; i < table.n; i++) {
		agent_send_direct_command_req(ctxt, table.params[i],
					      table.id[i]);
	}

	expect_in_set_count(rpc_request_cb, id, ids, table.n);
	expect_string_count(rpc_request_cb, method, "test-method", table.n);
	expect_string_count(rpc_request_cb, params,
			    agent_get_payload(DIRECT_COMMAND_PARAMS_PARSED_1),
			    table.n);
	for (size_t i = 0; i < table.n; i++) {
		EVP_processEvent(sdk_handle, 1000);
	}
	assert_not_in_set((unsigned long)false, table.req_callback_dispatched,
			  table.n);

	// Issue MDC responses
	EVP_RPC_RESPONSE_STATUS status = EVP_RPC_RESPONSE_STATUS_OK;
	for (size_t i = 0; i < table.n; i++) {
		result = EVP_sendRpcResponse(sdk_handle, table.id[i],
					     "\"" TEST_RPC_RESPONSE1 "\"",
					     status, rpc_response_cb, NULL);
		assert_int_equal(result, EVP_OK);
		agent_poll(verify_contains, TEST_RPC_RESPONSE1);
	}

	// Verify response callbacks
	expect_value_count(rpc_response_cb, reason,
			   EVP_RPC_RESPONSE_CALLBACK_REASON_SENT, table.n);
	for (size_t i = 0; i < table.n; i++) {
		EVP_processEvent(sdk_handle, 1000);
	}

	// cleanup
	for (size_t i = 0; i < table.n; i++) {
		free(table.params[i]);
	}
}

int
setup(void **state)
{
	agent_test_setup();
	// register EVP1 payloads
	agent_register_payload(DEPLOYMENT_MANIFEST_1, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_DEPLOYMENT_MANIFEST_1);
	agent_register_payload(DIRECT_COMMAND_PARAMS_1, EVP_HUB_TYPE_EVP1_TB,
			       TB_TEST_RPC_REQUEST_PARAMS);
	agent_register_payload(DIRECT_COMMAND_PARAMS_PARSED_1,
			       EVP_HUB_TYPE_EVP1_TB,
			       TB_TEST_RPC_REQUEST_PARAMS);
	// register TB payloads
	agent_register_payload(DEPLOYMENT_MANIFEST_1, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_DEPLOYMENT_MANIFEST_1);
	agent_register_payload(DIRECT_COMMAND_PARAMS_1, EVP_HUB_TYPE_EVP2_TB,
			       TB_TEST_RPC_REQUEST_PARAMS);
	agent_register_payload(DIRECT_COMMAND_PARAMS_PARSED_1,
			       EVP_HUB_TYPE_EVP2_TB,
			       TB_TEST_RPC_REQUEST_PARAMS_PARSED);

	// start agent
	struct evp_agent_context *ctxt = agent_test_start();

	if (!ctxt) {
		fprintf(stderr, "%s: agent_test_start failed\n", __func__);
		return -1;
	}

	*state = ctxt;
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
		cmocka_unit_test(test_direct_commands_parallel),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup, teardown);
}
