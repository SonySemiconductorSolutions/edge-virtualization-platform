/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <evp/sdk.h>
#include <parson.h>

#include <internal/util.h>

#include "agent_test.h"
#include "hub.h"
#include "module_instance.h"
#include "mqtt_custom.h"

enum test_wasm_config_echo_payloads {
	DEPLOYMENT_MANIFEST_1,
	EMPTY_DEPLOYMENT_MANIFEST_1,
	INSTANCE_CONFIG_1,
	INSTANCE_CONFIG_2,
	EXPECTED_STATE,
	EXPECTED_STATUS,
};

#define TEST_DEPLOYMENT_ID1       "10000000-1001-1002-1003-100000000004"
#define TEST_EMPTY_DEPLOYMENT_ID1 "20000000-2001-2002-2003-200000000004"
#define TEST_INSTANCE_ID1         "88888880-8881-8882-8883-888888888884"
#define TEST_INSTANCE_ID2         "88888880-8881-8882-8883-888888888885"

#define ACTION_KEY       "exit-request"
#define ACTION_VALUE     "dummy"
#define ACTION_VALUE_B64 "ZHVtbXk=" // b64-encoded string: "dummy"

#define MODULE_PATH "../test_modules/exit_voluntarily.wasm"

#define MODULE_HASH                                                           \
	"4bd8c7493022942da08c1ebe921f6cef6c59dd04fe20e18b2678f8ce1bbbdaac"

#define EVP1_DEPLOYMENT_MANIFEST_1                                            \
	"\"{ "                                                                \
	"        \\\"deploymentId\\\": "                                      \
	"\\\"" TEST_DEPLOYMENT_ID1 "\\\","                                    \
	"        \\\"instanceSpecs\\\": {"                                    \
	"            \\\"" TEST_INSTANCE_ID1 "\\\": {"                        \
	"                \\\"moduleId\\\": "                                  \
	"\\\"aaaaaaa0-aaa1-aaa2-aaa3-aaaaaaaaaaa4\\\","                       \
	"                \\\"entryPoint\\\": \\\"main\\\","                   \
	"                \\\"version\\\": 1,"                                 \
	"                \\\"publish\\\": {},"                                \
	"                \\\"subscribe\\\": {}"                               \
	"            },"                                                      \
	"            \\\"" TEST_INSTANCE_ID2 "\\\": {"                        \
	"                \\\"moduleId\\\": "                                  \
	"\\\"aaaaaaa0-aaa1-aaa2-aaa3-aaaaaaaaaaa4\\\","                       \
	"                \\\"entryPoint\\\": \\\"main\\\","                   \
	"                \\\"version\\\": 1,"                                 \
	"                \\\"publish\\\": {},"                                \
	"                \\\"subscribe\\\": {}"                               \
	"            }"                                                       \
	"        },"                                                          \
	"        \\\"modules\\\": {"                                          \
	"            \\\"aaaaaaa0-aaa1-aaa2-aaa3-aaaaaaaaaaa4\\\": {"         \
	"                \\\"moduleImpl\\\": \\\"wasm\\\","                   \
	"                \\\"downloadUrl\\\": \\\"file://%s\\\","             \
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

#define EVP1_INSTANCE_CONFIG_1                                                \
	"{"                                                                   \
	"	\"configuration/" TEST_INSTANCE_ID1 "/" ACTION_KEY            \
	"\": \"" ACTION_VALUE_B64 "\""                                        \
	"}"

#define EVP1_INSTANCE_CONFIG_2                                                \
	"{"                                                                   \
	"	\"configuration/" TEST_INSTANCE_ID2 "/" ACTION_KEY            \
	"\": \"" ACTION_VALUE_B64 "\""                                        \
	"}"

#define EVP2_DEPLOYMENT_MANIFEST_1                                            \
	"{"                                                                   \
	"        \"deploymentId\": \"" TEST_DEPLOYMENT_ID1 "\","              \
	"        \"instanceSpecs\": {"                                        \
	"            \"" TEST_INSTANCE_ID1 "\": {"                            \
	"                \"moduleId\": "                                      \
	"\"aaaaaaa0-aaa1-aaa2-aaa3-aaaaaaaaaaa4\","                           \
	"                \"publish\": {},"                                    \
	"                \"subscribe\": {}"                                   \
	"            },"                                                      \
	"            \"" TEST_INSTANCE_ID2 "\": {"                            \
	"                \"moduleId\": "                                      \
	"\"aaaaaaa0-aaa1-aaa2-aaa3-aaaaaaaaaaa4\","                           \
	"                \"publish\": {},"                                    \
	"                \"subscribe\": {}"                                   \
	"            }"                                                       \
	"        },"                                                          \
	"        \"modules\": {"                                              \
	"            \"aaaaaaa0-aaa1-aaa2-aaa3-aaaaaaaaaaa4\": {"             \
	"                \"entryPoint\": \"main\","                           \
	"                \"moduleImpl\": \"wasm\","                           \
	"                \"downloadUrl\": "                                   \
	"\"file://%s\","                                                      \
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

#define EVP2_INSTANCE_CONFIG_1                                                \
	"{"                                                                   \
	"	\"configuration/" TEST_INSTANCE_ID1 "/" ACTION_KEY            \
	"\": \"" ACTION_VALUE "\""                                            \
	"}"

#define EVP2_INSTANCE_CONFIG_2                                                \
	"{"                                                                   \
	"	\"configuration/" TEST_INSTANCE_ID2 "/" ACTION_KEY            \
	"\": \"" ACTION_VALUE "\""                                            \
	"}"

#define EVP1_EXPECTED_STATE ACTION_VALUE_B64
#define EVP2_EXPECTED_STATE ACTION_VALUE

void
test_wasm_health_check(void **state)
{
	// start agent
	struct evp_agent_context *ctxt = agent_test_start();
	struct agent_deployment d = {.ctxt = ctxt};

	// deploy
	agent_ensure_deployment(&d, agent_get_payload(DEPLOYMENT_MANIFEST_1),
				TEST_DEPLOYMENT_ID1);

	// send config
	agent_send_instance_config(ctxt, agent_get_payload(INSTANCE_CONFIG_1));

	// wait for the module instance status to be set as "self-exiting"
	agent_poll(verify_json, agent_get_payload(EXPECTED_STATUS),
		   "self-exiting");

	// Sends a second state to force a report
	agent_send_instance_config(ctxt, agent_get_payload(INSTANCE_CONFIG_2));

	// wait for the dummy value to be echoed as an instance state message
	agent_poll(verify_json,
		   "state/" TEST_INSTANCE_ID1 "/" ACTION_KEY "=%s",
		   agent_get_payload(EXPECTED_STATE));

	// send empty deployment
	agent_ensure_deployment(&d,
				agent_get_payload(EMPTY_DEPLOYMENT_MANIFEST_1),
				TEST_EMPTY_DEPLOYMENT_ID1);
}

static char *deployment1;
static char *deployment2;

static int
teardown(void **state)
{
	agent_test_exit();
	free(deployment1);
	free(deployment2);
	return 0;
}

static int
setup(void **state)
{
	agent_test_setup();

	xasprintf(&deployment1, EVP1_DEPLOYMENT_MANIFEST_1, MODULE_PATH);

	xasprintf(&deployment2, EVP2_DEPLOYMENT_MANIFEST_1, MODULE_PATH);

	agent_register_payload(INSTANCE_CONFIG_1, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_INSTANCE_CONFIG_1);
	agent_register_payload(INSTANCE_CONFIG_1, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_INSTANCE_CONFIG_1);
	agent_register_payload(INSTANCE_CONFIG_2, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_INSTANCE_CONFIG_2);
	agent_register_payload(INSTANCE_CONFIG_2, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_INSTANCE_CONFIG_2);

	agent_register_payload(DEPLOYMENT_MANIFEST_1, EVP_HUB_TYPE_EVP1_TB,
			       deployment1);
	agent_register_payload(DEPLOYMENT_MANIFEST_1, EVP_HUB_TYPE_EVP2_TB,
			       deployment2);
	agent_register_payload(EMPTY_DEPLOYMENT_MANIFEST_1,
			       EVP_HUB_TYPE_EVP2_TB,
			       EVP2_EMPTY_DEPLOYMENT_MANIFEST_1);
	agent_register_payload(EMPTY_DEPLOYMENT_MANIFEST_1,
			       EVP_HUB_TYPE_EVP1_TB,
			       EVP1_EMPTY_DEPLOYMENT_MANIFEST_1);

	agent_register_payload(
		EXPECTED_STATUS, EVP_HUB_TYPE_EVP1_TB,
		"deploymentStatus=#{instances." TEST_INSTANCE_ID1
		".status=%s}");
	agent_register_payload(EXPECTED_STATUS, EVP_HUB_TYPE_EVP2_TB,
			       "deploymentStatus.instances." TEST_INSTANCE_ID1
			       ".status=%s");

	agent_register_payload(EXPECTED_STATE, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_EXPECTED_STATE);
	agent_register_payload(EXPECTED_STATE, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_EXPECTED_STATE);
	return 0;
}

int
main(void)
{
	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_wasm_health_check),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup, teardown);
}
