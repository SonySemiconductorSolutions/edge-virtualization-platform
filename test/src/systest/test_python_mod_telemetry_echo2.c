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

enum test_wasm_telemetry_echo2_payloads {
	DEPLOYMENT_MANIFEST_1,
	EMPTY_DEPLOYMENT_MANIFEST_1,
	INSTANCE_CONFIG_1,
};

#define TEST_DEPLOYMENT_ID1       "4fa905ae-e103-46ab-a8b9-73be07599708"
#define TEST_EMPTY_DEPLOYMENT_ID1 "4fa905ae-e103-46ab-a8b9-73be07599709"
#define TEST_INSTANCE_ID1         "b218f90b-9228-423f-8e02-000000000001"

#define DUMMY_KEY        "download"
#define EXPECTED_STATE   "{\"foo\":\"bar\"}"
#define EVP1_DUMMY_VALUE "eyJmb28iOiAiYmFyIn0K"
#define EVP2_DUMMY_VALUE "{\\\"foo\\\": \\\"bar\\\"}"

#define MODULE_PATH "../test_modules/python/telemetry_echo2.zip"

#define MODULE_HASH                                                           \
	"36f2fab6c8c9c3bb700ce5dc52c4f740be9acc439f749f2612d4f9177bc5bb83"

#define EVP1_DEPLOYMENT_MANIFEST_1                                            \
	"\"{ "                                                                \
	"        \\\"deploymentId\\\": "                                      \
	"\\\"" TEST_DEPLOYMENT_ID1 "\\\","                                    \
	"        \\\"instanceSpecs\\\": {"                                    \
	"            \\\"" TEST_INSTANCE_ID1 "\\\": {"                        \
	"                \\\"moduleId\\\": "                                  \
	"\\\"b218f90b-9228-423f-8e02-a6d3527bc15d\\\","                       \
	"                \\\"entryPoint\\\": \\\"main\\\","                   \
	"                \\\"version\\\": 1,"                                 \
	"                \\\"publish\\\": {},"                                \
	"                \\\"subscribe\\\": {}"                               \
	"            }"                                                       \
	"        },"                                                          \
	"        \\\"modules\\\": {"                                          \
	"            \\\"b218f90b-9228-423f-8e02-a6d3527bc15d\\\": {"         \
	"                \\\"moduleImpl\\\": \\\"python\\\","                 \
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

#define EVP1_INSTANCE_CONFIG_1                                                \
	"{"                                                                   \
	"	\"configuration/" TEST_INSTANCE_ID1 "/" DUMMY_KEY             \
	"\": \"" EVP1_DUMMY_VALUE "\""                                        \
	"}"

#define EVP2_DEPLOYMENT_MANIFEST_1                                            \
	"{"                                                                   \
	"        \"deploymentId\": \"" TEST_DEPLOYMENT_ID1 "\","              \
	"        \"instanceSpecs\": {"                                        \
	"            \"" TEST_INSTANCE_ID1 "\": {"                            \
	"                \"moduleId\": "                                      \
	"\"b218f90b-9228-423f-8e02-a6d3527bc15d\","                           \
	"                \"publish\": {},"                                    \
	"                \"subscribe\": {}"                                   \
	"            }"                                                       \
	"        },"                                                          \
	"        \"modules\": {"                                              \
	"            \"b218f90b-9228-423f-8e02-a6d3527bc15d\": {"             \
	"                \"entryPoint\": \"main\","                           \
	"                \"moduleImpl\": \"python\","                         \
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

#define EVP2_INSTANCE_CONFIG_1                                                \
	"{"                                                                   \
	"	\"configuration/" TEST_INSTANCE_ID1 "/" DUMMY_KEY             \
	"\": \"" EVP2_DUMMY_VALUE "\""                                        \
	"}"

static void
test_python_mod_telemetry_echo2(void **state)
{
	// start agent
	struct evp_agent_context *ctxt = agent_test_start();
	struct agent_deployment d = {.ctxt = ctxt};

	// deploy
	agent_ensure_deployment(&d, agent_get_payload(DEPLOYMENT_MANIFEST_1),
				TEST_DEPLOYMENT_ID1);

	// send config
	agent_send_instance_config(ctxt, agent_get_payload(INSTANCE_CONFIG_1));

	// wait for the dummy value
	agent_poll(verify_contains, EXPECTED_STATE);

	// send empty deployment
	agent_ensure_deployment(&d,
				agent_get_payload(EMPTY_DEPLOYMENT_MANIFEST_1),
				TEST_EMPTY_DEPLOYMENT_ID1);
}

static int
teardown(void **state)
{
	agent_test_exit();
	return 0;
}

static int
setup(void **state)
{
	agent_test_setup();

	agent_register_payload(DEPLOYMENT_MANIFEST_1, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_DEPLOYMENT_MANIFEST_1);
	agent_register_payload(INSTANCE_CONFIG_1, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_INSTANCE_CONFIG_1);
	agent_register_payload(DEPLOYMENT_MANIFEST_1, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_DEPLOYMENT_MANIFEST_1);
	agent_register_payload(EMPTY_DEPLOYMENT_MANIFEST_1,
			       EVP_HUB_TYPE_EVP2_TB,
			       EVP2_EMPTY_DEPLOYMENT_MANIFEST_1);
	agent_register_payload(EMPTY_DEPLOYMENT_MANIFEST_1,
			       EVP_HUB_TYPE_EVP1_TB,
			       EVP1_EMPTY_DEPLOYMENT_MANIFEST_1);
	agent_register_payload(INSTANCE_CONFIG_1, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_INSTANCE_CONFIG_1);
	return 0;
}

int
main(void)
{
	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_python_mod_telemetry_echo2),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup, teardown);
}
