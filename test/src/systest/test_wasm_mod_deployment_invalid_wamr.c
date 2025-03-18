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
#include "fsutil.h"
#include "hub.h"
#include "module_instance.h"
#include "mqtt_custom.h"
#include "path.h"

enum test_wasm_config_echo_payloads {
	DEPLOYMENT_MANIFEST_1,
	EMPTY_DEPLOYMENT_MANIFEST_1,
	INSTANCE_CONFIG_1,
	EXPECTED_STATE,
};

#define TEST_DEPLOYMENT_ID1       "4fa905ae-e103-46ab-a8b9-73be07599708"
#define TEST_EMPTY_DEPLOYMENT_ID1 "4fa905ae-e103-46ab-a8b9-73be07599709"
#define TEST_INSTANCE_ID1         "b218f90b-9228-423f-8e02-000000000001"

#define MODULE_PATH_AOT_AMD64_OLD                                             \
	"resources/invalid_wamr_modules/wamr_1.3.1_config_echo.wasm.x86_64"
#define MODULE_PATH MODULE_PATH_AOT_AMD64_OLD
#define DEPLOYMENT_STATUS_ERR_INVALID_WAMR_VER                                \
	"wasm_runtime_load failed with AOT module load failed: unexpected "   \
	"end"

#define MODULE_HASH                                                           \
	"579fca500ec9f67a661e8b1a3a59a114a97029c46776d6ad9502fb183f1a1f7d"

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
	"	\"configuration/" TEST_INSTANCE_ID1 "/" DUMMY_KEY             \
	"\": \"" EVP2_DUMMY_VALUE "\""                                        \
	"}"

/*
 * The goal of this test is to be sure that the agent report an error message
 * when the wasm aot module is build with a different version from the
 * supported one. See ADI-406
 */
void
test_wasm_mod_deployment_invalid_wamr_version(void **state)
{
	// start agent
	struct evp_agent_context *ctxt = agent_test_start();
	struct agent_deployment d = {.ctxt = ctxt};

	// deploy
	agent_send_initial(ctxt, agent_get_payload(DEPLOYMENT_MANIFEST_1),
			   NULL, NULL);

	agent_poll(verify_contains, DEPLOYMENT_STATUS_ERR_INVALID_WAMR_VER);
	d.init = true;

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

	return 0;
}

int
main(void)
{
	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(
			test_wasm_mod_deployment_invalid_wamr_version),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup, teardown);
}
