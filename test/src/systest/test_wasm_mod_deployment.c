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
#include "module.h"
#include "module_instance.h"
#include "mqtt_custom.h"

enum test_wasm_config_echo_payloads {
	DEPLOYMENT_MANIFEST_1,
	DEPLOYMENT_MANIFEST_2,
	EMPTY_DEPLOYMENT_MANIFEST_1,
	JSON_STATUS_CHECK,
};

#define TEST_DEPLOYMENT_ID1       "deployment-1"
#define TEST_DEPLOYMENT_ID2       "deployment-2"
#define TEST_EMPTY_DEPLOYMENT_ID1 "empty-deployment"
#define TEST_INSTANCE_ID1         "instance-001"
#define TEST_INSTANCE_ID2         "instance-002"
#define TEST_INSTANCE_ID3         "instance-003"
#define MODULE_ID1                "backdoor"
#define MODULE_ID2                "module-A"
#define MODULE_ID3                "module-B"

#define MODULE_PATH "../test_modules/config_echo.wasm"
#define MODULE_URL  "file://" MODULE_PATH
#define MODULE_HASH                                                           \
	"579fca500ec9f67a661e8b1a3a59a114a97029c46776d6ad9502fb183f1a1f7d"

#define EVP1_JSON_STATUS_CHECK "deploymentStatus=#{reconcileStatus=%s"
#define TB_JSON_STATUS_CHECK   "deploymentStatus.reconcileStatus=%s"

#define EVP1_DEPLOYMENT_MANIFEST_1                                            \
	"\"{"                                                                 \
	"        \\\"deploymentId\\\": \\\"" TEST_DEPLOYMENT_ID1 "\\\","      \
	"        \\\"instanceSpecs\\\": {"                                    \
	"            \\\"" TEST_INSTANCE_ID1 "\\\": {"                        \
	"                \\\"moduleId\\\": \\\"" MODULE_ID1 "\\\","           \
	"                \\\"entryPoint\\\": \\\"backdoor-test\\\","          \
	"                \\\"version\\\": 1,"                                 \
	"                \\\"publish\\\": {},"                                \
	"                \\\"subscribe\\\": {}"                               \
	"            },"                                                      \
	"            \\\"" TEST_INSTANCE_ID2 "\\\": {"                        \
	"                \\\"moduleId\\\": \\\"" MODULE_ID2 "\\\","           \
	"                \\\"entryPoint\\\": \\\"main\\\","                   \
	"                \\\"version\\\": 1,"                                 \
	"                \\\"publish\\\": {},"                                \
	"                \\\"subscribe\\\": {}"                               \
	"            }"                                                       \
	"        },"                                                          \
	"        \\\"modules\\\": {"                                          \
	"            \\\"" MODULE_ID1 "\\\": {"                               \
	"                \\\"moduleImpl\\\": \\\"spawn\\\","                  \
	"                \\\"downloadUrl\\\": \\\"\\\","                      \
	"                \\\"hash\\\": \\\"\\\""                              \
	"            },"                                                      \
	"            \\\"" MODULE_ID2 "\\\": {"                               \
	"                \\\"moduleImpl\\\": \\\"wasm\\\","                   \
	"                \\\"downloadUrl\\\": \\\"" MODULE_URL "\\\","        \
	"                \\\"hash\\\": \\\"" MODULE_HASH "\\\""               \
	"            }"                                                       \
	"        },"                                                          \
	"        \\\"publishTopics\\\": {},"                                  \
	"        \\\"subscribeTopics\\\": {}"                                 \
	"}\""

#define EVP1_DEPLOYMENT_MANIFEST_2                                            \
	"\"{ "                                                                \
	"        \\\"deploymentId\\\": \\\"" TEST_DEPLOYMENT_ID2 "\\\","      \
	"        \\\"instanceSpecs\\\": {"                                    \
	"            \\\"" TEST_INSTANCE_ID1 "\\\": {"                        \
	"                \\\"moduleId\\\": \\\"" MODULE_ID1 "\\\","           \
	"                \\\"entryPoint\\\": \\\"backdoor-test\\\","          \
	"                \\\"version\\\": 1,"                                 \
	"                \\\"publish\\\": {},"                                \
	"                \\\"subscribe\\\": {}"                               \
	"            },"                                                      \
	"            \\\"" TEST_INSTANCE_ID3 "\\\": {"                        \
	"                \\\"moduleId\\\": \\\"" MODULE_ID3 "\\\","           \
	"                \\\"entryPoint\\\": \\\"main\\\","                   \
	"                \\\"version\\\": 1,"                                 \
	"                \\\"publish\\\": {},"                                \
	"                \\\"subscribe\\\": {}"                               \
	"            }"                                                       \
	"        },"                                                          \
	"        \\\"modules\\\": {"                                          \
	"            \\\"" MODULE_ID1 "\\\": {"                               \
	"                \\\"moduleImpl\\\": \\\"spawn\\\","                  \
	"                \\\"downloadUrl\\\": \\\"\\\","                      \
	"                \\\"hash\\\": \\\"\\\""                              \
	"            },"                                                      \
	"            \\\"" MODULE_ID3 "\\\": {"                               \
	"                \\\"moduleImpl\\\": \\\"wasm\\\","                   \
	"                \\\"downloadUrl\\\": \\\"" MODULE_URL "\\\","        \
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
	"                \"moduleId\": \"" MODULE_ID1 "\","                   \
	"                \"publish\": {},"                                    \
	"                \"subscribe\": {}"                                   \
	"            },"                                                      \
	"            \"" TEST_INSTANCE_ID2 "\": {"                            \
	"                \"moduleId\": \"" MODULE_ID2 "\","                   \
	"                \"publish\": {},"                                    \
	"                \"subscribe\": {}"                                   \
	"            }"                                                       \
	"        },"                                                          \
	"        \"modules\": {"                                              \
	"            \"" MODULE_ID1 "\": {"                                   \
	"                \"entryPoint\": \"backdoor-test\","                  \
	"                \"moduleImpl\": \"spawn\","                          \
	"                \"downloadUrl\": \"\","                              \
	"                \"hash\": \"\""                                      \
	"            },"                                                      \
	"            \"" MODULE_ID2 "\": {"                                   \
	"                \"entryPoint\": \"main\","                           \
	"                \"moduleImpl\": \"wasm\","                           \
	"                \"downloadUrl\": \"" MODULE_URL "\","                \
	"                \"hash\": \"" MODULE_HASH "\""                       \
	"            }"                                                       \
	"        },"                                                          \
	"        \"publishTopics\": {},"                                      \
	"        \"subscribeTopics\": {}"                                     \
	"}"

#define EVP2_DEPLOYMENT_MANIFEST_2                                            \
	"{"                                                                   \
	"        \"deploymentId\": \"" TEST_DEPLOYMENT_ID2 "\","              \
	"        \"instanceSpecs\": {"                                        \
	"            \"" TEST_INSTANCE_ID1 "\": {"                            \
	"                \"moduleId\": \"" MODULE_ID1 "\","                   \
	"                \"publish\": {},"                                    \
	"                \"subscribe\": {}"                                   \
	"            },"                                                      \
	"            \"" TEST_INSTANCE_ID3 "\": {"                            \
	"                \"moduleId\": \"" MODULE_ID3 "\","                   \
	"                \"publish\": {},"                                    \
	"                \"subscribe\": {}"                                   \
	"            }"                                                       \
	"        },"                                                          \
	"        \"modules\": {"                                              \
	"            \"" MODULE_ID1 "\": {"                                   \
	"                \"entryPoint\": \"backdoor-test\","                  \
	"                \"moduleImpl\": \"spawn\","                          \
	"                \"downloadUrl\": \"\","                              \
	"                \"hash\": \"\""                                      \
	"            },"                                                      \
	"            \"" MODULE_ID3 "\": {"                                   \
	"                \"entryPoint\": \"main\","                           \
	"                \"moduleImpl\": \"wasm\","                           \
	"                \"downloadUrl\": \"" MODULE_URL "\","                \
	"                \"hash\": \"" MODULE_HASH "\""                       \
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

void
wasm_modules_get_unloaded_with_backdoor(void **state)
{
	struct evp_agent_context *ctxt = *state;
	struct agent_deployment d = {.ctxt = ctxt};

	// deploy
	agent_ensure_deployment(&d, agent_get_payload(DEPLOYMENT_MANIFEST_1),
				TEST_DEPLOYMENT_ID1);

	assert_non_null(module_ops(MODULE_ID1)); // Backdoor
	assert_non_null(module_ops(MODULE_ID2));
	assert_null(module_ops(MODULE_ID3));

	// send new deployment
	agent_ensure_deployment(&d, agent_get_payload(DEPLOYMENT_MANIFEST_2),
				TEST_DEPLOYMENT_ID2);

	assert_non_null(module_ops(MODULE_ID1)); // Backdoor
	assert_null(module_ops(MODULE_ID2));
	assert_non_null(module_ops(MODULE_ID3));

	// send empty deployment
	agent_ensure_deployment(&d,
				agent_get_payload(EMPTY_DEPLOYMENT_MANIFEST_1),
				TEST_EMPTY_DEPLOYMENT_ID1);

	assert_null(module_ops(MODULE_ID1)); // Backdoor
	assert_null(module_ops(MODULE_ID2));
	assert_null(module_ops(MODULE_ID3));

	// send new deployment
	agent_ensure_deployment(&d, agent_get_payload(DEPLOYMENT_MANIFEST_2),
				TEST_DEPLOYMENT_ID2);

	assert_non_null(module_ops(MODULE_ID1)); // Backdoor
	assert_null(module_ops(MODULE_ID2));
	assert_non_null(module_ops(MODULE_ID3));

	// send empty deployment
	agent_ensure_deployment(&d,
				agent_get_payload(EMPTY_DEPLOYMENT_MANIFEST_1),
				TEST_EMPTY_DEPLOYMENT_ID1);

	assert_null(module_ops(MODULE_ID1)); // Backdoor
	assert_null(module_ops(MODULE_ID2));
	assert_null(module_ops(MODULE_ID3));
}

static int
setup(void **state)
{
	agent_test_setup();

	/* EVP1 */
	agent_register_payload(EMPTY_DEPLOYMENT_MANIFEST_1,
			       EVP_HUB_TYPE_EVP1_TB,
			       EVP1_EMPTY_DEPLOYMENT_MANIFEST_1);
	agent_register_payload(DEPLOYMENT_MANIFEST_1, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_DEPLOYMENT_MANIFEST_1);
	agent_register_payload(DEPLOYMENT_MANIFEST_2, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_DEPLOYMENT_MANIFEST_2);

	/* EVP2 */
	agent_register_payload(EMPTY_DEPLOYMENT_MANIFEST_1,
			       EVP_HUB_TYPE_EVP2_TB,
			       EVP2_EMPTY_DEPLOYMENT_MANIFEST_1);
	agent_register_payload(DEPLOYMENT_MANIFEST_1, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_DEPLOYMENT_MANIFEST_1);
	agent_register_payload(DEPLOYMENT_MANIFEST_2, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_DEPLOYMENT_MANIFEST_2);

	// start agent
	struct evp_agent_context *ctxt = agent_test_start();

	struct EVP_client *h = evp_agent_add_instance(ctxt, "backdoor-test");
	assert_non_null(h);

	*state = ctxt;
	return 0;
}

static int
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
		cmocka_unit_test(wasm_modules_get_unloaded_with_backdoor),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup, teardown);
}
