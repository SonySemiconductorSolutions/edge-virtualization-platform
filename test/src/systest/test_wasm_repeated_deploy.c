/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <evp/sdk.h>
#include <parson.h>

#include <internal/util.h>

#include "agent_internal.h"
#include "agent_test.h"
#include "hub.h"
#include "module_instance.h"
#include "mqtt_custom.h"

enum { DEPLOYMENT_MANIFEST, EMPTY_DEPLOYMENT_MANIFEST };

#define TEST_EMPTY_DEPLOYMENT_ID1 "d2862453-f57e-4ddb-90d2-d470c27f6a92"
#define TEST_DEPLOYMENT_ID1       "4fa905ae-e103-46ab-a8b9-73be07599708"

#define CONFIG_ECHO_INSTANCE_ID "10709a54-1d35-4955-b087-2380863f7eea"
#define CONFIG_ECHO_MODULE_ID   "0329dea0-bd16-4e8a-be29-cd415c1a10ff"
#define CONFIG_ECHO_MODULE_PATH "../test_modules/config_echo.wasm"
#define CONFIG_ECHO_MODULE_HASH                                               \
	"579fca500ec9f67a661e8b1a3a59a114a97029c46776d6ad9502fb183f1a1f7d"

#define EVP1_DEPLOYMENT_MANIFEST_1                                            \
	"\"{ "                                                                \
	"        \\\"deploymentId\\\": "                                      \
	"\\\"" TEST_DEPLOYMENT_ID1 "\\\","                                    \
	"        \\\"instanceSpecs\\\": {"                                    \
	"            \\\"" CONFIG_ECHO_INSTANCE_ID "\\\": {"                  \
	"                \\\"moduleId\\\": "                                  \
	"\\\"" CONFIG_ECHO_MODULE_ID "\\\","                                  \
	"                \\\"entryPoint\\\": \\\"main\\\","                   \
	"                \\\"version\\\": 1,"                                 \
	"                \\\"publish\\\": {},"                                \
	"                \\\"subscribe\\\": {}"                               \
	"            }"                                                       \
	"        },"                                                          \
	"        \\\"modules\\\": {"                                          \
	"            \\\"" CONFIG_ECHO_MODULE_ID "\\\": {"                    \
	"                \\\"moduleImpl\\\": \\\"wasm\\\","                   \
	"                \\\"downloadUrl\\\": \\\"file://%s\\\","             \
	"                \\\"hash\\\": \\\"" CONFIG_ECHO_MODULE_HASH "\\\""   \
	"            }"                                                       \
	"        },"                                                          \
	"        \\\"publishTopics\\\": {},"                                  \
	"        \\\"subscribeTopics\\\": {}"                                 \
	"}\""

#define EVP2_DEPLOYMENT_MANIFEST_1                                            \
	"{"                                                                   \
	"    \"deploymentId\": \"" TEST_DEPLOYMENT_ID1 "\","                  \
	"    \"instanceSpecs\": {"                                            \
	"        \"" CONFIG_ECHO_INSTANCE_ID "\": {"                          \
	"            \"moduleId\": \"" CONFIG_ECHO_MODULE_ID "\","            \
	"            \"publish\": {},"                                        \
	"            \"subscribe\": {}"                                       \
	"        }"                                                           \
	"    },"                                                              \
	"    \"modules\": {"                                                  \
	"        \"" CONFIG_ECHO_MODULE_ID "\": {"                            \
	"            \"downloadUrl\": \"file://%s\","                         \
	"            \"entryPoint\": \"main\","                               \
	"            \"hash\": \"" CONFIG_ECHO_MODULE_HASH "\","              \
	"            \"moduleImpl\": \"wasm\""                                \
	"        }"                                                           \
	"    },"                                                              \
	"    \"publishTopics\": {},"                                          \
	"    \"subscribeTopics\": {}"                                         \
	"}"

#define EVP1_EMPTY_DEPLOYMENT_MANIFEST_1                                      \
	"\"{ "                                                                \
	"        \\\"deploymentId\\\": "                                      \
	"\\\"" TEST_EMPTY_DEPLOYMENT_ID1 "\\\","                              \
	"        \\\"instanceSpecs\\\": {},"                                  \
	"        \\\"modules\\\": {},"                                        \
	"        \\\"publishTopics\\\": {},"                                  \
	"        \\\"subscribeTopics\\\": {}"                                 \
	"}\""

#define EVP2_EMPTY_DEPLOYMENT_MANIFEST_1                                      \
	"{"                                                                   \
	"        \"deploymentId\": \"" TEST_EMPTY_DEPLOYMENT_ID1 "\","        \
	"        \"instanceSpecs\": {},"                                      \
	"        \"modules\": {},"                                            \
	"        \"publishTopics\": {},"                                      \
	"        \"subscribeTopics\": {}"                                     \
	"}"

static void
test_wasm_mod_repeated_deploy(void **state)
{
	struct agent_deployment *d = *state;
	const char *iot = getenv("EVP_IOT_PLATFORM");
	assert_non_null(iot);

	for (int i = 0; i < 5; i++) {
		fprintf(stderr, "%s: iteration %d\n", __func__, i);

		agent_ensure_deployment(d,
					agent_get_payload(DEPLOYMENT_MANIFEST),
					TEST_DEPLOYMENT_ID1);
		agent_ensure_deployment(
			d, agent_get_payload(EMPTY_DEPLOYMENT_MANIFEST),
			TEST_EMPTY_DEPLOYMENT_ID1);
	}
}

static char *evp1_deployment1;
static char *evp2_deployment1;

static int
teardown(void **state)
{
	// wait for agent to finish
	agent_test_exit();

	free(evp1_deployment1);
	free(evp2_deployment1);
	return 0;
}

static int
setup(void **state)
{
	agent_test_setup();

	struct evp_agent_context *ctxt = agent_test_start();

	if (ctxt == NULL) {
		fprintf(stderr, "%s: agent_test_start failed\n", __func__);
		return -1;
	}

	static struct agent_deployment d;

	d = (struct agent_deployment){.ctxt = ctxt};

	*state = &d;

	xasprintf(&evp1_deployment1, EVP1_DEPLOYMENT_MANIFEST_1,
		  CONFIG_ECHO_MODULE_PATH);
	xasprintf(&evp2_deployment1, EVP2_DEPLOYMENT_MANIFEST_1,
		  CONFIG_ECHO_MODULE_PATH);

	agent_register_payload(DEPLOYMENT_MANIFEST, EVP_HUB_TYPE_EVP1_TB,
			       evp1_deployment1);
	agent_register_payload(DEPLOYMENT_MANIFEST, EVP_HUB_TYPE_EVP2_TB,
			       evp2_deployment1);

	agent_register_payload(EMPTY_DEPLOYMENT_MANIFEST, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_EMPTY_DEPLOYMENT_MANIFEST_1);
	agent_register_payload(EMPTY_DEPLOYMENT_MANIFEST, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_EMPTY_DEPLOYMENT_MANIFEST_1);

	return 0;
}

int
main(void)
{
	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_wasm_mod_repeated_deploy),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup, teardown);
}
