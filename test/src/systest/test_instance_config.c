/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

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

enum test_instance_config_payloads {
	DEPLOYMENT_MANIFEST_1,
	INSTANCE_CONFIG_1
};

#define TEST_DEPLOYMENT_ID1 "2dc1a1c3-531b-4693-abba-a4a039bb827d"
#define TEST_INSTANCE_ID1   "07fe77d5-7117-4326-9042-47fda5dd9bf5"

#define EVP1_DEPLOYMENT_MANIFEST_1                                            \
	"\"{ "                                                                \
	"        \\\"deploymentId\\\": "                                      \
	"\\\"" TEST_DEPLOYMENT_ID1 "\\\","                                    \
	"        \\\"instanceSpecs\\\": {"                                    \
	"            \\\" " TEST_INSTANCE_ID1 " \\\": {"                      \
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

#define EVP1_INSTANCE_CONFIG_1                                                \
	"{"                                                                   \
	"	\"configuration/ " TEST_INSTANCE_ID1 " /"                     \
	"test_topic\": \"dGhpcyBpcyBhbiBpbml0aWFsIHZhbHVl\""                  \
	"}"

#define EVP2_DEPLOYMENT_MANIFEST_1                                            \
	"{"                                                                   \
	"        \"deploymentId\": \"" TEST_DEPLOYMENT_ID1 "\","              \
	"        \"instanceSpecs\": {"                                        \
	"            \" " TEST_INSTANCE_ID1 " \": {"                          \
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

#define EVP2_INSTANCE_CONFIG_1                                                \
	"{"                                                                   \
	"	\"configuration/ " TEST_INSTANCE_ID1 " /"                     \
	"test_topic\": \"this is an initial value\""                          \
	"}"

static void
cfg_request_cb(const char *topic, const void *config, size_t configlen,
	       void *userData)
{
	check_expected(topic);
	check_expected(config);
	check_expected(configlen);
	check_expected(userData);
}

void
test_instance_config(void **state)
{
	// start agent
	struct evp_agent_context *ctxt = agent_test_start();
	assert_non_null(ctxt);
	struct agent_deployment d = {.ctxt = ctxt};

	// create backdoor instance
	EVP_RESULT result;
	struct EVP_client *sdk_handle =
		evp_agent_add_instance(ctxt, "backdoor-mdc");
	assert_non_null(sdk_handle);
	result =
		EVP_setConfigurationCallback(sdk_handle, cfg_request_cb, NULL);
	assert_int_equal(result, EVP_OK);

	// deploy
	agent_ensure_deployment(&d, agent_get_payload(DEPLOYMENT_MANIFEST_1),
				TEST_DEPLOYMENT_ID1);

	// send instance config
	agent_send_instance_config(ctxt, agent_get_payload(INSTANCE_CONFIG_1));

	// verify request callback
	expect_string(cfg_request_cb, topic, "test_topic");
	/*
	 * "dGhpcyBpcyBhbiBpbml0aWFsIHZhbHVl" is the base64
	 * encoded string for "this is an initial value"
	 */
	expect_memory(cfg_request_cb, config, "this is an initial value", 24);
	expect_value(cfg_request_cb, configlen, 24);
	expect_value(cfg_request_cb, userData, NULL);
	result = EVP_processEvent(sdk_handle, 1000);
	assert_int_equal(result, EVP_OK);

	// ensure that EVP_setConfigurationCallback returns EVP_ERROR when
	// called twice
	result =
		EVP_setConfigurationCallback(sdk_handle, cfg_request_cb, NULL);
	assert_int_equal(result, EVP_ERROR);
}

int
setup(void **state)
{
	agent_test_setup();

	// EVP1
	agent_register_payload(DEPLOYMENT_MANIFEST_1, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_DEPLOYMENT_MANIFEST_1);
	agent_register_payload(INSTANCE_CONFIG_1, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_INSTANCE_CONFIG_1);

	// EVP2
	agent_register_payload(DEPLOYMENT_MANIFEST_1, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_DEPLOYMENT_MANIFEST_1);
	agent_register_payload(INSTANCE_CONFIG_1, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_INSTANCE_CONFIG_1);
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
		cmocka_unit_test(test_instance_config),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup, teardown);
}
