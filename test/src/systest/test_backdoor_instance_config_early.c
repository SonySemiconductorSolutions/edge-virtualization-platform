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
#include "fsutil.h"
#include "hub.h"
#include "module_instance.h"
#include "mqtt_custom.h"
#include "path.h"

enum test_instance_config_payloads {
	DEPLOYMENT_MANIFEST,
	INSTANCE_CONFIG,
};

#define BACKDOOR1_ENTRYPOINT  "backdoor-EA_Main"
#define BACKDOOR1_INSTANCE_ID "b218f90b-9228-423f-8e02-aa107c47a9e9"

#define BACKDOOR2_ENTRYPOINT  "backdoor-EA_UD"
#define BACKDOOR2_INSTANCE_ID "b218f90b-9228-423f-8e02-aa107c47a9ea"

#define DEPLOYMENT_ID       "98368966-92e4-4312-a9cd-1a03b09b9c92"
#define EMPTY_DEPLOYMENT_ID "8543e017-2d93-444b-bd4c-bcaa39c46095"

#define TOPIC "test_topic"

static const char *evp2_deployment_manifest =
	"{ "
	"        \"deploymentId\": \"" DEPLOYMENT_ID "\","
	"        \"instanceSpecs\": {"
	"            \"" BACKDOOR1_INSTANCE_ID "\": {"
	"                \"moduleId\": "
	"\"b218f90b-9228-423f-8e02-a6d3527bc15d\","
	"                \"publish\": {},"
	"                \"subscribe\": {}"
	"            },"
	"            \"" BACKDOOR2_INSTANCE_ID "\": {"
	"                \"moduleId\": "
	"\"b218f90b-9228-423f-8e02-a6d3527bc15e\","
	"                \"publish\": {},"
	"                \"subscribe\": {}"
	"            }"
	"        },"
	"        \"modules\": {"
	"            \"b218f90b-9228-423f-8e02-a6d3527bc15d\": {"
	"                \"entryPoint\": \"" BACKDOOR1_ENTRYPOINT "\","
	"                \"moduleImpl\": \"spawn\","
	"                \"downloadUrl\": \"\","
	"                \"hash\": \"\""
	"            },"
	"            \"b218f90b-9228-423f-8e02-a6d3527bc15e\": {"
	"                \"entryPoint\": \"" BACKDOOR2_ENTRYPOINT "\","
	"                \"moduleImpl\": \"spawn\","
	"                \"downloadUrl\": \"\","
	"                \"hash\": \"\""
	"            }"
	"        },"
	"        \"publishTopics\": {},"
	"        \"subscribeTopics\": {}"
	"}";

static const char *evp2_instance_config =
	"	\"configuration/" BACKDOOR1_INSTANCE_ID "/"
	"" TOPIC "\": \"this is an initial value\"";

static const char *evp1_deployment_manifest =
	"\"{ "
	"        \\\"deploymentId\\\": "
	"\\\"" DEPLOYMENT_ID "\\\","
	"        \\\"instanceSpecs\\\": {},"
	"        \\\"modules\\\": {},"
	"        \\\"publishTopics\\\": {},"
	"        \\\"subscribeTopics\\\": {}"
	"}\"";

static const char *evp1_instance_config =
	"	\"configuration/" BACKDOOR1_ENTRYPOINT "/"
	"" TOPIC "\": \"dGhpcyBpcyBhbiBpbml0aWFsIHZhbHVl\"";

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
test_backdoor_instance_config_early(void **state)
{
	// start agent
	struct evp_agent_context *ctxt = agent_test_start();
	struct agent_deployment d = {.ctxt = ctxt};

	// create backdoor instance
	EVP_RESULT result;
	struct EVP_client *sdk_handle_1 =
		evp_agent_add_instance(ctxt, BACKDOOR1_ENTRYPOINT);
	assert_non_null(sdk_handle_1);
	struct EVP_client *sdk_handle_2 =
		evp_agent_add_instance(ctxt, BACKDOOR2_ENTRYPOINT);
	assert_non_null(sdk_handle_2);

	// set config callback
	result = EVP_setConfigurationCallback(sdk_handle_1, cfg_request_cb,
					      NULL);
	assert_int_equal(result, EVP_OK);

	// ensure that EVP_setConfigurationCallback returns EVP_ERROR when
	// called twice
	result = EVP_setConfigurationCallback(sdk_handle_1, cfg_request_cb,
					      NULL);
	assert_int_equal(result, EVP_ERROR);

	// Wait for a periodic report to be sure that the backdoor instances
	// are running
	agent_poll(verify_contains, BACKDOOR1_ENTRYPOINT);

	// Send deployment and configuration together
	agent_ensure_deployment_config(
		&d, agent_get_payload(DEPLOYMENT_MANIFEST), DEPLOYMENT_ID,
		agent_get_payload(INSTANCE_CONFIG));

	// verify request callback
	expect_string(cfg_request_cb, topic, TOPIC);
	/*
	 * "dGhpcyBpcyBhbiBpbml0aWFsIHZhbHVl" is the base64
	 * encoded string for "this is an initial value"
	 */
	expect_memory(cfg_request_cb, config, "this is an initial value", 24);
	expect_value(cfg_request_cb, configlen, 24);
	expect_value(cfg_request_cb, userData, NULL);
	result = EVP_processEvent(sdk_handle_1, 1000);
	assert_int_equal(result, EVP_OK);

	// check the desired file to make sure the config is not included
	const char *desired_path = path_get(DESIRED_TWINS_PATH_ID);

	char *json_str = NULL;
	size_t sz;
	json_str = read_file(desired_path, &sz, true);
	assert_non_null(json_str);

	// the topic must not be found in the desired database
	char *substr = strstr(json_str, TOPIC);
	assert_null(substr);

	free(json_str);
}

int
setup(void **state)
{
	// be sure that the periodic report is send every 3 seconds
	putenv("EVP_REPORT_STATUS_INTERVAL_MAX_SEC=3");
	agent_test_setup();

	// EVP1
	agent_register_payload(DEPLOYMENT_MANIFEST, EVP_HUB_TYPE_EVP1_TB,
			       evp1_deployment_manifest);
	agent_register_payload(INSTANCE_CONFIG, EVP_HUB_TYPE_EVP1_TB,
			       evp1_instance_config);

	// EVP2
	agent_register_payload(DEPLOYMENT_MANIFEST, EVP_HUB_TYPE_EVP2_TB,
			       evp2_deployment_manifest);
	agent_register_payload(INSTANCE_CONFIG, EVP_HUB_TYPE_EVP2_TB,
			       evp2_instance_config);
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
		cmocka_unit_test(test_backdoor_instance_config_early),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup, teardown);
}
