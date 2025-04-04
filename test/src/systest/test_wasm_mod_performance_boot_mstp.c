/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE
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
#include "xlog.h"

enum test_wasm_config_echo_payloads {
	DEPLOYMENT_MANIFEST_1,
	INSTANCE_CONFIG_1,
	MSTP_REQUEST_TOPIC_1,
	MSTP_RESPONSE_1,
	EMPTY_DEPLOYMENT_MANIFEST_1,
};

#define TEST_DEPLOYMENT_ID1       "4fa905ae-e103-46ab-a8b9-73be07599708"
#define TEST_EMPTY_DEPLOYMENT_ID1 "4fa905ae-e103-46ab-a8b9-73be07599709"
#define TEST_INSTANCE_ID1         "b218f90b-9228-423f-8e02-000000000001"

#define TOPIC_STORAGE_NAME_DEF_KEY        "storage_name_def"
#define TOPIC_STORAGE_NAME_DEF_VALUE_EVP1 "c3RvcmFnZV9kYXRhCg=="
#define TOPIC_STORAGE_NAME_DEF_VALUE_EVP2 "storage_data"

#define MSG_FMT_MSTP_REQUEST_TOPIC_1 "v1/devices/me/rpc/request/%s"

#define MODULE_PATH "../test_modules/performance_boot_mstp.wasm"

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
	"	\"configuration/" TEST_INSTANCE_ID1                           \
	"/" TOPIC_STORAGE_NAME_DEF_KEY                                        \
	"\": \"" TOPIC_STORAGE_NAME_DEF_VALUE_EVP1 "\""                       \
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

#define EVP2_INSTANCE_CONFIG_1                                                \
	"{"                                                                   \
	"	\"configuration/" TEST_INSTANCE_ID1                           \
	"/" TOPIC_STORAGE_NAME_DEF_KEY                                        \
	"\": \"" TOPIC_STORAGE_NAME_DEF_VALUE_EVP2 "\""                       \
	"}"

#define REQID_FMT    "%s"
#define SOME_SAS_URL "my_sas_testing"

#define EVP1_MSTP_RESPONSE_1                                                  \
	"{"                                                                   \
	"\"method\":\"StorageToken\","                                        \
	"\"params\":{"                                                        \
	"\"URL\":\"" SOME_SAS_URL "\","                                       \
	"\"headers\":{\"x-ms-blob-type\":"                                    \
	"\"BlockBlob\"},"                                                     \
	"\"cert\":\"56176780-9747-11ed-9bd5-"                                 \
	"5f138e81521e\""                                                      \
	"}"                                                                   \
	"}"

#define EVP2_MSTP_RESPONSE_1                                                  \
	"{"                                                                   \
	"\"storagetoken-response\":{"                                         \
	"\"reqid\":\"" REQID_FMT "\","                                        \
	"\"status\":\"ok\","                                                  \
	"\"URL\":\"" SOME_SAS_URL "\","                                       \
	"\"headers\":{\"x-ms-blob-type\":"                                    \
	"\"BlockBlob\"}"                                                      \
	"}"                                                                   \
	"}"

enum MQTTErrors
__wrap_mqtt_publish(struct mqtt_client *client, const char *topic_name,
		    const void *application_message,
		    size_t application_message_size, uint8_t publish_flags)
{
	agent_write_to_pipe(topic_name);
	char *payload = xstrndup((char *)application_message,
				 application_message_size);
	xlog_info("MQTT publish %s: %s", topic_name, payload);
	agent_write_to_pipe(payload);
	free(payload);
	return MQTT_OK;
}

/*
 * The goal of this test is validate the module MODULE_PATH
 * Send the storageName (key) configuration, and wait for a mSTP blob operation
 * TODO: When the stop/start agent inside a ST is supported it should test that
 * the mstp action is done just after restarting the module
 */
void
test_wasm_mod_performance_boot_mstp(void **state)
{
	// start agent
	struct evp_agent_context *ctxt = agent_test_start();
	struct agent_deployment d = {.ctxt = ctxt};

	// deploy
	agent_ensure_deployment(&d, agent_get_payload(DEPLOYMENT_MANIFEST_1),
				TEST_DEPLOYMENT_ID1);

	// send config
	agent_send_instance_config(ctxt, agent_get_payload(INSTANCE_CONFIG_1));

	// Wait for the rpc request and get the reqid from topic (compatible
	// between EVP1 and EVP2)
	char *msg;
	uintmax_t reqid;
	msg = agent_poll_fetch(verify_contains, "v1/devices/me/rpc/request/");
	assert_int_equal(sscanf(msg, "v1/devices/me/rpc/request/%ju", &reqid),
			 1);
	assert_non_null(msg);
	free(msg);

	// Send the RPC response
	char *reqid_str;
	asprintf(&reqid_str, "%ju", reqid);

	char *payload =
		agent_get_payload_formatted(MSTP_RESPONSE_1, reqid_str);
	agent_send_storagetoken_response(ctxt, payload, reqid_str);
	free(reqid_str);
	free(payload);

	// wait for the http request
	agent_poll(verify_equals, "PUT " SOME_SAS_URL);
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
	// Deployment mannifest
	agent_register_payload(DEPLOYMENT_MANIFEST_1, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_DEPLOYMENT_MANIFEST_1);
	agent_register_payload(DEPLOYMENT_MANIFEST_1, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_DEPLOYMENT_MANIFEST_1);

	agent_register_payload(MSTP_RESPONSE_1, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_MSTP_RESPONSE_1);
	agent_register_payload(MSTP_RESPONSE_1, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_MSTP_RESPONSE_1);

	// configuration
	agent_register_payload(INSTANCE_CONFIG_1, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_INSTANCE_CONFIG_1);
	agent_register_payload(INSTANCE_CONFIG_1, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_INSTANCE_CONFIG_1);

	// Empty Deployment
	agent_register_payload(EMPTY_DEPLOYMENT_MANIFEST_1,
			       EVP_HUB_TYPE_EVP1_TB,
			       EVP1_EMPTY_DEPLOYMENT_MANIFEST_1);
	agent_register_payload(EMPTY_DEPLOYMENT_MANIFEST_1,
			       EVP_HUB_TYPE_EVP2_TB,
			       EVP2_EMPTY_DEPLOYMENT_MANIFEST_1);

	return 0;
}

int
main(void)
{
	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_wasm_mod_performance_boot_mstp),
	};

	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup, teardown);
}
