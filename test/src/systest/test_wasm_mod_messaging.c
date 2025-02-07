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

#include "webclient/webclient.h"

#include "agent_test.h"
#include "hub.h"
#include "module_instance.h"
#include "mqtt_custom.h"
#include "xlog.h"

enum test_wasm_http_ext_payloads {
	DEPLOYMENT_MANIFEST,
	EMPTY_DEPLOYMENT_MANIFEST,
	INSTANCE_CONFIG_RECEIVER,
	INSTANCE_CONFIG_SENDER,
	STATE_RECEIVER_STARTED,
	STATE_SENDER_STARTED,
	STATE_RECEIVER_CONFIGURED,
	STATE_RECEIVER_FINISHED,
	STATE_SENDER_FINISHED,
};

#define TEST_DEPLOYMENT_ID        "4fa905ae-e103-46ab-a8b9-73be07599708"
#define TEST_EMPTY_DEPLOYMENT_ID  "4fa905ae-e103-46ab-a8b9-73be07599709"
#define TEST_MODULE_MESSAGING_ID  "module-messaging-id-0000000000000000"
#define TEST_INSTANCE_RECEIVER_ID "instance-receiver-id-00-000000000001"
#define TEST_INSTANCE_SENDER_ID   "instance-sender-id-00-00000000000002"

/*
 * step = 0       Messaging module has been started
 * step = 1000    Messaging module has finished
 * step = 10000   Messaging module has been configured
 */
#define B64_G_STEP_0     "Z19zdGVwID0gMA=="
#define B64_G_STEP_1000  "Z19zdGVwID0gMTAwMA=="
#define B64_G_STEP_10000 "Z19zdGVwID0gMTAwMDA="

#define G_STEP_0     "g_step = 0"
#define G_STEP_1000  "g_step = 1000"
#define G_STEP_10000 "g_step = 10000"

#define EVP1_STATE_RECEIVER_STARTED                                           \
	"\"state/" TEST_INSTANCE_RECEIVER_ID "/status\":\"" B64_G_STEP_0 "\""

#define EVP1_STATE_SENDER_STARTED                                             \
	"\"state/" TEST_INSTANCE_SENDER_ID "/status\":\"" B64_G_STEP_0 "\""

#define EVP1_STATE_RECEIVER_CONFIGURED                                        \
	"\"state/" TEST_INSTANCE_RECEIVER_ID "/status\":\"" B64_G_STEP_10000  \
	"\""

#define EVP1_STATE_RECEIVER_FINISHED                                          \
	"\"state/" TEST_INSTANCE_RECEIVER_ID "/status\":\"" B64_G_STEP_1000   \
	"\""

#define EVP1_STATE_SENDER_FINISHED                                            \
	"\"state/" TEST_INSTANCE_SENDER_ID "/status\":\"" B64_G_STEP_1000 "\""

#define EVP2_STATE_RECEIVER_STARTED                                           \
	"\"state/" TEST_INSTANCE_RECEIVER_ID "/status\":\"" G_STEP_0 "\""

#define EVP2_STATE_SENDER_STARTED                                             \
	"\"state/" TEST_INSTANCE_SENDER_ID "/status\":\"" G_STEP_0 "\""

#define EVP2_STATE_RECEIVER_CONFIGURED                                        \
	"\"state/" TEST_INSTANCE_RECEIVER_ID "/status\":\"" G_STEP_10000 "\""

#define EVP2_STATE_RECEIVER_FINISHED                                          \
	"\"state/" TEST_INSTANCE_RECEIVER_ID "/status\":\"" G_STEP_1000 "\""

#define EVP2_STATE_SENDER_FINISHED                                            \
	"\"state/" TEST_INSTANCE_SENDER_ID "/status\":\"" G_STEP_1000 "\""

#define SALUTE_CONTENT            "this is a greeting"
#define SALUTE_CONTENT_B64        "dGhpcyBpcyBhIGdyZWV0aW5n"
#define SUBSCRIBE_TOPIC_FIELD     "receiver-topic"
#define SUBSCRIBE_TOPIC_FIELD_B64 "cmVjZWl2ZXItdG9waWM="
#define PUBLISH_TOPIC_FIELD       "sender-topic"
#define PUBLISH_TOPIC_FIELD_B64   "c2VuZGVyLXRvcGlj"

#define MODULE_PATH "../test_modules/messaging.wasm"
#define MODULE_HASH                                                           \
	"b34ecae0f7d010e18d4dd03ac9e8bf3e7d06e3b0cb65fd0d9f9a6bb9bfdc9c0f"
#define MODULE_ID "writer-wasm"

#define EVP1_DEPLOYMENT_MANIFEST                                              \
	"\"{ "                                                                \
	"        \\\"deploymentId\\\": "                                      \
	"\\\"" TEST_DEPLOYMENT_ID "\\\","                                     \
	"        \\\"instanceSpecs\\\": {"                                    \
	"            \\\"" TEST_INSTANCE_RECEIVER_ID "\\\": {"                \
	"                \\\"moduleId\\\": "                                  \
	"\\\"" TEST_MODULE_MESSAGING_ID "\\\","                               \
	"                \\\"entryPoint\\\": \\\"main\\\","                   \
	"                \\\"version\\\": 1,"                                 \
	"                \\\"publish\\\": {},"                                \
	"                \\\"subscribe\\\": {"                                \
	"                    \\\"" SUBSCRIBE_TOPIC_FIELD                      \
	"\\\": \\\"salute-subscription\\\""                                   \
	"                }"                                                   \
	"            },"                                                      \
	"            \\\"" TEST_INSTANCE_SENDER_ID "\\\": {"                  \
	"                \\\"moduleId\\\": "                                  \
	"\\\"" TEST_MODULE_MESSAGING_ID "\\\","                               \
	"                \\\"entryPoint\\\": \\\"main\\\","                   \
	"                \\\"version\\\": 1,"                                 \
	"                \\\"publish\\\": {"                                  \
	"                    \\\"" PUBLISH_TOPIC_FIELD                        \
	"\\\": \\\"salute-publication\\\""                                    \
	"                },"                                                  \
	"                \\\"subscribe\\\": {}"                               \
	"            }"                                                       \
	"        },"                                                          \
	"        \\\"modules\\\": {"                                          \
	"            \\\"" TEST_MODULE_MESSAGING_ID "\\\": {"                 \
	"                \\\"moduleImpl\\\": \\\"wasm\\\","                   \
	"                \\\"downloadUrl\\\": \\\"file://%s\\\","             \
	"                \\\"hash\\\": \\\"" MODULE_HASH "\\\""               \
	"            }"                                                       \
	"        },"                                                          \
	"        \\\"publishTopics\\\": {"                                    \
	"            \\\"salute-publication\\\": {"                           \
	"                \\\"type\\\": \\\"local\\\","                        \
	"                \\\"topic\\\": \\\"salute\\\""                       \
	"            }"                                                       \
	"        },"                                                          \
	"        \\\"subscribeTopics\\\": {"                                  \
	"           \\\"salute-subscription\\\": {"                           \
	"               \\\"type\\\": \\\"local\\\","                         \
	"               \\\"topic\\\": \\\"salute\\\""                        \
	"           }"                                                        \
	"        }"                                                           \
	"}\""

#define EVP2_DEPLOYMENT_MANIFEST                                              \
	"{ "                                                                  \
	"        \"deploymentId\": "                                          \
	"\"" TEST_DEPLOYMENT_ID "\","                                         \
	"        \"instanceSpecs\": {"                                        \
	"            \"" TEST_INSTANCE_RECEIVER_ID "\": {"                    \
	"                \"moduleId\": "                                      \
	"\"" TEST_MODULE_MESSAGING_ID "\","                                   \
	"                \"publish\": {},"                                    \
	"                \"subscribe\": {"                                    \
	"                    \"" SUBSCRIBE_TOPIC_FIELD                        \
	"\": \"salute-subscription\""                                         \
	"                }"                                                   \
	"            },"                                                      \
	"            \"" TEST_INSTANCE_SENDER_ID "\": {"                      \
	"                \"moduleId\": "                                      \
	"\"" TEST_MODULE_MESSAGING_ID "\","                                   \
	"                \"publish\": {"                                      \
	"                    \"" PUBLISH_TOPIC_FIELD                          \
	"\": \"salute-publication\""                                          \
	"                },"                                                  \
	"                \"subscribe\": {}"                                   \
	"            }"                                                       \
	"        },"                                                          \
	"        \"modules\": {"                                              \
	"            \"" TEST_MODULE_MESSAGING_ID "\": {"                     \
	"                \"moduleImpl\": \"wasm\","                           \
	"                \"entryPoint\": \"main\","                           \
	"                \"downloadUrl\": \"file://%s\","                     \
	"                \"hash\": \"" MODULE_HASH "\""                       \
	"            }"                                                       \
	"        },"                                                          \
	"        \"publishTopics\": {"                                        \
	"            \"salute-publication\": {"                               \
	"                \"type\": \"local\","                                \
	"                \"topic\": \"salute\""                               \
	"            }"                                                       \
	"        },"                                                          \
	"        \"subscribeTopics\": {"                                      \
	"           \"salute-subscription\": {"                               \
	"               \"type\": \"local\","                                 \
	"               \"topic\": \"salute\""                                \
	"           }"                                                        \
	"        }"                                                           \
	"}"

#define EVP1_EMPTY_DEPLOYMENT_MANIFEST                                        \
	"\"{ "                                                                \
	"        \\\"deploymentId\\\": "                                      \
	"\\\"" TEST_EMPTY_DEPLOYMENT_ID "\\\","                               \
	"        \\\"instanceSpecs\\\": {},"                                  \
	"        \\\"modules\\\": {},"                                        \
	"        \\\"publishTopics\\\": {},"                                  \
	"        \\\"subscribeTopics\\\": {}"                                 \
	"}\""

#define EVP2_EMPTY_DEPLOYMENT_MANIFEST                                        \
	"{"                                                                   \
	"        \"deploymentId\": \"" TEST_EMPTY_DEPLOYMENT_ID "\","         \
	"        \"instanceSpecs\": {},"                                      \
	"        \"modules\": {},"                                            \
	"        \"publishTopics\": {},"                                      \
	"        \"subscribeTopics\": {}"                                     \
	"}"

#define EVP1_INSTANCE_RECEIVER_CONFIG                                         \
	"{"                                                                   \
	"	\"configuration/" TEST_INSTANCE_RECEIVER_ID "/salute\": "     \
	"\"" SALUTE_CONTENT_B64 "\","                                         \
	"	\"configuration/" TEST_INSTANCE_RECEIVER_ID                   \
	"/subscribe_to\": "                                                   \
	"\"" SUBSCRIBE_TOPIC_FIELD_B64 "\""                                   \
	"}"

#define EVP1_INSTANCE_SENDER_CONFIG                                           \
	"{"                                                                   \
	"	\"configuration/" TEST_INSTANCE_SENDER_ID "/salute\": "       \
	"\"" SALUTE_CONTENT_B64 "\","                                         \
	"	\"configuration/" TEST_INSTANCE_SENDER_ID "/publish_to\": "   \
	"\"" PUBLISH_TOPIC_FIELD_B64 "\""                                     \
	"}"

#define EVP2_INSTANCE_RECEIVER_CONFIG                                         \
	"{"                                                                   \
	"	\"configuration/" TEST_INSTANCE_RECEIVER_ID "/salute\": "     \
	"\"" SALUTE_CONTENT "\","                                             \
	"	\"configuration/" TEST_INSTANCE_RECEIVER_ID                   \
	"/subscribe_to\": "                                                   \
	"\"" SUBSCRIBE_TOPIC_FIELD "\""                                       \
	"}"

#define EVP2_INSTANCE_SENDER_CONFIG                                           \
	"{"                                                                   \
	"	\"configuration/" TEST_INSTANCE_SENDER_ID "/salute\": "       \
	"\"" SALUTE_CONTENT "\","                                             \
	"	\"configuration/" TEST_INSTANCE_SENDER_ID "/publish_to\": "   \
	"\"" PUBLISH_TOPIC_FIELD "\""                                         \
	"}"

static char *deployment_evp1;
static char *deployment_evp2;

void
test_wasm_mod_messaging(void **state)
{
	xlog_info("Check that the messaging wasm interface works well.");
	xlog_info("The test deploys 2 modules, one (sender) publishes data "
		  "and the other one (receiver) subscribes to the same topic "
		  "and checks that the data is as expected (set by "
		  "configuraton API) .");
	// start agent
	struct evp_agent_context *ctxt = agent_test_start();
	struct agent_deployment d = {.ctxt = ctxt};

	// Deploy 2 instances (sender and receiver)
	agent_ensure_deployment(&d, agent_get_payload(DEPLOYMENT_MANIFEST),
				TEST_DEPLOYMENT_ID);

	// wait for module ready
	struct multi_check values_started[] = {
		{.value = agent_get_payload(STATE_RECEIVER_STARTED)},
		{.value = agent_get_payload(STATE_SENDER_STARTED)},
		{.value = NULL}, // List termination
	};
	agent_poll(verify_contains_in_unordered_set, values_started);

	/* Send receiver cofiguration, to config:
	 *  - the topic parameter to subscribe
	 *  - the expected value received (in sender the value is the same)
	 */
	agent_send_instance_config(
		ctxt, agent_get_payload(INSTANCE_CONFIG_RECEIVER));

	// Check that the receiver gets the config
	agent_poll(verify_contains,
		   agent_get_payload(STATE_RECEIVER_CONFIGURED));

	// config sender instance to publish the expected data to the topic
	// parameter
	agent_send_instance_config(ctxt,
				   agent_get_payload(INSTANCE_CONFIG_SENDER));

	/*
	 * At this point, the sender is publishing the data and finishes
	 * execution. When the instance finishes it sends the state "status =
	 * g_step_1000", the receiver is subscribed to the same topic, and it
	 * will check that the data is matching the expected one. After that,
	 * the receiver will report the finish valid state if the data matches
	 */
	struct multi_check values_finished[] = {
		{.value = agent_get_payload(STATE_SENDER_FINISHED)},
		{.value = agent_get_payload(STATE_RECEIVER_FINISHED)},
		{.value = NULL}, // List termination
	};
	agent_poll(verify_contains_in_unordered_set, values_finished);

	// send empty deployment
	agent_ensure_deployment(&d,
				agent_get_payload(EMPTY_DEPLOYMENT_MANIFEST),
				TEST_EMPTY_DEPLOYMENT_ID);
}

static int
teardown(void **state)
{
	agent_test_exit();
	free(deployment_evp1);
	free(deployment_evp2);

	return 0;
}

static int
setup(void **state)
{
	agent_test_setup();

	char *path = MODULE_PATH;
	char *abs_path;
	if (*path != '/') {
		abs_path = realpath(path, NULL);
	} else {
		abs_path = xstrdup(path);
	}

	xasprintf(&deployment_evp1, EVP1_DEPLOYMENT_MANIFEST, MODULE_PATH);
	xasprintf(&deployment_evp2, EVP2_DEPLOYMENT_MANIFEST, MODULE_PATH);
	free(abs_path);

	// DEPLOYMENT_MANIFEST - Deployment manifest
	agent_register_payload(DEPLOYMENT_MANIFEST, EVP_HUB_TYPE_EVP1_TB,
			       deployment_evp1);
	agent_register_payload(DEPLOYMENT_MANIFEST, EVP_HUB_TYPE_EVP2_TB,
			       deployment_evp2);

	// EMPTY_DEPLOYMENT_MANIFEST - The empty deployment manifest
	agent_register_payload(EMPTY_DEPLOYMENT_MANIFEST, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_EMPTY_DEPLOYMENT_MANIFEST);
	agent_register_payload(EMPTY_DEPLOYMENT_MANIFEST, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_EMPTY_DEPLOYMENT_MANIFEST);

	// INSTANCE_CONFIG_RECEIVER - Receiver configuration
	agent_register_payload(INSTANCE_CONFIG_RECEIVER, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_INSTANCE_RECEIVER_CONFIG);
	agent_register_payload(INSTANCE_CONFIG_RECEIVER, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_INSTANCE_RECEIVER_CONFIG);

	// INSTANCE_CONFIG_SENDER - Sender configuration
	agent_register_payload(INSTANCE_CONFIG_SENDER, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_INSTANCE_SENDER_CONFIG);
	agent_register_payload(INSTANCE_CONFIG_SENDER, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_INSTANCE_SENDER_CONFIG);

	// STATE_RECEVIVER_STARTED - receiver started
	agent_register_payload(STATE_RECEIVER_STARTED, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_STATE_RECEIVER_STARTED);
	agent_register_payload(STATE_RECEIVER_STARTED, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_STATE_RECEIVER_STARTED);

	// STATE_SENDER_STARTED - sender started
	agent_register_payload(STATE_SENDER_STARTED, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_STATE_SENDER_STARTED);
	agent_register_payload(STATE_SENDER_STARTED, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_STATE_SENDER_STARTED);

	// STATE_RECEIVER_CONFIGURED - receiver configured
	agent_register_payload(STATE_RECEIVER_CONFIGURED, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_STATE_RECEIVER_CONFIGURED);
	agent_register_payload(STATE_RECEIVER_CONFIGURED, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_STATE_RECEIVER_CONFIGURED);

	// STATE_RECEIVER_FINISHED - receiver finished
	agent_register_payload(STATE_RECEIVER_FINISHED, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_STATE_RECEIVER_FINISHED);
	agent_register_payload(STATE_RECEIVER_FINISHED, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_STATE_RECEIVER_FINISHED);

	// STATE_SENDER_FINISHED - sender finished
	agent_register_payload(STATE_SENDER_FINISHED, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_STATE_SENDER_FINISHED);
	agent_register_payload(STATE_SENDER_FINISHED, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_STATE_SENDER_FINISHED);

	return 0;
}

int
main(void)
{
	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_wasm_mod_messaging),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup, teardown);
}
