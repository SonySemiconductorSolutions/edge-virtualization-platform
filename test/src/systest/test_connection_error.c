/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <semaphore.h>
#include <setjmp.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>
#include <evp/sdk.h>
#include <parson.h>

#include <internal/util.h>

#include "agent_test.h"
#include "hub.h"
#include "module_instance.h"
#include "mqtt_custom.h"
#include "testlog.h"
#include "xlog.h"

#define TEST_DEPLOYMENT_ID1 "2dc1a1c3-531b-4693-abba-a4a039bb827d"

#define EVP1_EXPECT_STATE                                                     \
	"\"state/07fe77d5-7117-4326-9042-47fda5dd9bf5/"                       \
	"test_topic\":\"VGhpcyBpcyBhIHRlc3Q=\""

#define EVP2_EXPECT_STATE                                                     \
	"\"state/07fe77d5-7117-4326-9042-47fda5dd9bf5/"                       \
	"test_topic\":\"This is a test\""

enum test_connection_error_payloads { DEPLOYMENT_MANIFEST_1, EXPECTED_STATE };

struct test_context {
	struct evp_agent_context *agent;
	struct EVP_client *h;
	struct agent_deployment d;
	sem_t sem;
	bool called;
};

#define EVP1_DEPLOYMENT_MANIFEST_1                                            \
	"\"{ "                                                                \
	"        \\\"deploymentId\\\": "                                      \
	"\\\"" TEST_DEPLOYMENT_ID1 "\\\","                                    \
	"        \\\"instanceSpecs\\\": {"                                    \
	"            "                                                        \
	"\\\"07fe77d5-7117-4326-9042-47fda5dd9bf5\\\":"                       \
	" {"                                                                  \
	"                \\\"moduleId\\\": "                                  \
	"\\\"b91fe3e8-df6d-41b7-90cb-72f8b92bdf5e\\\","                       \
	"                \\\"entryPoint\\\": "                                \
	"\\\"backdoor-test\\\","                                              \
	"                \\\"version\\\": 1,"                                 \
	"                \\\"publish\\\": {},"                                \
	"                \\\"subscribe\\\": {}"                               \
	"            }"                                                       \
	"        },"                                                          \
	"        \\\"modules\\\": {"                                          \
	"            "                                                        \
	"\\\"b91fe3e8-df6d-41b7-90cb-72f8b92bdf5e\\\":"                       \
	" {"                                                                  \
	"                \\\"moduleImpl\\\": "                                \
	"\\\"spawn\\\","                                                      \
	"                \\\"downloadUrl\\\": "                               \
	"\\\"\\\","                                                           \
	"                \\\"hash\\\": \\\"\\\""                              \
	"            }"                                                       \
	"        },"                                                          \
	"        \\\"publishTopics\\\": {},"                                  \
	"        \\\"subscribeTopics\\\": {}"                                 \
	"}\""

#define EVP2_DEPLOYMENT_MANIFEST_1                                            \
	"{"                                                                   \
	"        \"deploymentId\": \"" TEST_DEPLOYMENT_ID1 "\","              \
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
	"                \"entryPoint\": \"backdoor-test\","                  \
	"                \"moduleImpl\": \"spawn\","                          \
	"                \"downloadUrl\": \"\","                              \
	"                \"hash\": \"\""                                      \
	"            }"                                                       \
	"        },"                                                          \
	"        \"publishTopics\": {},"                                      \
	"        \"subscribeTopics\": {}"                                     \
	"}"

enum MQTTErrors
__wrap_mqtt_publish(struct mqtt_client *client, const char *topic_name,
		    const void *application_message,
		    size_t application_message_size, uint8_t publish_flags)
{
	char *payload = xstrndup((char *)application_message,
				 application_message_size);
	xlog_info("MQTT publish %s: %s", topic_name, payload);
	enum MQTTErrors ret;
	agent_test_call_count(1);
	if (get_connected()) {
		agent_write_to_pipe(payload);
		ret = MQTT_OK;
	} else {
		ret = MQTT_ERROR_SOCKET_ERROR;
	}
	free(payload);
	return ret;
}

enum MQTTErrors
__wrap_mqtt_sync(struct mqtt_client *client)
{
	if (client->error == MQTT_ERROR_INITIAL_RECONNECT) {
		client->error = MQTT_OK;
		client->connected_callback(client, &client->reconnect_state);
		set_connected(true);
		return MQTT_OK;
	}
	if (get_connected()) {
		return MQTT_OK;
	} else {
		return MQTT_ERROR_SOCKET_ERROR;
	}
}

static void
state_cb(EVP_STATE_CALLBACK_REASON reason, void *userData)
{
	struct test_context *ctxt = userData;

	check_expected(reason);
	check_expected(userData);
	ctxt->called = true;
}

static void
telemetry_cb(EVP_TELEMETRY_CALLBACK_REASON reason, void *userData)
{
	struct test_context *ctxt = userData;

	check_expected(reason);
	check_expected(userData);
	ctxt->called = true;
}

static int
connection_cb(const void *args, void *user_data)
{
	const char *status = args;
	struct test_context *ctxt = user_data;

	xlog_info("connection status: %s", status);
	assert(!sem_post(&ctxt->sem));
	return 0;
}

static void
set_agent_connection_state(struct test_context *ctxt, bool connect)
{
	struct evp_agent_context *agent = ctxt->agent;
	enum evp_agent_status status_check;
	if (connect) {
		evp_agent_connect(agent);
		status_check = EVP_AGENT_STATUS_CONNECTED;
	} else {
		evp_agent_disconnect(agent);
		status_check = EVP_AGENT_STATUS_DISCONNECTED;
	}

	while (evp_agent_get_status(agent) != status_check) {
		assert_int_equal(sem_wait(&ctxt->sem), 0);
	}
}

static void
ensure_event(struct test_context *ctxt)
{
	ctxt->called = false;

	while (!ctxt->called) {
		assert_int_equal(EVP_processEvent(ctxt->h, -1), EVP_OK);
	}
}

static void
test_state(void **state)
{
	struct test_context *ctxt = *state;

	const char state_topic[] = "test_topic";
	const char state_blob[] = "This is a test";
	EVP_RESULT result;
	set_agent_connection_state(ctxt, false);
	// Reset publish counter (expected to remain 0 all along deconnected
	// state)
	agent_test_call_count(-1);
	// send state repeatedly while disconnected
	for (int i = 0; i < 10; ++i) {
		result = EVP_sendState(ctxt->h, state_topic, state_blob,
				       strlen(state_blob), state_cb, ctxt);
		assert_int_equal(result, EVP_OK);

		expect_value(state_cb, userData, ctxt);

		EVP_STATE_CALLBACK_REASON reason =
			i + 1 < 10 ? EVP_STATE_CALLBACK_REASON_OVERWRITTEN
				   : EVP_STATE_CALLBACK_REASON_SENT;

		expect_value(state_cb, reason, reason);
	}

	for (int i = 0; i < 10; i++) {
		ensure_event(ctxt);
		assert_int_equal(agent_test_call_count(0), 0);
	}

	set_agent_connection_state(ctxt, true);

	agent_poll(verify_contains, agent_get_payload(EXPECTED_STATE));
	assert_int_not_equal(agent_test_call_count(0), 0);
}

static void
test_telemetry(void **state)
{
	struct test_context *ctxt = *state;

	struct EVP_telemetry_entry entries[] = {
		{.key = "room1",
		 .value = "{\"temperature\":\"25\",\"humidity\":\"53\"}"}};
	char *expected_telemetry;
	expected_telemetry = xstrdup(entries[0].value);

	EVP_RESULT result;
	set_agent_connection_state(ctxt, false);
	// Reset publish counter (expected to remain 0 all along deconnected
	// state)
	agent_test_call_count(-1);
	// send telemetry repeatedly while disconnected
	for (int i = 0; i < 10; ++i) {
		result = EVP_sendTelemetry(ctxt->h, entries,
					   __arraycount(entries), telemetry_cb,
					   ctxt);
		assert_int_equal(result, EVP_OK);

		expect_value(telemetry_cb, reason,
			     EVP_TELEMETRY_CALLBACK_REASON_SENT);
		expect_value(telemetry_cb, userData, ctxt);
	}

	for (int i = 0; i < 10; ++i) {
		ensure_event(ctxt);
		assert_int_equal(agent_test_call_count(0), 0);
	}

	set_agent_connection_state(ctxt, true);

	// Extra telemetry to make sure we send at least one in connected state
	result = EVP_sendTelemetry(ctxt->h, entries, __arraycount(entries),
				   telemetry_cb, ctxt);
	assert_int_equal(result, EVP_OK);

	expect_value(telemetry_cb, reason, EVP_TELEMETRY_CALLBACK_REASON_SENT);
	expect_value(telemetry_cb, userData, ctxt);

	agent_poll(verify_contains, expected_telemetry);
	free(expected_telemetry);
	ensure_event(ctxt);
}

int
setup(void **state)
{
	static struct test_context ctxt;

	assert_int_equal(sem_init(&ctxt.sem, 0, 0), 0);

	agent_test_setup();

	agent_register_payload(DEPLOYMENT_MANIFEST_1, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_DEPLOYMENT_MANIFEST_1);
	agent_register_payload(DEPLOYMENT_MANIFEST_1, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_DEPLOYMENT_MANIFEST_1);

	agent_register_payload(EXPECTED_STATE, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_EXPECT_STATE);
	agent_register_payload(EXPECTED_STATE, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_EXPECT_STATE);

	ctxt.agent = agent_test_start();
	assert_non_null(ctxt.agent);

	assert_int_equal(
		evp_agent_notification_subscribe(ctxt.agent, "agent/status",
						 connection_cb, &ctxt),
		0);

	ctxt.d = (struct agent_deployment){.ctxt = ctxt.agent};

	// create backdoor instance
	ctxt.h = evp_agent_add_instance(ctxt.agent, "backdoor-test");
	assert_non_null(ctxt.h);
	agent_ensure_deployment(&ctxt.d,
				agent_get_payload(DEPLOYMENT_MANIFEST_1),
				TEST_DEPLOYMENT_ID1);

	*state = &ctxt;
	return 0;
}

static int
teardown(void **state)
{
	struct test_context *ctxt = *state;

	agent_test_exit();
	assert_int_equal(sem_destroy(&ctxt->sem), 0);
	return 0;
}

int
main(void)
{
	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_state),
		cmocka_unit_test(test_telemetry),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup, teardown);
}
