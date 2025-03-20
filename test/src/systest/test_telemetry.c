/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <config.h>

#include <stdbool.h>
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
#include "telemetry.h"

static char *deployment_evp1 = NULL;
static char *deployment_evp2 = NULL;

enum test_telemetry_payloads {
	DEPLOYMENT_MANIFEST_1,
};

struct test_input_set {
	void (*test_telemetry)(struct EVP_client *,
			       const struct EVP_telemetry_entry *, size_t);
};

static bool collect_fail, strdup_fail;

#define MODULE_NAME "backdoor-telemetry"
#define INSTANCE_ID "07fe77d5-7117-4326-9042-47fda5dd9bf5"
#define DEPLOYMENT_FILE_EVP1                                                  \
	"src/systest/test_telemetry_deployment_payload-evp1.json"
#define DEPLOYMENT_FILE_EVP2                                                  \
	"src/systest/test_telemetry_deployment_payload-evp2.json"

static void
telemetry_cb(EVP_TELEMETRY_CALLBACK_REASON reason, void *userData)
{
	check_expected(reason);
	check_expected(userData);
}

static void
test_telemetry_common(struct EVP_client *sdk_handle,
		      const struct EVP_telemetry_entry *entries,
		      size_t n_entries, EVP_TELEMETRY_CALLBACK_REASON reason)
{
	char *user_data = "Telemetry data";

	// send telemetry entries
	EVP_RESULT result = EVP_sendTelemetry(sdk_handle, entries, n_entries,
					      telemetry_cb, user_data);
	assert_int_equal(result, EVP_OK);

	// verify callback
	expect_value(telemetry_cb, reason, reason);
	expect_memory(telemetry_cb, userData, user_data, sizeof(user_data));
	EVP_processEvent(sdk_handle, 1000);
}

static void
test_telemetry_tb(struct EVP_client *sdk_handle,
		  const struct EVP_telemetry_entry *entries, size_t n_entries)
{
	const char *expected =
		"{\"" INSTANCE_ID
		"/room1\":{\"temperature\":\"25\",\"humidity\":\"53\"}"
		",\"" INSTANCE_ID
		"/room2\":{\"temperature\":\"34\",\"humidity\":\"24\"}}";
	;

	test_telemetry_common(sdk_handle, entries, n_entries,
			      EVP_TELEMETRY_CALLBACK_REASON_SENT);

	// verify telemetry payload
	agent_poll(verify_contains, expected);
}

static void
test_telemetry(void **state)
{
	static const struct test_input_set test_inputs[] = {
		[EVP_HUB_TYPE_EVP1_TB] = {test_telemetry_tb},
		[EVP_HUB_TYPE_EVP2_TB] = {test_telemetry_tb},
	};

	struct EVP_client *sdk_handle = *state;
	const enum evp_hub_type hub = agent_test_get_hub_type();
	const struct test_input_set *set = &test_inputs[hub];

	struct EVP_telemetry_entry entries[] = {
		{
			.key = "room1",
			.value = "{\"temperature\":\"25\","
				 "\"humidity\":\"53\"}",
		},
		{
			.key = "room2",
			.value = "{\"temperature\":\"34\","
				 "\"humidity\":\"24\"}",
		},
	};

	set->test_telemetry(sdk_handle, entries, __arraycount(entries));
}

static void
test_telemetry_too_large(void **state)
{
	/*
	 * Test that a telemetry bigger than MQTT buffer size is not accepted
	 */
	EVP_RESULT result;
	struct EVP_client *sdk_handle = *state;
	char *value_too_large = xmalloc(CONFIG_EVP_MQTT_SEND_BUFF_SIZE);
	memset(value_too_large, 'a', CONFIG_EVP_MQTT_SEND_BUFF_SIZE);
	memcpy(value_too_large, "{\"field\":\"a", strlen("{\"field\":\"a"));
	memcpy(value_too_large + CONFIG_EVP_MQTT_SEND_BUFF_SIZE -
		       (sizeof("\"}")),
	       "\"}", sizeof("\"}"));

	struct EVP_telemetry_entry entries_1_too_large[] = {{
		.key = "too_large",
		.value = value_too_large,
	}};
	result = EVP_sendTelemetry(sdk_handle, entries_1_too_large,
				   __arraycount(entries_1_too_large),
				   telemetry_cb, NULL);
	assert_int_equal(result, EVP_TOOBIG);
	EVP_processEvent(sdk_handle, 100);

	/*
	 * Test that a list of telemetries bigger than MQTT buffer size is not
	 * accepted
	 */
	int size = CONFIG_EVP_MQTT_SEND_BUFF_SIZE / 3;
	char *value_very_large = xmalloc(size);
	memset(value_very_large, 'a', size);
	memcpy(value_very_large, "{\"field\":\"a", strlen("{\"field\":\"a"));
	memcpy(value_very_large + size - (sizeof("\"}")), "\"}",
	       sizeof("\"}"));

	struct EVP_telemetry_entry entries_3_very_large[] = {
		{.key = "large_1", .value = value_very_large},
		{.key = "large_2", .value = value_very_large},
		{.key = "large_3", .value = value_very_large},
	};
	result = EVP_sendTelemetry(sdk_handle, entries_3_very_large,
				   __arraycount(entries_3_very_large),
				   telemetry_cb, NULL);
	assert_int_equal(result, EVP_TOOBIG);
	EVP_processEvent(sdk_handle, 100);

	free(value_too_large);
	free(value_very_large);
}

void
__wrap_sdk_collect_telemetry(int (*cb)(const char *,
				       const struct EVP_telemetry_entry *,
				       size_t, void *),
			     void *user)
{
	void __real_sdk_collect_telemetry(
		int (*)(const char *, const struct EVP_telemetry_entry *,
			size_t, void *),
		void *);

	if (collect_fail) {
		strdup_fail = true;
		collect_fail = false;
	}

	__real_sdk_collect_telemetry(cb, user);
	strdup_fail = false;
}

char *
__wrap_strdup(const char *s)
{
	char *__real_strdup(const char *);

	if (strdup_fail)
		return NULL;

	return __real_strdup(s);
}

static void
test_telemetry_error(void **state)
{
	struct EVP_client *sdk_handle = *state;
	unsigned int user_data = 0xC0FFEEEEu;
	const struct EVP_telemetry_entry entries[] = {
		{.key = "key", .value = "value"}};

	collect_fail = true;
	expect_value(telemetry_cb, reason,
		     EVP_TELEMETRY_CALLBACK_REASON_ERROR);
	expect_memory(telemetry_cb, userData, &user_data, sizeof(user_data));
	assert_int_equal(EVP_sendTelemetry(sdk_handle, entries,
					   __arraycount(entries), telemetry_cb,
					   &user_data),
			 EVP_OK);
	assert_int_equal(EVP_processEvent(sdk_handle, -1), EVP_OK);
}

int
setup(void **state)
{
	agent_test_setup();

	// read and serialise EVP1 json
	size_t sz;
	char *tmp = read_file(DEPLOYMENT_FILE_EVP1, &sz, true);
	JSON_Value *value = json_value_init_string(tmp);
	deployment_evp1 = json_serialize_to_string(value);
	assert_non_null(deployment_evp1);
	agent_register_payload(DEPLOYMENT_MANIFEST_1, EVP_HUB_TYPE_EVP1_TB,
			       deployment_evp1);
	json_value_free(value);
	free(tmp);

	// read and register EVP2 json
	deployment_evp2 = read_file(DEPLOYMENT_FILE_EVP2, &sz, true);
	assert_non_null(deployment_evp2);
	agent_register_payload(DEPLOYMENT_MANIFEST_1, EVP_HUB_TYPE_EVP2_TB,
			       deployment_evp2);

	// start agent and send deployment
	struct evp_agent_context *ctxt = agent_test_start();
	assert_non_null(ctxt);
	struct agent_deployment d = {.ctxt = ctxt};

	// create backdoor instance
	struct EVP_client *sdk_handle =
		evp_agent_add_instance(ctxt, MODULE_NAME);
	assert_non_null(sdk_handle);

	static const char id[] = "2dc1a1c3-531b-4693-abba-a4a039bb827d";
	agent_ensure_deployment(&d, agent_get_payload(DEPLOYMENT_MANIFEST_1),
				id);
	*state = sdk_handle;
	return 0;
}

int
teardown(void **state)
{
	// wait for agent to finish
	agent_test_exit();
	free(deployment_evp1);
	free(deployment_evp2);
	return 0;
}

int
main(void)
{
	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_telemetry),
		cmocka_unit_test(test_telemetry_too_large),
		cmocka_unit_test(test_telemetry_error),
	};

	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup, teardown);
}
