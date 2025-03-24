/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <config.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <evp/sdk.h>
#include <parson.h>

#include <internal/util.h>

#include "agent_test.h"
#include "global.h"
#include "hub.h"
#include "module_instance.h"
#include "mqtt_custom.h"

enum test_instance_state_payloads {
	DEPLOYMENT_MANIFEST_1,
	DEPLOYMENT_MANIFEST_2,
	MESSAGE_1,
	MESSAGE_2
};

struct test_context {
	struct evp_agent_context *agent;
};

#define REPORT_STATUS_INTERVAL_MIN 3
#define REPORT_STATUS_INTERVAL_MAX 5

#define TEST_DEPLOYMENT_ID1 "2dc1a1c3-531b-4693-abba-a4a039bb827d"
#define TEST_DEPLOYMENT_ID2 "2dc1a1c3-531b-4693-abba-a4a039bb827e"

#define TEST_INSTANCE_ID1 "07fe77d5-7117-4326-9042-47fda5dd9bf5"
#define TEST_INSTANCE_ID2 "07fe77d5-7117-4326-9042-47fda5dd9bf6"

#define TEST_MODULE_ID1 "b91fe3e8-df6d-41b7-90cb-72f8b92bdf5e"
#define TEST_MODULE_ID2 "b91fe3e8-df6d-41b7-90cb-72f8b92bdf5f"

#define TEST_MODULE_URL "file://../test_modules/config_echo.wasm"

#define STATE_1     "This is a test"
#define STATE_1_B64 "VGhpcyBpcyBhIHRlc3Q="
#define STATE_2     "{\"key\":\"value\"}"
#define STATE_2_B64 "eyJrZXkiOiJ2YWx1ZSJ9"

int
setup(void **state)
{
	static struct test_context ctxt;

	agent_test_setup();

	// Set periodic report intervals
	putenv("EVP_REPORT_STATUS_INTERVAL_MIN_SEC=" ___STRING(
		REPORT_STATUS_INTERVAL_MIN));
	putenv("EVP_REPORT_STATUS_INTERVAL_MAX_SEC=" ___STRING(
		REPORT_STATUS_INTERVAL_MAX));

	agent_register_payload(MESSAGE_1, EVP_HUB_TYPE_EVP1_TB, STATE_1_B64);
	agent_register_payload(MESSAGE_1, EVP_HUB_TYPE_EVP2_TB, STATE_1);
	agent_register_payload(MESSAGE_2, EVP_HUB_TYPE_EVP1_TB, STATE_2_B64);
	agent_register_payload(MESSAGE_2, EVP_HUB_TYPE_EVP2_TB, STATE_2);

	ctxt.agent = agent_test_start();

	agent_send_initial(ctxt.agent, NULL, NULL, NULL);
	*state = &ctxt;

	return 0;
}

int
teardown(void **state)
{
	agent_test_exit();
	return 0;
}

void
deploy(struct test_context *ctxt, const char *id, const char *instance_id,
       const char *impl)
{
	message_info("Deploy %s", id);
	JSON_Object *o = manifest_create(NULL, id);
	assert_non_null(manifest_add_module_spec(o, TEST_MODULE_ID1, impl,
						 "000000000000",
						 TEST_MODULE_URL, "main"));
	assert_non_null(manifest_add_instance_spec(
		o, instance_id, TEST_MODULE_ID1, "main", 1));

	manifest_finalize(o);
	char *deployment = manifest_serialize_deployment(o);
	object_free(o);
	agent_send_deployment(ctxt->agent, deployment);
	free(deployment);
	agent_poll(verify_contains, id);
}

void
send_instance_config(struct test_context *ctxt, const char *instance_id)
{
	message_info("Create config");
	struct test_instance_config *pair;
	pair = test_instance_config_create(instance_id, "test_topic",
					   "value1");
	assert_non_null(pair);

	message_info("Send %s config payload", instance_id);
	JSON_Object *o = object_create(NULL);
	object_add_instance_config(o, pair);

	char *config = object_serialize(o);
	object_free(o);
	agent_send_instance_config(ctxt->agent, config);
	free(config);

	message_info("Verify that %s is being reported", pair->state_key);
	char *dotquery;
	xasprintf(&dotquery, ".=$#,state/%s/test_topic=%%s", instance_id);
	agent_poll(verify_json, dotquery, 1, pair->value);
	free(dotquery);
	test_instance_config_free(pair);
}

void
test_instance_state(void **state)
{
	struct test_context *ctxt = *state;

	deploy(ctxt, TEST_DEPLOYMENT_ID1, TEST_INSTANCE_ID1, "wasm");

	send_instance_config(ctxt, TEST_INSTANCE_ID1);

	deploy(ctxt, TEST_DEPLOYMENT_ID2, TEST_INSTANCE_ID2, "wasm");

	send_instance_config(ctxt, TEST_INSTANCE_ID2);
}

int
main(void)
{
	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_instance_state),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup, teardown);
}
