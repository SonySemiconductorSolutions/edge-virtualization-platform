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

enum {
	JSON_STATUS_CHECK,
};

struct test_context {
	struct evp_agent_context *agent;
};

#define REPORT_STATUS_INTERVAL_MIN 3
#define REPORT_STATUS_INTERVAL_MAX 5

#define TEST_DEPLOYMENT_ID1 "2dc1a1c3-531b-4693-abba-a4a039bb827d"
#define TEST_INSTANCE_ID1   "07fe77d5-7117-4326-9042-47fda5dd9bf5"
#define TEST_MODULE_ID1     "b91fe3e8-df6d-41b7-90cb-72f8b92bdf5e"
#define TEST_MODULE_URL     "file://../test_modules/config_echo.wasm"

#define JSON_STATUS_CHECK_EVP1 "deploymentStatus=#{reconcileStatus=%s"
#define JSON_STATUS_CHECK_TB   "deploymentStatus.reconcileStatus=%s"

int
setup(void **state)
{
	static struct test_context ctxt;

	// Set periodic report intervals
	agent_test_setup();

	putenv("EVP_REPORT_STATUS_INTERVAL_MIN_SEC=" ___STRING(
		REPORT_STATUS_INTERVAL_MIN));
	putenv("EVP_REPORT_STATUS_INTERVAL_MAX_SEC=" ___STRING(
		REPORT_STATUS_INTERVAL_MAX));

	agent_register_payload(JSON_STATUS_CHECK, EVP_HUB_TYPE_EVP1_TB,
			       JSON_STATUS_CHECK_EVP1);
	agent_register_payload(JSON_STATUS_CHECK, EVP_HUB_TYPE_EVP2_TB,
			       JSON_STATUS_CHECK_TB);

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
test_undeploy_all(void **state)
{
	struct test_context *ctxt = *state;

	deploy(ctxt, TEST_DEPLOYMENT_ID1, TEST_INSTANCE_ID1, "wasm");

	send_instance_config(ctxt, TEST_INSTANCE_ID1);

	assert_int_equal(evp_agent_undeploy_all(ctxt->agent), 0);

	agent_poll(verify_json, agent_get_payload(JSON_STATUS_CHECK), "ok");

	char *s;
	int rv;
	rv = popenf(popen_strcpy, &s, "cat %s",
		    path_get(DESIRED_TWINS_PATH_ID));
	assert_int_equal(rv, 0);
	assert_string_equal(s, "{}");
	free(s);

	rv = popenf(popen_strcpy, &s, "ls -A %s",
		    path_get(MODULE_INSTANCE_PATH_ID));
	assert_int_equal(rv, 0);
	assert_string_equal(s, "");
	free(s);

	rv = popenf(popen_strcpy, &s, "ls -A %s", path_get(MODULE_PATH_ID));
	assert_int_equal(rv, 0);
	assert_string_equal(s, "");
	free(s);
}

int
main(void)
{
	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_undeploy_all),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup, teardown);
}
