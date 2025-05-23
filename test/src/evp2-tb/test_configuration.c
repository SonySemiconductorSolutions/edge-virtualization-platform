/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <cmocka.h>
#include <evp/agent.h>
#include <parson.h>

#include <internal/evp_config.h>
#include <internal/util.h>

#include "device_config.h"
#include "fsutil.h"
#include "global.h"
#include "hub.h"
#include "instance_config.h"
#include "module_instance.h"
#include "mqtt.h"
#include "persist.h"

int
setup_basic_desired(void **state)
{
	json_value_free(g_evp_global.desired);
	g_evp_global.desired = json_value_init_object();
	if (!g_evp_global.desired)
		return 1;
	return 0;
}

int
setup_min_interval_config_desired(void **state)
{
	const char *device_config = "{\"desiredDeviceConfig\":"
				    "{\"configuration/$agent/"
				    "report-status-interval-min\": 45}"
				    "}";
	json_value_free(g_evp_global.desired);
	g_evp_global.desired = json_parse_string(device_config);
	if (!g_evp_global.desired)
		return 1;
	return 0;
}

/*
 * Wrap module_instance_notify because there is not any valid instance
 * installed in the agent
 */
void
__wrap_module_instance_notify(enum notify_type type,
			      const char *module_instance_name,
			      size_t module_instance_name_len, EVP_RPC_ID id,
			      const char *topic, const void *blob,
			      size_t bloblen)
{
	assert_int_equal(type, NOTIFY_CONFIG);

	/* verify that we have received the expected data */
	check_expected(module_instance_name);
	check_expected(module_instance_name_len);
	check_expected(topic);

	/* The real method assign this pointer to sdk queues, and it is free
	 * later. So the mock has to handle it. */
	free(__UNCONST(blob));
}

/*
 * Dummy wrapper for save_desired
 */
void
__wrap_save_desired(struct evp_agent_context *agent)
{
	function_called();
}

/*
 * Test that agent can parse a configuration (specific attribute) and the data
 * is notified to the specific instance referenced
 */
void
test_parse_module_configuration(void **state)
{
	struct evp_agent_context *agent = *state;
	char *mi_name = "module_instance_name";
	int mi_name_len = strlen(mi_name);

	expect_memory(__wrap_module_instance_notify, module_instance_name,
		      mi_name, mi_name_len);
	expect_value(__wrap_module_instance_notify, module_instance_name_len,
		     mi_name_len);
	expect_string(__wrap_module_instance_notify, topic, "some_key");
	expect_function_call(__wrap_save_desired);

	struct instance_config_reqs msg = {
		.nreqs = 1,
		.reqs = (struct instance_config_req[]){
			[0].delete = 0,
			[0].instance = mi_name,
			[0].name = "some_key",
			[0].value = "YXp1cmVfYXp1cmVfZmlsZS0z",
		}};
	evp_process_instance_config(agent, &msg, EVP_CONFIG_HUB);
}

/*
 * Test that agent can parse more than one configuration in the same json
 * payload message
 */
void
test_parse_module_configuration_list(void **state)
{
	struct evp_agent_context *agent = *state;
	char *mi_name = "module_instance_name";
	int mi_name_len = strlen(mi_name);

	/* 1st config */
	expect_memory(__wrap_module_instance_notify, module_instance_name,
		      mi_name, mi_name_len);
	expect_value(__wrap_module_instance_notify, module_instance_name_len,
		     mi_name_len);
	expect_string(__wrap_module_instance_notify, topic, "some_key");

	/* 2nd config */
	expect_memory(__wrap_module_instance_notify, module_instance_name,
		      mi_name, mi_name_len);
	expect_value(__wrap_module_instance_notify, module_instance_name_len,
		     mi_name_len);
	expect_string(__wrap_module_instance_notify, topic, "another_key");
	expect_function_call(__wrap_save_desired);

	struct instance_config_reqs msg = {
		.nreqs = 2,
		.reqs = (struct instance_config_req[]){
			[0].delete = 0,
			[0].instance = mi_name,
			[0].name = "some_key",
			[0].value = "YXp1cmVfYXp1cmVfZmlsZS0z",
			[1].delete = 0,
			[1].instance = mi_name,
			[1].name = "another_key",
			[1].value = "YXp1cmVfYXp1cmVfZmlsZS0z",
		}};
	evp_process_instance_config(agent, &msg, EVP_CONFIG_HUB);
}

/*
 * Test that agent can parse a deviceConfiguraton value.
 * Ensure set and delete actions
 * This value has been updated in global.desired json struct
 */
void
test_parse_device_configuration_interval_min(void **state)
{
	int ret;
	intmax_t val;

	expect_function_call(__wrap_save_desired);
	struct device_config msg = {.interval_min = 45};
	struct evp_agent_context *ctxt = *state;
	hub_received_device_config(ctxt, &msg);

	/* Check value update from desired device configuration */
	ret = config_get_int(EVP_CONFIG_REPORT_STATUS_INTERVAL_MIN_SEC, &val);
	assert_int_equal(ret, 0);
	assert_int_equal(val, 45);
}

void
test_parse_default_config(void **state)
{
	int ret;
	intmax_t val;

	/* Ensure default value is configured for min interval */
	ret = config_get_int(EVP_CONFIG_REPORT_STATUS_INTERVAL_MIN_SEC, &val);
	assert_int_equal(ret, 0);
	assert_int_equal(val, MIN_REPORT_INTERVAL_SEC);
}

void
test_parse_device_configuration_interval_min_null(void **state)
{
	int ret;
	intmax_t val;

	expect_function_call(__wrap_save_desired);
	struct device_config msg = {.interval_min = -1};
	struct evp_agent_context *ctxt = *state;
	hub_received_device_config(ctxt, &msg);

	ret = config_get_int(EVP_CONFIG_REPORT_STATUS_INTERVAL_MIN_SEC, &val);
	assert_int_equal(ret, 0);
	assert_int_equal(val, MIN_REPORT_INTERVAL_SEC);
}

static int
teardown(void **state)
{
	int ret;
	struct evp_agent_context *ctxt = *state;

	ret = evp_agent_stop(ctxt);
	evp_agent_free(ctxt);
	return ret;
}

static int
setup(void **state)
{
	int ret = -1;
	bool started = false;
	struct evp_agent_context *ctxt = NULL;

	if ((ret = putenv("EVP_IOT_PLATFORM=tb")) ||
	    (ret = putenv("EVP_MQTT_HOST=test.mqtt.host.value")) ||
	    (ret = putenv("EVP_MQTT_PORT=1234")))
		goto end;

	if (!(ctxt = evp_agent_setup("test")) || (ret = evp_agent_start(ctxt)))
		goto end;

	started = true;
	*state = ctxt;
	ret = 0;

end:
	if (ret && ctxt) {
		if (started)
			evp_agent_stop(ctxt);

		evp_agent_free(ctxt);
	}

	return ret;
}

int
main(void)
{
	/* define tests */
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(
			test_parse_module_configuration, setup_basic_desired,
			NULL),
		cmocka_unit_test_setup_teardown(
			test_parse_module_configuration_list,
			setup_basic_desired, NULL),
		cmocka_unit_test_setup_teardown(test_parse_default_config,
						setup_basic_desired, NULL),
		cmocka_unit_test_setup_teardown(
			test_parse_device_configuration_interval_min,
			setup_basic_desired, NULL),
		cmocka_unit_test_setup_teardown(
			test_parse_device_configuration_interval_min_null,
			setup_min_interval_config_desired, NULL),
	};

	return cmocka_run_group_tests(tests, setup, teardown);
}
