/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <cmocka.h>

#include <internal/evp_config.h>

#include "cdefs.h"
#include "global.h"
#include "hub.h"
#include "module_instance.h"
#include "report.h"
#include "req.h"
#include "timeutil.h"

#define TEST_CONFIG_MQTT_HOST    "test.mqtt.host.value"
#define TEST_CONFIG_MQTT_PORT    "12435"
#define TEST_CONFIG_MIN_INTERVAL 1
#define TEST_CONFIG_MAX_INTERVAL 1

static int
setup(void **state)
{
	putenv("EVP_MQTT_HOST=" TEST_CONFIG_MQTT_HOST);
	putenv("EVP_MQTT_PORT=" TEST_CONFIG_MQTT_PORT);
	putenv("EVP_IOT_PLATFORM=tb");

	g_evp_global.current = json_value_init_object();
	g_evp_global.instance_states = json_value_init_object();

	if (!g_evp_global.current)
		return -1;

	return 0;
}

static int
teardown(void **state)
{
	json_value_free(g_evp_global.current);
	return 0;
}

void
__wrap_sdk_collect_states(void (*cb)(const char *, const char *, const void *,
				     size_t, void *),
			  void *user)
{
	function_called();
}

void
__wrap_main_loop_add_abs_timeout_ms(const char *name, uint64_t timeout_ms)
{
}

void
__wrap_periodic_report_send(const struct evp_hub_context *hub, char *payload,
			    struct report_state *state)
{
	function_called();
}

char *
__wrap_report_refresh(const struct evp_hub_context *hub, bool *states_updated)
{
	*states_updated = false;
	return "";
}

char *
__wrap_report_refresh_instance_state(const struct evp_agent_context *agent,
				     const struct evp_hub_context *hub,
				     void *cb_data, intmax_t *qos,
				     enum req_priority *priority)
{
	return strdup("{}");
}

static void
test_report_negative_max_interval_same_payload(void **state)
{
	struct report_params params;
	const struct evp_hub_context *hub = evp_hub_setup("TB");

	assert_non_null(hub);
	fprintf(stderr, "EVP_REPORT_STATUS_INTERVAL_MIN_SEC=%d\n",
		TEST_CONFIG_MIN_INTERVAL);
	putenv("EVP_REPORT_STATUS_INTERVAL_MIN_SEC=" ___STRING(
		TEST_CONFIG_MIN_INTERVAL));
	putenv("EVP_REPORT_STATUS_INTERVAL_MAX_SEC=-1");
	get_report_interval(&params);
	assert_int_equal(params.interval_max_ms, -1 * 1000);
	struct report_state report_state = {
		.last_report_payload = strdup("{}"),
	};
	periodic_report_instance_state(NULL, &params, hub, &report_state);
	assert_int_equal(report_state.last_report_timestamp, 0);
	json_free_serialized_string(report_state.last_report_payload);
}

static void
test_report_negative_max_interval_diff_payload(void **state)
{
	struct report_params params;
	const struct evp_hub_context *hub = evp_hub_setup("TB");

	assert_non_null(hub);
	fprintf(stderr, "EVP_REPORT_STATUS_INTERVAL_MIN_SEC=%d\n",
		TEST_CONFIG_MIN_INTERVAL);
	putenv("EVP_REPORT_STATUS_INTERVAL_MIN_SEC=" ___STRING(
		TEST_CONFIG_MIN_INTERVAL));
	putenv("EVP_REPORT_STATUS_INTERVAL_MAX_SEC=-1");
	get_report_interval(&params);
	assert_int_equal(params.interval_max_ms, -1 * 1000);

	struct report_state report_state = {
		.last_report_payload = strdup("a different payload"),
	};
	expect_function_call(__wrap_periodic_report_send);
	periodic_report_instance_state(NULL, &params, hub, &report_state);
	json_free_serialized_string(report_state.last_report_payload);
}

static void
test_report_negative_max_interval(void **state)
{
	struct report_params params;
	const struct evp_hub_context *hub = evp_hub_setup("TB");

	assert_non_null(hub);
	putenv("EVP_REPORT_STATUS_INTERVAL_MIN_SEC=" ___STRING(
		TEST_CONFIG_MIN_INTERVAL));
	putenv("EVP_REPORT_STATUS_INTERVAL_MAX_SEC=-2");
	get_report_interval(&params);
	assert_int_equal(params.interval_max_ms,
			 MAX_REPORT_INTERVAL_SEC * 1000);
}

static void
test_report_negative_min_interval(void **state)
{
	struct report_params params;
	const struct evp_hub_context *hub = evp_hub_setup("TB");

	assert_non_null(hub);
	putenv("EVP_REPORT_STATUS_INTERVAL_MAX_SEC=" ___STRING(
		TEST_CONFIG_MAX_INTERVAL));
	putenv("EVP_REPORT_STATUS_INTERVAL_MIN_SEC=-2");
	get_report_interval(&params);
	assert_int_equal(params.interval_min_ms,
			 MIN_REPORT_INTERVAL_SEC * 1000);
}

int
main(void)
{
	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(
			test_report_negative_max_interval_same_payload),
		cmocka_unit_test(
			test_report_negative_max_interval_diff_payload),
		cmocka_unit_test(test_report_negative_max_interval),
		cmocka_unit_test(test_report_negative_min_interval),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup, teardown);
}
