/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sys/stat.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cmocka.h>
#include <evp/sdk.h>
#include <parson.h>

#include "device_config.h"
#include "sdk_local_wasm.h"

static void
test_parse_device_config_missing_mandatory_fields(void **status)
{
	struct device_config devConfig;

	JSON_Value *jsonValue =
		json_parse_string("{\"desiredDeviceConfig\":{}}");

	int error = hub_evp2_parse_device_config(jsonValue, &devConfig);

	json_value_free(jsonValue);

	assert_int_equal(error, -1);
}

static void
test_parse_device_config_invalid_minv_value(void **status)
{
	struct device_config devConfig;

	const char *dev_config =
		"{\"desiredDeviceConfig\":{"
		"\"configuration/$agent/report-status-interval-min\":\"bad\","
		"\"configuration/$agent/report-status-interval-max\":100,"
		"\"configuration/$agent/configuration-id\":\"id\","
		"\"configuration/$agent/registry-auth\": {}"
		"}}";

	JSON_Value *jsonValue = json_parse_string(dev_config);

	int error = hub_evp2_parse_device_config(jsonValue, &devConfig);

	json_value_free(jsonValue);

	assert_int_equal(error, -1);
}

static void
test_parse_device_config_invalid_maxv_value(void **status)
{
	struct device_config devConfig;

	const char *dev_config =
		"{\"desiredDeviceConfig\":{"
		"\"configuration/$agent/report-status-interval-min\":100,"
		"\"configuration/$agent/report-status-interval-max\":\"bad\","
		"\"configuration/$agent/configuration-id\":\"id\","
		"\"configuration/$agent/registry-auth\": {}"
		"}}";

	JSON_Value *jsonValue = json_parse_string(dev_config);

	int error = hub_evp2_parse_device_config(jsonValue, &devConfig);

	json_value_free(jsonValue);

	assert_int_equal(error, -1);
}

static void
test_parse_device_config_invalid_id_value(void **status)
{
	struct device_config devConfig;

	const char *dev_config =
		"{\"desiredDeviceConfig\":{"
		"\"configuration/$agent/report-status-interval-min\":100,"
		"\"configuration/$agent/report-status-interval-max\":100,"
		"\"configuration/$agent/configuration-id\":123,"
		"\"configuration/$agent/registry-auth\": {}"
		"}}";

	JSON_Value *jsonValue = json_parse_string(dev_config);

	int error = hub_evp2_parse_device_config(jsonValue, &devConfig);

	json_value_free(jsonValue);

	assert_int_equal(error, -1);
}

static void
test_parse_device_config_invalid_regv_value(void **status)
{
	struct device_config devConfig;

	const char *dev_config =
		"{\"desiredDeviceConfig\":{"
		"\"configuration/$agent/report-status-interval-min\":100,"
		"\"configuration/$agent/report-status-interval-max\":100,"
		"\"configuration/$agent/configuration-id\":\"id\","
		"\"configuration/$agent/registry-auth\": 123"
		"}}";

	JSON_Value *jsonValue = json_parse_string(dev_config);

	int error = hub_evp2_parse_device_config(jsonValue, &devConfig);

	json_value_free(jsonValue);

	assert_int_equal(error, -1);
}

static void
test_parse_device_config_null_default_values(void **status)
{
	struct device_config devConfig;

	const char *dev_config =
		"{\"desiredDeviceConfig\":{"
		"\"configuration/$agent/report-status-interval-min\":null,"
		"\"configuration/$agent/report-status-interval-max\":null,"
		"\"configuration/$agent/configuration-id\":null,"
		"\"configuration/$agent/registry-auth\":null"
		"}}";

	JSON_Value *jsonValue = json_parse_string(dev_config);

	int rv = hub_evp2_parse_device_config(jsonValue, &devConfig);

	json_value_free(jsonValue);

	assert_int_equal(rv, 0);

	assert_int_equal(devConfig.interval_min, INVALID_TIME);
	assert_int_equal(devConfig.interval_max, INVALID_TIME);
	assert_int_equal(devConfig.config_id, NULL);
	assert_int_equal(devConfig.registry_auth, NULL);
}

int
main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(
			test_parse_device_config_missing_mandatory_fields),
		cmocka_unit_test(test_parse_device_config_invalid_minv_value),
		cmocka_unit_test(test_parse_device_config_invalid_maxv_value),
		cmocka_unit_test(test_parse_device_config_invalid_id_value),
		cmocka_unit_test(test_parse_device_config_invalid_regv_value),
		cmocka_unit_test(test_parse_device_config_null_default_values),

	};
	// test run
	return cmocka_run_group_tests(tests, NULL, NULL);
}
