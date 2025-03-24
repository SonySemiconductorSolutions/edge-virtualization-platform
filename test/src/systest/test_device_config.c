/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <parson.h>

#include <internal/util.h>

#include "agent_test.h"
#include "hub.h"
#include "mqtt_custom.h"

#define TEST_DEPLOYMENT_ID1 "8543e017-2d93-444b-bd4c-bcaa39c46095"

#define TEST_DEVICE_CONFIG_ID1 "d60927b4-c944-470b-b351-3323d966178d"
#define TEST_DEVICE_CONFIG_ID2 "7acbea8c-10dc-480d-8720-cd9fb94d4a55"

#define TEST_DEVICE_STATE1_REPORT_STATUS_INTERVAL_MIN                         \
	"\"state/$agent/report-status-interval-min\":2"
#define TEST_DEVICE_STATE1_REPORT_STATUS_INTERVAL_MAX                         \
	"\"state/$agent/report-status-interval-max\":4"
#define TEST_DEVICE_STATE1_REGISTRY_AUTH                                      \
	"\"state/$agent/"                                                     \
	"registry-auth\":{\"domain.a.com\":\"auth-a\",\"domain.b.com\":"      \
	"\"auth-b\"}"
#define TEST_DEVICE_STATE1_CONFIGURATION_ID                                   \
	"\"state/$agent/configuration-id\":\"" TEST_DEVICE_CONFIG_ID1 "\""

#define TEST_DEVICE_STATE2_REPORT_STATUS_INTERVAL_MIN                         \
	"\"state/$agent/report-status-interval-min\":1"
#define TEST_DEVICE_STATE2_REPORT_STATUS_INTERVAL_MAX                         \
	"\"state/$agent/report-status-interval-max\":" ___STRING(             \
		MAX_REPORT_INTERVAL_SEC)
#define TEST_DEVICE_STATE2_REGISTRY_AUTH                                      \
	"\"state/$agent/registry-auth\":{\"domain.b.com\":\"auth-c\"}"
#define TEST_DEVICE_STATE2_CONFIGURATION_ID                                   \
	"\"state/$agent/configuration-id\":\"" TEST_DEVICE_CONFIG_ID2 "\""

static struct multi_check test_set_device_state1[] = {
	{.value = TEST_DEVICE_STATE1_REPORT_STATUS_INTERVAL_MIN},
	{.value = TEST_DEVICE_STATE1_REPORT_STATUS_INTERVAL_MAX},
	{.value = TEST_DEVICE_STATE1_REGISTRY_AUTH},
	{.value = TEST_DEVICE_STATE1_CONFIGURATION_ID},
	{.value = NULL}, // List termination
};

static struct multi_check test_set_device_state2[] = {
	{.value = TEST_DEVICE_STATE2_REPORT_STATUS_INTERVAL_MIN},
	{.value = TEST_DEVICE_STATE2_REPORT_STATUS_INTERVAL_MAX},
	{.value = TEST_DEVICE_STATE2_REGISTRY_AUTH},
	{.value = TEST_DEVICE_STATE2_CONFIGURATION_ID},
	{.value = NULL}, // List termination
};

static const char *device_config1 =
	"{\"desiredDeviceConfig\": {"
	"        \"configuration/$agent/report-status-interval-min\": 2,"
	"        \"configuration/$agent/report-status-interval-max\": 4,"
	"        \"configuration/$agent/registry-auth\": {"
	"                 \"domain.a.com\": \"auth-a\","
	"                 \"domain.b.com\": \"auth-b\""
	"        },"
	"        \"configuration/$agent/configuration-id\": "
	"\"" TEST_DEVICE_CONFIG_ID1 "\""
	"}}";
static const char *device_config2 =
	"{\"desiredDeviceConfig\": {"
	"        \"configuration/$agent/report-status-interval-min\": 1,"
	"        \"configuration/$agent/report-status-interval-max\": null,"
	"        \"configuration/$agent/registry-auth\": {"
	"                 \"domain.b.com\": \"auth-c\""
	"        },"
	"        \"configuration/$agent/configuration-id\": "
	"\"" TEST_DEVICE_CONFIG_ID2 "\""
	"}}";

void
test_device_config(void **state)
{
	if (agent_test_get_hub_type() == EVP_HUB_TYPE_EVP1_TB) {
		/* This test only applies for evp2 */
		return;
	}
	// start agent
	struct evp_agent_context *ctxt = agent_test_start();

	// test device config shared attribute / managed object
	agent_send_initial(ctxt, NULL, device_config1, NULL);
	agent_poll(verify_contains_in_unordered_set, test_set_device_state1);

	// test device config update
	agent_send_device_config(ctxt, device_config2);
	agent_poll(verify_contains_in_unordered_set, test_set_device_state2);
}

int
setup(void **state)
{
	agent_test_setup();
	// This test expects the default value when no value
	// is set via env var. So be sure that there is not any
	// value as max report
	putenv("EVP_REPORT_STATUS_INTERVAL_MAX_SEC=");
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
		cmocka_unit_test(test_device_config)};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup, teardown);
}
