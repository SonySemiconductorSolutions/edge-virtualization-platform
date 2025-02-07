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
#include <string.h>

#include <cmocka.h>
#include <parson.h>

#include <internal/evp_config.h>

#include "cdefs.h"
#include "device_state.h"
#include "global.h"
#include "hub.h"
#include "persist.h"

#define INTERVAL_MIN_SUFFIX  "/report-status-interval-min"
#define INTERVAL_MAX_SUFFIX  "/report-status-interval-max"
#define REGISTRY_AUTH_SUFFIX "/registry-auth"
#define CONFIGURATION_ID     "/configuration-id"

#define STATE_PREFIX           "state/$agent"
#define STATE_INTERVAL_MIN     STATE_PREFIX INTERVAL_MIN_SUFFIX
#define STATE_INTERVAL_MAX     STATE_PREFIX INTERVAL_MAX_SUFFIX
#define STATE_REGISTRY_AUTH    STATE_PREFIX REGISTRY_AUTH_SUFFIX
#define STATE_CONFIGURATION_ID STATE_PREFIX CONFIGURATION_ID

#define TEST_DOMAIN           "test.example.org"
#define TEST_CREDENTIALS      "credentials"
#define TEST_CONFIGURATION_ID "b234f90b-8828-4f3f-8a01-a6d3527bc15d"

/* Called by device_state_add to retrieve
 * EVP_CONFIG_REPORT_STATUS_INTERVAL_{MIN,MAX}_SEC. */
int
__wrap_config_get_int(enum config_key key, intmax_t *value)
{
	switch (key) {
	case EVP_CONFIG_REPORT_STATUS_INTERVAL_MIN_SEC:
		*value = MIN_REPORT_INTERVAL_SEC;
		break;

	case EVP_CONFIG_REPORT_STATUS_INTERVAL_MAX_SEC:
		*value = MAX_REPORT_INTERVAL_SEC;
		break;

	case EVP_CONFIG_CONFIGURATION_ID:
		/* Fall through. */
	case EVP_CONFIG_REGISTRY_AUTH:
		/* Fall through. */
	default:
		fail_msg("unexpected key %d", key);
		return -1;
	}

	return 0;
}

/* Called by device_state_add to retrieve:
 * - EVP_CONFIG_REGISTRY_AUTH
 * - EVP_CONFIG_CONFIGURATION_ID
 */
char *
__wrap_config_get_string(enum config_key key)
{
	switch (key) {
	case EVP_CONFIG_REGISTRY_AUTH:
		return strdup("{\"" TEST_DOMAIN "\": \"" TEST_CREDENTIALS
			      "\"}");

	case EVP_CONFIG_CONFIGURATION_ID:
		return strdup(TEST_CONFIGURATION_ID);

	case EVP_CONFIG_REPORT_STATUS_INTERVAL_MIN_SEC:
		/* Fall through. */
	case EVP_CONFIG_REPORT_STATUS_INTERVAL_MAX_SEC:
		/* Fall through. */
	default:
		fail_msg("unexpected key %d", key);
		break;
	}

	return NULL;
}

static void
test_state(void **state)
{
	JSON_Value *v = json_value_init_object();
	assert_non_null(v);
	JSON_Object *o = json_value_get_object(v);
	assert_non_null(o);

	assert_int_equal(hub_evp2_device_state_add(o), 0);

	assert_int_equal(json_object_get_number(o, STATE_INTERVAL_MIN),
			 MIN_REPORT_INTERVAL_SEC);

	/* Ensure default value has been retrieved. */
	assert_int_equal(json_object_get_number(o, STATE_INTERVAL_MAX),
			 MAX_REPORT_INTERVAL_SEC);

	JSON_Object *auth = json_object_get_object(o, STATE_REGISTRY_AUTH);
	assert_non_null(auth);

	const char *credentials = json_object_get_string(auth, TEST_DOMAIN);
	assert_non_null(credentials);
	assert_string_equal(credentials, TEST_CREDENTIALS);

	const char *configuration_id =
		json_object_get_string(o, STATE_CONFIGURATION_ID);
	assert_non_null(configuration_id);
	assert_string_equal(configuration_id, TEST_CONFIGURATION_ID);
	json_value_free(v);
}

int
main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_state),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
