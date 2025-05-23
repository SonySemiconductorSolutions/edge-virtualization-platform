/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>

#include <parson.h>

#include <internal/evp_config.h>

#include "cdefs.h"
#include "device_state.h"
#include "report.h"

#define DEVICE_STATE_PREFIX "state/$agent"
#define REPORT_STATUS_INTERVAL_MIN                                            \
	DEVICE_STATE_PREFIX "/report-status-interval-min"
#define REPORT_STATUS_INTERVAL_MAX                                            \
	DEVICE_STATE_PREFIX "/report-status-interval-max"
#define REPORT_STATUS_REGISTRY_AUTH DEVICE_STATE_PREFIX "/registry-auth"
#define CONFIGURATION_ID            DEVICE_STATE_PREFIX "/configuration-id"

static int
add_report_configuration_id(JSON_Object *o)
{
	int ret = 0;
	char *configuration_id =
		config_get_string(EVP_CONFIG_CONFIGURATION_ID);

	if (configuration_id) {
		JSON_Status status = json_object_set_string(
			o, CONFIGURATION_ID, configuration_id);
		free(configuration_id);
		if (status != JSONSuccess)
			ret = -1;
	} else {
		/* Return successfully even if config is not available. */
	}

	return ret;
}

static int
add_report_interval_min(JSON_Object *o)
{
	intmax_t min;
	JSON_Status st;
	struct report_params params;
	int ret = 0;

	get_report_interval(&params);
	min = params.interval_min_ms / 1000;
	st = json_object_set_number(o, REPORT_STATUS_INTERVAL_MIN, min);
	if (st != JSONSuccess)
		ret = -1;

	return ret;
}

static int
add_report_interval_max(JSON_Object *o)
{
	intmax_t max;
	JSON_Status st;
	struct report_params params;
	int ret = 0;

	get_report_interval(&params);
	max = params.interval_max_ms / 1000;
	st = json_object_set_number(o, REPORT_STATUS_INTERVAL_MAX, max);
	if (st != JSONSuccess)
		ret = -1;

	return ret;
}

static int
add_registry_auth(JSON_Object *o)
{
	int ret = 0;
	char *auth = config_get_string(EVP_CONFIG_REGISTRY_AUTH);

	if (auth) {
		JSON_Value *v = NULL;

		v = json_parse_string(auth);

		if (v) {
			JSON_Status status = json_object_set_value(
				o, REPORT_STATUS_REGISTRY_AUTH, v);

			if (status != JSONSuccess) {
				ret = -1;
				json_value_free(v);
			}
		} else {
			ret = -1;
		}

		free(auth);
	} else {
		/* Return successfully even if config is not available. */
	}

	return ret;
}

int
hub_evp2_device_state_add(JSON_Object *o)
{
	if (add_report_interval_min(o) || add_report_interval_max(o) ||
	    add_registry_auth(o) || add_report_configuration_id(o))
		return -1;

	return 0;
}

int
hub_evp1_device_state_add(JSON_Object *o)
{
	return 0;
}
