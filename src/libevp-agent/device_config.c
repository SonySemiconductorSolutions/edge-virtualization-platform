/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>

#include <internal/util.h>

#include "agent_internal.h"
#include "device_config.h"
#include "global.h"
#include "hub.h"
#include "persist.h"
#include "xlog.h"

#define MAX_NAME "configuration/$agent/report-status-interval-max"
#define MIN_NAME "configuration/$agent/report-status-interval-min"
#define ID_NAME  "configuration/$agent/configuration-id"
#define REG_NAME "configuration/$agent/registry-auth"

void
device_config_ctor(struct device_config *cp, int max, int min, const char *id,
		   const char *reg)
{
	*cp = (struct device_config){
		.interval_max = max,
		.interval_min = min,
	};

	if (id)
		cp->config_id = xstrdup(id);
	if (reg)
		cp->registry_auth = xstrdup(reg);
}

void
device_config_dtor(struct device_config *cp)
{
	free(cp->config_id);
	free(cp->registry_auth);
}

int
hub_evp1_parse_device_config(JSON_Value *payload, struct device_config *cp)
{
	return -1;
}

int
hub_evp2_parse_device_config(JSON_Value *payload, struct device_config *cp)
{
	JSON_Value *minv, *maxv, *idv, *regv;
	int min, max;
	const char *id;
	char *reg;
	JSON_Object *o = json_value_get_object(payload);
	JSON_Object *cfg = json_object_get_object(o, "desiredDeviceConfig");

	if (!cfg) {
		return -1;
	}

	minv = json_object_get_value(cfg, MIN_NAME);
	maxv = json_object_get_value(cfg, MAX_NAME);
	idv = json_object_get_value(cfg, ID_NAME);
	regv = json_object_get_value(cfg, REG_NAME);

	if (!minv || !maxv || !idv || !regv) {
		xlog_error("%s: missed mandatory field", __func__);
		return -1;
	}

	switch (json_value_get_type(minv)) {
	case JSONNull:
		min = INVALID_TIME;
		break;
	case JSONNumber:
		min = json_value_get_number(minv);
		break;
	default:
		goto invalid_format;
	}

	switch (json_value_get_type(maxv)) {
	case JSONNull:
		max = INVALID_TIME;
		break;
	case JSONNumber:
		max = json_value_get_number(maxv);
		break;
	default:
		goto invalid_format;
	}

	switch (json_value_get_type(idv)) {
	case JSONNull:
		id = NULL;
		break;
	case JSONString:
		id = json_value_get_string(idv);
		break;
	default:
		goto invalid_format;
	}

	switch (json_value_get_type(regv)) {
	case JSONNull:
		reg = NULL;
		break;
	case JSONObject:
		reg = json_serialize_to_string(regv);
		break;
	default:
		goto invalid_format;
	}

	device_config_ctor(cp, max, min, id, reg);
	json_free_serialized_string(reg);

	return 0;

invalid_format:
	xlog_error("%s: invalid device config format", __func__);
	return -1;
}

void
hub_evp1_update_desired_device_config(struct device_config *cp)
{
	xlog_error("%s: device config is not supported in EVP1", __func__);
}

void
hub_evp2_update_desired_device_config(struct device_config *cp)
{
	JSON_Value *value;
	JSON_Object *o, *desired;
	JSON_Status st = JSONSuccess;

	desired = json_value_get_object(g_evp_global.desired);
	if (!desired) {
		xlog_error("Corrupted desired object");
		return;
	}

	value = json_value_init_object();
	o = json_value_get_object(value);
	if (!o)
		goto error;

	if (cp->interval_min != INVALID_TIME) {
		st = json_object_set_number(o, MIN_NAME, cp->interval_min);
		if (st != JSONSuccess)
			goto error;
	}

	if (cp->interval_max != INVALID_TIME) {
		st = json_object_set_number(o, MAX_NAME, cp->interval_max);
		if (st != JSONSuccess)
			goto error;
	}

	if (cp->config_id != NULL) {
		st = json_object_set_string(o, ID_NAME, cp->config_id);
		if (st != JSONSuccess)
			goto error;
	}

	if (cp->registry_auth != NULL) {
		JSON_Value *v = json_parse_string(cp->registry_auth);
		st = json_object_set_value(o, REG_NAME, v);
		if (st != JSONSuccess) {
			json_value_free(v);
			goto error;
		}
	}

	st = json_object_set_value(desired, "desiredDeviceConfig", value);
	if (st != JSONSuccess)
		goto error;
	return;

error:
	json_value_free(value);
	xlog_error("error updating desired device config: %d", (int)st);
}

void
hub_received_device_config(struct evp_agent_context *ctxt,
			   struct device_config *dev_config)
{
	struct device_config *cfg;

	if (dev_config->interval_min == 0 ||
	    dev_config->interval_min > 24 * 60 * 60) {
		dev_config->interval_min = INVALID_TIME;
		xlog_error("%s: invalid max/min report interval", __func__);
	}

	if (dev_config->interval_max == 0 ||
	    dev_config->interval_max > 24 * 60 * 60) {
		dev_config->interval_max = INVALID_TIME;
		xlog_error("%s: invalid max/min report interval", __func__);
	}

	if (!g_evp_global.devcfg) {
		g_evp_global.devcfg = xmalloc(sizeof(*cfg));
		*g_evp_global.devcfg = (struct device_config){0};
	}
	cfg = g_evp_global.devcfg;

	device_config_dtor(cfg);
	device_config_ctor(cfg, dev_config->interval_max,
			   dev_config->interval_min, dev_config->config_id,
			   dev_config->registry_auth);
	ctxt->hub->update_desired_device_config(dev_config);
	save_desired(ctxt);
	dump_global();
}
