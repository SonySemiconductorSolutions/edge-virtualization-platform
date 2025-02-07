/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <parson.h>

#define INVALID_TIME -1

// evp-onwire-schema/schema/device-config.schema.json
struct device_config {
	int interval_min;
	int interval_max;
	char *config_id;
	char *registry_auth;
};

struct evp_agent_context;

void device_config_ctor(struct device_config *cp, int max, int min,
			const char *id, const char *reg);

void device_config_dtor(struct device_config *cp);

/* parse functions */
int hub_evp1_parse_device_config(JSON_Value *payload,
				 struct device_config *cp);
int hub_evp2_parse_device_config(JSON_Value *payload,
				 struct device_config *cp);
/* update desired */
void hub_evp1_update_desired_device_config(struct device_config *cp);
void hub_evp2_update_desired_device_config(struct device_config *cp);

void hub_received_device_config(struct evp_agent_context *ctxt,
				struct device_config *dev_config);
