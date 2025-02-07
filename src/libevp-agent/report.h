/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef REPORT_H
#define REPORT_H

#include <stdbool.h>
#include <stdint.h>

#include "evp_hub.h"
#include "req.h"

struct report_params {
	uint64_t interval_min_ms;
	uint64_t interval_max_ms;
};

struct report_state {
	uint64_t last_report_timestamp;
	uint64_t last_status_poll_timestamp;
	char *last_report_payload;
	struct request *last_req;
};

/**
 * Get the interval report from the environment vars and check them
 * If the environment vars don't exist it will assign a default value
 *
 * @param params The address of the report_params structure to initialize
 */
int get_report_interval(struct report_params *params);

void periodic_report_status(const struct evp_agent_context *agent,
			    const struct report_params *params,
			    const struct evp_hub_context *hub,
			    struct report_state *state);
void periodic_report_instance_state(const struct evp_agent_context *agent,
				    const struct report_params *params,
				    const struct evp_hub_context *hub,
				    struct report_state *state);
int periodic_report_send(const struct evp_hub_context *hub, char *payload,
			 struct report_state *state, intmax_t qos,
			 enum req_priority priority);
char *report_refresh_status(const struct evp_agent_context *agent,
			    const struct evp_hub_context *hub, void *cb_data,
			    intmax_t *qos, enum req_priority *priority);
char *report_refresh_instance_state(const struct evp_agent_context *agent,
				    const struct evp_hub_context *hub,
				    void *cb_data, intmax_t *qos,
				    enum req_priority *priority);

int hub_evp1_deployment_status_add(JSON_Object *current_obj);
int hub_evp2_tb_deployment_status_add(JSON_Object *current_obj);
int hub_evp1_convert_state(JSON_Object *o, const char *name, const void *blob,
			   size_t bloblen);
int hub_evp2_convert_state(JSON_Object *o, const char *name, const void *blob,
			   size_t bloblen);

void clean_instance_state(const char *id);

#endif
