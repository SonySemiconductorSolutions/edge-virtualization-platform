/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <config.h>

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <parson.h>

#include <internal/evp_config.h>
#include <internal/util.h>

#include "base64.h"
#include "device_state.h"
#include "evp_hub.h"
#include "global.h"
#include "hub.h"
#include "main_loop.h"
#include "module.h"
#include "module_instance.h"
#include "persist.h"
#include "report.h"
#include "req.h"
#include "sdk_agent.h"
#include "system_info.h"
#include "timeutil.h"
#include "xlog.h"

/*
 * do not report our state to the Hub too frequently.
 *
 * Note:
 * 	The Hub has an inactivity time, be sure to send the report more often
 * 	than the timeout in the HUB or modify the timeout in the HUB.
 *  The report is send at least every MAX_REPORT_INTERVAL_SEC seconds
 */

/*
 * MIN_STATUS_POLL_INTERVAL_SEC: Minimum polling interval for
 * module/module instance status. The sole purpose of this constant
 * is to avoid querying the backend too frequently.
 *
 * Note: 0 is probably ok. But it's waste to poll the status too
 * frequently, especially for backends where a query can be
 * expensive. Eg. For docker, a query can be a remote call over network.
 */
#define MIN_STATUS_POLL_INTERVAL_SEC 3

int
get_report_interval(struct report_params *params)
{
	int rv;
	intmax_t report_interval;

	static unsigned long last_report_interval_min_ms = 0;
	static unsigned long last_report_interval_max_ms = 0;

	rv = config_get_int(EVP_CONFIG_REPORT_STATUS_INTERVAL_MIN_SEC,
			    &report_interval);
	// config must provide a compile-time default value
	if (rv) {
		xlog_error("No default value found for "
			   "EVP_REPORT_STATUS_INTERVAL_MIN_SEC");
		return rv;
	}
	if (report_interval <= 0 || report_interval > 24 * 60 * 60) {
		xlog_error("\"%jd\" is not a valid value for \"%s\" (in s)",
			   report_interval,
			   "EVP_REPORT_STATUS_INTERVAL_MIN_SEC");
		report_interval = MIN_REPORT_INTERVAL_SEC;
	}
	params->interval_min_ms = report_interval * 1000;

	rv = config_get_int(EVP_CONFIG_REPORT_STATUS_INTERVAL_MAX_SEC,
			    &report_interval);
	// config must provide a compile-time default value
	if (rv) {
		xlog_error("No default value found for "
			   "EVP_REPORT_STATUS_INTERVAL_MAX_SEC");
		return rv;
	}
	if (report_interval != -1 &&
	    (report_interval <= 0 || report_interval > 24 * 60 * 60)) {
		xlog_error("\"%jd\" is not a valid value for \"%s\" (in s)",
			   report_interval,
			   "EVP_REPORT_STATUS_INTERVAL_MAX_SEC");
		report_interval = MAX_REPORT_INTERVAL_SEC;
	}
	params->interval_max_ms = report_interval * 1000;

	if (params->interval_max_ms > 0 &&
	    params->interval_min_ms > params->interval_max_ms) {
		xlog_error("min report interval must be smaller or equal than "
			   "max");
		params->interval_max_ms = params->interval_min_ms;
	}

	if (last_report_interval_min_ms != params->interval_min_ms) {
		xlog_info("Report interval min updated to %" PRIu64
			  " (previous was "
			  "%lu).",
			  params->interval_min_ms,
			  last_report_interval_min_ms);
		last_report_interval_min_ms = params->interval_min_ms;
	}

	if (last_report_interval_max_ms != params->interval_max_ms) {
		xlog_info("Report interval max updated to %" PRIu64
			  " (previous was "
			  "%lu).",
			  params->interval_max_ms,
			  last_report_interval_max_ms);
		last_report_interval_max_ms = params->interval_max_ms;
	}
	return 0;
}

static void
schedule_next(const struct report_params *params,
	      const struct report_state *state, bool want)
{
	/*
	 * Note: we overweight interval_max_ms than other constraints here.
	 *
	 * Note: last_status_poll_timestamp >= last_report_timestamp.
	 */
	uint64_t next_max =
		state->last_report_timestamp + params->interval_max_ms;

	if (want) {
		uint64_t next_min =
			state->last_report_timestamp + params->interval_min_ms;
		uint64_t next_poll_min = state->last_status_poll_timestamp +
					 MIN_STATUS_POLL_INTERVAL_SEC * 1000;

		if (next_min < next_poll_min) {
			main_loop_add_abs_timeout_ms("PERIODIC-STATUS-POLL",
						     next_poll_min);
		} else {
			main_loop_add_abs_timeout_ms("PERIODIC-REPORT-MIN",
						     next_min);
		}
	}

	main_loop_add_abs_timeout_ms("PERIODIC-REPORT-MAX", next_max);
}

static JSON_Value *
build_deployment_status(JSON_Value *mi_value)
{
	JSON_Value *ds_value = json_value_init_object();
	JSON_Object *ds_obj = json_value_get_object(ds_value);
	json_object_set_value(ds_obj, "instances", mi_value);
	JSON_Value *mod_value = module_get_json_value();
	json_object_set_value(ds_obj, "modules", mod_value);

	if (g_evp_global.deploymentId != NULL) {
		json_object_set_string(ds_obj, "deploymentId",
				       g_evp_global.deploymentId);
	}
	if (g_evp_global.reconcileStatus != NULL) {
		json_object_set_string(ds_obj, "reconcileStatus",
				       g_evp_global.reconcileStatus);
	}

	return ds_value;
}

int
hub_evp1_deployment_status_add(JSON_Object *current_obj)
{
	JSON_Value *ds_value =
		build_deployment_status(module_instance_get_json_value_evp1());
	char *ds_str = json_serialize_to_string(ds_value);
	json_value_free(ds_value);
	json_object_set_string(current_obj, "deploymentStatus", ds_str);
	json_free_serialized_string(ds_str);
	return 0;
}

int
hub_evp2_tb_deployment_status_add(JSON_Object *current_obj)
{
	JSON_Value *ds_value =
		build_deployment_status(module_instance_get_json_value_evp2());
	json_object_set_value(current_obj, "deploymentStatus", ds_value);
	return 0;
}

static bool
check_force(const struct report_params *params, struct report_state *state,
	    uint64_t now)
{
	if (state->last_report_payload == NULL) {
		state->last_report_timestamp = now;
		state->last_status_poll_timestamp = now;
		xlog_trace("Sending a report because it's the first report");
		return true;
	} else if (now - state->last_report_timestamp >=
		   params->interval_max_ms) {
		xlog_trace("Sending a report because of max report interval");
		return true;
	}
	return false;
}

static bool
check_suppress(const struct report_params *params, struct report_state *state,
	       uint64_t now)
{
	if (now - state->last_report_timestamp < params->interval_min_ms) {
		xlog_trace("Skipping a report because of min report "
			   "interval");
		return true;
	}
	if (now - state->last_status_poll_timestamp <
	    MIN_STATUS_POLL_INTERVAL_SEC * 1000) {
		xlog_trace("Skipping a status poll because of "
			   "MIN_STATUS_POLL_INTERVAL_SEC");
		return true;
	}
	return false;
}

static int
periodic_report(const struct evp_agent_context *agent,
		const struct report_params *params,
		const struct evp_hub_context *hub, struct report_state *state,
		char *(*report_refresh)(const struct evp_agent_context *agent,
					const struct evp_hub_context *, void *,
					intmax_t *, enum req_priority *),
		void *cb_data)
{
	int ret = 0;
	const uint64_t now = gettime_ms();

	const bool force = check_force(params, state, now);
	const bool suppress = !force && check_suppress(params, state, now);

	// XXX implement some kind of acknowledgement from the cloud.
	// - forget acked states

	// https://thingsboard.io/docs/reference/mqtt-api/#publish-attribute-update-to-the-server

	if (suppress) {
		goto reschedule;
	}

	intmax_t qos;
	enum req_priority priority;

	char *payload = report_refresh(agent, hub, cb_data, &qos, &priority);
	if (payload == NULL) {
		goto reschedule;
	}

	/*
	 * TODO: Use a hash of report instead a full string to save memory
	 */
	state->last_status_poll_timestamp = now;
	if (!force && state->last_report_payload != NULL &&
	    !strcmp(payload, state->last_report_payload)) {
		json_free_serialized_string(payload);
		xlog_trace("Skipping a report because of the "
			   "identical contents");
	} else {
		xlog_trace("Sending a report after %" PRIu64 " ms",
			   now - state->last_report_timestamp);
		if (state->last_req != NULL) {
			xlog_debug("Cancelling the previous "
				   "incomplete report");
			request_unlink(state->last_req);
			request_free(state->last_req);
			state->last_req = NULL;
		}
		json_free_serialized_string(state->last_report_payload);
		state->last_report_payload = payload;
		state->last_report_timestamp = now;
		ret = periodic_report_send(hub, payload, state, qos, priority);
	}

reschedule:
	schedule_next(params, state, suppress);
	return ret;
}

void
periodic_report_status(const struct evp_agent_context *agent,
		       const struct report_params *params,
		       const struct evp_hub_context *hub,
		       struct report_state *state)
{
	periodic_report(agent, params, hub, state, report_refresh_status,
			NULL);
}

void
periodic_report_instance_state(const struct evp_agent_context *agent,
			       const struct report_params *params,
			       const struct evp_hub_context *hub,
			       struct report_state *state)
{
	bool state_updated = false;
	EVP_STATE_CALLBACK_REASON reason = EVP_STATE_CALLBACK_REASON_SENT;
	int rv =
		periodic_report(agent, params, hub, state,
				report_refresh_instance_state, &state_updated);
	if (rv) {
		reason = EVP_STATE_CALLBACK_REASON_DENIED;
	}
	if (state_updated) {
		sdk_complete_collected_states(reason);
	}
}
