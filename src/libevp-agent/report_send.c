/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include <internal/evp_config.h>

#include "hub.h"
#include "report.h"
#include "req.h"

static void
report_payload_free(struct request *req, void *arg)
{
	struct report_state *state = arg;

	// TODO: Replace assert (programming error)
	assert(state != NULL);
	// TODO: Replace assert (programming error)
	assert(state->last_req != NULL);
	// TODO: Replace assert (programming error)
	assert(state->last_req == req);
	// TODO: Replace assert (programming error)
	assert(state->last_report_payload == req->payload);
	state->last_req = NULL;
	req->payload = NULL; /* just to be safe */
}

int
periodic_report_send(const struct evp_hub_context *hub, char *payload,
		     struct report_state *state, intmax_t qos,
		     enum req_priority priority)
{
	struct request *req = request_alloc();
	// reset timeout to make sure it is not removed from mq
	req->timeout_ms = 0;
	req->payload = payload;
	req->payload_free = report_payload_free;
	req->payload_free_arg = state;
	req->qos = qos;
	req->priority = priority;
	state->last_req = req;
	if (hub->send_periodic_report(req)) {
		request_free(req);
		return -1;
	}
	return 0;
}
