/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <inttypes.h>

#include "main_loop.h"
#include "retry.h"
#include "xlog.h"

void
retry_state_init(struct retry_state *state)
{
	state->backoff = 0;
	state->recovering = false;
}

static uint64_t
retry_interval(struct retry_state *state)
{
	if (state->recovering) {
		// TODO: Replace assert (programming error)
		assert(state->backoff > 0);
		return 0;
	} else if (state->backoff > 0) {
		return UINT64_C(1000) << (state->backoff - 1);
	}
	return 0;
}

bool
retry_check(const struct retry_params *params, struct retry_state *state,
	    uint64_t now_ms)
{
	uint64_t interval_ms = retry_interval(state);

	xlog_trace("%s: interval %" PRIu64 " ms", params->name, interval_ms);
	if (interval_ms > 0 &&
	    now_ms - state->last_timestamp_ms < interval_ms) {
		uint64_t next_ms = state->last_timestamp_ms + interval_ms;
		main_loop_add_abs_timeout_ms(params->name, next_ms);
		xlog_trace("%s: suppressing until %" PRIu64 " (%" PRIu64
			   " ms from now)",
			   params->name, next_ms, next_ms - now_ms);
		return false;
	}
	return true;
}

void
retry_succeeded(const struct retry_params *params, struct retry_state *state,
		uint64_t now_ms)
{
	if (state->recovering) {
		// TODO: Replace assert (programming error)
		assert(state->backoff > 0);
		if (now_ms - state->last_timestamp_ms >=
		    params->recovering_grace_period_ms) {
			xlog_trace("%s: resetting backoff", params->name);
			/* Completed the recovering grace period. */
			state->recovering = false;
			state->backoff = 0;
		}
	} else if (state->backoff > 0) {
		state->recovering = true;
		state->last_timestamp_ms = now_ms;
		xlog_trace(
			"%s: enter recovering grace period: timestamp %" PRIu64
			" backoff %u",
			params->name, state->last_timestamp_ms,
			state->backoff);
	}
}

void
retry_failed(const struct retry_params *params, struct retry_state *state,
	     uint64_t now_ms)
{
	if (state->backoff < params->max_backoff) {
		state->backoff++;
	}
	state->last_timestamp_ms = now_ms;
	state->recovering = false;
	xlog_trace("%s timestamp %" PRIu64 " backoff %u", params->name,
		   state->last_timestamp_ms, state->backoff);
}
