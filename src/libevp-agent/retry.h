/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <stdint.h>

struct retry_params {
	/*
	 * Human readable name for logging.
	 * Also used as "name" for the main_loop.h API.
	 * It's recommended to use a string unique within the code base.
	 */
	const char *name;

	/*
	 * Max backoff.
	 *
	 * This effectively controls the max retry interval,
	 * which is (1 << (max_backoff - 1)) seconds.
	 */
	unsigned int max_backoff;

	/*
	 * For some situations, it's desirable to avoid resetting the
	 * backoff too soon, even after successful attempts.
	 *
	 * The state will be reset only when no failure has been observed
	 * for this period.
	 */
	uint64_t recovering_grace_period_ms;
};

/*
 * Note: struct retry_state is considered internal to retry.c.
 * Only the code within retry.c should access its members directly.
 */

struct retry_state {
	/*
	 * last_timestamp_ms is valid only when backoff > 0 || recovering.
	 *
	 * If recovering, last_timestamp_ms is the timestamp of
	 * the first successful attempt, which has started the recovering
	 * grace period.
	 * Otherwise, if backoff > 0, last_timestamp_ms is the timestamp of
	 * the latest failed attempt.
	 */
	uint64_t last_timestamp_ms;
	unsigned int backoff;
	bool recovering;
};

void retry_state_init(struct retry_state *state);
bool retry_check(const struct retry_params *params, struct retry_state *state,
		 uint64_t now_ms);
void retry_succeeded(const struct retry_params *params,
		     struct retry_state *state, uint64_t now_ms);
void retry_failed(const struct retry_params *params, struct retry_state *state,
		  uint64_t now_ms);
