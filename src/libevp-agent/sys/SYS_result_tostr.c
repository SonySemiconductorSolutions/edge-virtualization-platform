/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <evp/sdk_sys.h>

#include "../cdefs.h"

const char *
SYS_result_tostr(enum SYS_result r)
{
	static const char *const results[] = {
		[SYS_RESULT_OK] = "No error",
		[SYS_RESULT_TIMEDOUT] = "Timed out while waiting for an event",
		[SYS_RESULT_ERRNO] = "Failed with an errno value",
		[SYS_RESULT_SHOULD_EXIT] = "Application should exit",
		[SYS_RESULT_ERROR_NO_MEM] = "Not enough memory available",
		[SYS_RESULT_ERROR_BAD_PARAMS] = "Invalid parameters",
		[SYS_RESULT_ERROR_ALREADY_REGISTERED] = "Already registered",
	};

	if (r < 0 || (unsigned)r >= __arraycount(results)) {
		return "Unknown error code";
	}

	return results[r];
}
