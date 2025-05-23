/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <evp/sdk_sys.h>

#include "../cdefs.h"

const char *
SYS_reason_tostr(enum SYS_callback_reason r)
{
	static const char *const reasons[] = {
		[SYS_REASON_FINISHED] = "Finished",
		[SYS_REASON_TIMEOUT] = "Timed out",
		[SYS_REASON_ERROR] = "An error occurred",
	};

	if (r < 0 || (unsigned)r >= __arraycount(reasons)) {
		return "Unknown error code";
	}

	return reasons[r];
}
