/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <evp/sdk_sys.h>

#include "internal/chan.h"
#include "sys.h"

enum SYS_result
SYS_process_event(struct SYS_client *c, int ms)
{
	if (!c) {
		return SYS_RESULT_ERROR_BAD_PARAMS;
	}

	if (ms < 0) {
		chan_recv(c->ch);
	} else {
		if (!chan_timedrecv(c->ch, ms)) {
			return SYS_RESULT_TIMEDOUT;
		}
	}

	return SYS_RESULT_OK;
}
