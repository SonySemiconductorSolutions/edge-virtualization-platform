/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <internal/chan.h>

#include "sys.h"

int
sys_process_events(struct sys_group *gr)
{
	if (chan_tryrecv(gr->ch) < 0) {
		return -1;
	}

	return 0;
}
