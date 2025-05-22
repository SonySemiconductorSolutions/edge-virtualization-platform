/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stddef.h>
#include <string.h>

#include "cdefs.h"

/* TODO: generate this list automatically. */
/* clang-format off */
static const char(*const list[]) = {
	"agent/status",
	"agent/conn_status",
	"blob/result",
	"deployment/reconcileStatus",
	"mqtt/sync/err",
	"network/error",
	"start",
	"wasm/stopped",
};
/* clang-format on */

int
agent_event_check(const char *event)
{
	for (size_t i = 0; i < __arraycount(list); i++) {
		if (!strcmp(event, list[i])) {
			return 0;
		}
	}

	return -1;
}
