/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>

#include "sys.h"

void
sys_telemetry_dealloc(struct sys_telemetry *t)
{
	if (t) {
		free(t->topic);
		free(t->value);
	}

	free(t);
}
