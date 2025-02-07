/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>

#include "sys.h"

void
sys_ddc_dealloc(void *p)
{
	struct sys_command *cmd = p;

	free(cmd->command);
	free(cmd);
}
