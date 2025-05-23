/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include <internal/string_map.h>

#include "sys.h"

const char *const sys_prefix = "$system";

bool
sys_is_sysapp(const char *name)
{
	return strncmp(name, sys_prefix, strlen(sys_prefix)) == 0;
}
