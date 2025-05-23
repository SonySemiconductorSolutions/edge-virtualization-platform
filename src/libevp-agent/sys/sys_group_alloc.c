/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>

#include <internal/chan.h>
#include <internal/string_map.h>

#include "sys.h"

#define NR_MAP_CFG   32
#define NR_MAP_DDC   32
#define NR_MAP_STATE 32

struct sys_group *
sys_group_alloc(void)
{
	struct sys_group *gr;

	if ((gr = malloc(sizeof(*gr))) == NULL)
		return NULL;

	*gr = (struct sys_group){
		.cfg_map = string_map_alloc(NR_MAP_CFG, NULL),
		.ddc_map = string_map_alloc(NR_MAP_DDC, sys_ddc_dealloc),
		.state_map = string_map_alloc(NR_MAP_STATE, sys_state_dealloc),
		.ch = chan_alloc(),
	};

	if (!gr->cfg_map || !gr->ddc_map || !gr->ch || !gr->state_map)
		goto error;

	return gr;

error:
	sys_group_dealloc(gr);
	return NULL;
}
