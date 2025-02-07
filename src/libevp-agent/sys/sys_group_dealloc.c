/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>

#include <internal/chan.h>
#include <internal/string_map.h>

#include "sys.h"

static void
free_telemetries(struct sys_group *gr)
{
	struct sys_telemetry *t, *next;

	for (t = gr->telemetries; t; t = next) {
		next = t->next;

		sys_telemetry_dealloc(t);
	}
}

static int
free_cfg(const char *topic, void *value, void *user)
{
	struct sys_config *cfg, *next;

	for (cfg = value; cfg; cfg = next) {
		next = cfg->next;
		free(cfg);
	}

	return -1;
}

void
sys_group_dealloc(struct sys_group *gr)
{
	struct SYS_client *next;

	if (!gr)
		return;

	for (struct SYS_client *p = gr->list; p; p = next) {
		next = p->next;
		sys_client_dealloc(p);

		if (next == gr->list) {
			break;
		}
	}

	chan_dealloc(gr->ch);
	string_map_dealloc(gr->state_map);
	string_map_dealloc(gr->ddc_map);
	string_map_forall(gr->cfg_map, free_cfg, NULL);
	string_map_dealloc(gr->cfg_map);
	free_telemetries(gr);
	free(gr);
}
