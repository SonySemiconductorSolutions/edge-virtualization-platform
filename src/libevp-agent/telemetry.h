/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef TELEMETRY_H
#define TELEMETRY_H

#include <stdbool.h>
#include <stddef.h>

struct telemetry_entry {
	char *module_instance;
	char *topic;
	char *value;
};

struct telemetry_entries {
	struct telemetry_entry *entries;
	size_t n; // number of entries
};

struct telemetry_entries *telemetry_create(size_t count);
void telemetry_destroy(struct telemetry_entries *telemetry_entries);

struct evp_agent_context;
void telemetry_process(struct evp_agent_context *ctxt);

#endif
