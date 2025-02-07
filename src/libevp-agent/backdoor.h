/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef BACKDOOR_H
#define BACKDOOR_H

#include <stdbool.h>

#include <parson.h>

struct evp_agent_context;

bool is_backdoor_prefixed(const char *entry_point);

int hub_evp1_check_backdoor(const JSON_Value *deployment,
			    const char *instanceId, bool *out);
int hub_evp2_check_backdoor(const JSON_Value *deployment,
			    const char *instanceId, bool *out);

#endif
