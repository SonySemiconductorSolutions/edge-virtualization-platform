/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Header used by implementations of the evp_config.h interface
 */
#include <stdbool.h>

#include <evp/agent_config.h>

#include "evp_config.h"

bool is_config_optional(enum config_key);
int config_load_pk_file(const char *, void **, size_t *);
void config_unload_pk_file(void *, size_t);
