/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <parson.h>

/**
 * Get the info from the system (machine, version, ...)
 *
 * @return A valid json object, NULL in case of error.
 */
JSON_Value *hub_evp1_get_system_info(void);
JSON_Value *hub_evp2_tb_get_system_info(void);
