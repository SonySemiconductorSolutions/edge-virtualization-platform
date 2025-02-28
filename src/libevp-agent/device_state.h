/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <parson.h>

/**
 * @brief This function fills a @c JSON_Object with device state data,
 * as defined by the following JSON schema:
 *
 * @param o	JSON object to fill with device state data.
 *
 * @return Returns 0 if successful, -1 otherwise.
 */
int hub_evp1_device_state_add(JSON_Object *o);
int hub_evp2_device_state_add(JSON_Object *o);
