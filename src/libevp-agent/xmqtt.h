/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <stddef.h>

#include "mqtt_custom.h"

void mqtt_prepare_poll(struct mqtt_client *client, bool *want_writep);
bool xmqtt_request_fits(struct mqtt_client *client, size_t len);
