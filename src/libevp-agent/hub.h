/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef HUB_H
#define HUB_H

#include <stdbool.h>

#include <parson.h>

#include "evp_hub.h"
#include "models/models.h"

#define HUB_EVP1_NAME "EVP1"
#define HUB_TB_NAME   "TB"

struct mqtt_client;
struct mqtt_response_publish;

struct request;
struct mqtt_client;
struct evp_agent_context;

/**
 * Apply business logic to a message received from the Hub.
 */
void dump_global(void);
void dispatch_persist(JSON_Value *json, struct evp_agent_context *ctxt);

#endif
