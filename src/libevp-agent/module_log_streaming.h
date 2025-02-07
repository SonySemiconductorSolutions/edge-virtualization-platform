/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MODULE_LOG_STREAMING_H
#define MODULE_LOG_STREAMING_H

#include "telemetry.h"

struct evp_agent_context;
int module_log_streaming_flush(struct evp_agent_context *ctxt);
void module_log_send_telemetry(struct evp_agent_context *ctxt,
			       struct telemetry_entries *telemetries);
void module_log_streaming_report(struct evp_agent_context *ctxt);

#endif // MODULE_LOG_STREAMING_H
