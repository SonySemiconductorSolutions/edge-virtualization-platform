/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "agent_internal.h"
#include "module_log_streaming.h"
#include "telemetry.h"

void
module_log_send_telemetry(struct evp_agent_context *ctxt,
			  struct telemetry_entries *telemetries)
{
	ctxt->hub->send_telemetry(ctxt->transport_ctxt, telemetries);
}
