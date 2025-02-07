/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AGENT_INTERNAL_H
#define AGENT_INTERNAL_H

#include <evp/agent.h>

#include "deployment.h"
#include "evp_hub.h"
#include "report.h"
#include "tls.h"
#include "transport.h"
#include "xpthread.h"

struct sys_group;

struct evp_agent_context {
	struct report_params report_params;
	struct report_state report_status;
	struct report_state report_instance_state;
	struct transport_ctxt *transport_ctxt;
	const struct evp_hub_context *hub;
	struct evp_lock lock;
	struct deployment deployment;
	enum evp_agent_status status;
	struct tls_context *tls_context;
	struct sys_group *sys;
};

#endif
