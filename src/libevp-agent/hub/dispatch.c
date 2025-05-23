/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../agent_internal.h"
#include "../device_config.h"
#include "../evp_hub.h"
#include "../hub.h"
#include "../instance_config.h"
#include "../manifest.h"

void
dispatch_persist(JSON_Value *json, struct evp_agent_context *ctxt)
{
	JSON_Value *deployment;
	struct device_config cp;
	struct instance_config_reqs reqs;

	// process deployment manifest if present
	if (!try_load_deployment(json, &deployment)) {
		save_deployment(ctxt, deployment);
	}

	// process device configuration if present
	if (!ctxt->hub->parse_device_config(json, &cp)) {
		hub_received_device_config(ctxt, &cp);
		device_config_dtor(&cp);
	}

	// process module instance configuration if present
	if (!ctxt->hub->parse_instance_config(json, &reqs)) {
		evp_process_instance_config(ctxt, &reqs, EVP_CONFIG_PERSIST);
		instance_config_reqs_dtor(&reqs);
	}
}
