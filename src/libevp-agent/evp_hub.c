/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <config.h>

#include <malloc.h>
#include <strings.h>

#include <internal/util.h>

#include "backdoor.h"
#include "device_config.h"
#include "device_state.h"
#include "evp_hub.h"
#include "hub.h"
#include "hub/hub_tb.h"
#include "instance_config.h"
#include "manifest.h"
#include "mstp_schema.h"
#include "report.h"
#include "system_info.h"
#include "xlog.h"

static const struct evp_hub_context hub_evp2_tb = {
	.on_message = hub_evp2_tb_on_message,
	.on_connected = hub_evp2_tb_on_connected,
	.is_ready = hub_tb_is_ready_to_report,
	.send_telemetry = hub_tb_send_telemetry,
	.device_state_add = hub_evp2_device_state_add,
	.deployment_status_add = hub_evp2_tb_deployment_status_add,
	.get_system_info = hub_evp2_tb_get_system_info,
	.send_direct_command_response =
		hub_tb_evp2_send_direct_command_response,
	.send_periodic_report = hub_tb_send_periodic_report,
	.storagetoken_request_payload_create =
		hub_evp2_tb_storagetoken_request_payload_create,
	.send_storagetoken_request = hub_tb_send_rpc_request,
	.parse_device_config = hub_evp2_parse_device_config,
	.update_desired_device_config = hub_evp2_update_desired_device_config,
	.parse_instance_config = hub_evp2_parse_instance_config,
	.storagetoken_response_parse = hub_evp2_storagetoken_response_parse,
	.parse_deployment = parse_deployment_evp2,
	.convert_state = hub_evp2_convert_state,
	.notify_config = hub_evp2_notify_config,
	.check_backdoor = hub_evp2_check_backdoor,
	.impl_name = "EVP2-TB",
};

static const struct evp_hub_context hub_evp1 = {
	.on_message = hub_evp1_tb_on_message,
	.on_connected = hub_evp1_tb_on_connected,
	.is_ready = hub_tb_is_ready_to_report,
	.send_telemetry = hub_tb_send_telemetry,
	.device_state_add = hub_evp1_device_state_add,
	.deployment_status_add = hub_evp1_deployment_status_add,
	.get_system_info = hub_evp1_get_system_info,
	.send_direct_command_response =
		hub_tb_evp1_send_direct_command_response,
	.send_periodic_report = hub_tb_send_periodic_report,
	.storagetoken_request_payload_create =
		hub_evp1_storagetoken_request_payload_create,
	.send_storagetoken_request = hub_tb_send_rpc_request,
	.parse_device_config = hub_evp2_parse_device_config,
	.update_desired_device_config = hub_evp2_update_desired_device_config,
	.parse_instance_config = hub_evp1_parse_instance_config,
	.storagetoken_response_parse = hub_evp1_storagetoken_response_parse,
	.parse_deployment = parse_deployment_evp1,
	.convert_state = hub_evp1_convert_state,
	.notify_config = hub_evp1_notify_config,
	.check_backdoor = hub_evp1_check_backdoor,
	.impl_name = "EVP1",
};

static const struct evp_hub_context *
get_context(enum evp_hub_type hub_type)
{
	const struct evp_hub_context *hub_selected = NULL;
	switch (hub_type) {
	case EVP_HUB_TYPE_EVP2_TB:
		{
			hub_selected = &hub_evp2_tb;
			break;
		}

	case EVP_HUB_TYPE_EVP1_TB:
		{
			hub_selected = &hub_evp1;
			break;
		}

	default:
		break;
	}

	return hub_selected;
}

const struct evp_hub_context *
evp_hub_setup(const char *iot_platform)
{
	const enum evp_hub_type hub_type = get_hub_type(iot_platform);
	const struct evp_hub_context *ctxt = get_context(hub_type);

	xlog_abortif(ctxt == NULL, "Unsupported EVP_IOT_PLATFORM=%s\n",
		     iot_platform);

	return ctxt;
}

enum evp_hub_type
get_hub_type(const char *iot_platform)
{
	/* Assume EVP1 TB by default, even for invalid 'iot_platform' */
	enum evp_hub_type hub_type = EVP_HUB_TYPE_EVP1_TB;

	if (iot_platform != NULL) {
		if (strcasecmp(iot_platform, HUB_TB_NAME) == 0) {
			hub_type = EVP_HUB_TYPE_EVP2_TB;
		}
	}

	return hub_type;
}
