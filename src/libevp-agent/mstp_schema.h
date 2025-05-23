/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MSTP_H__
#define MSTP_H__

#include <evp/sdk_types.h>
#include <parson.h>

#include "certificates.h"
#include "models/mstp.h"

struct evp_agent_context;

struct storagetoken_data {
	EVP_RPC_ID reqid; /* Ignored for EVP1 */
	const char *remote_name;
	const char *instance_name;
	const char *storage_name;
};

struct storagetoken_ack_data {
	const char *status;
	const char *error;
	EVP_RPC_ID id;
};

/* EVP1-specific symbols. */

JSON_Value *hub_evp1_storagetoken_request_payload_create(
	struct storagetoken_data *st_data);

int hub_evp1_storagetoken_response_parse(const JSON_Object *payload,
					 struct storagetoken_response *resp);

/* EVP2-specific symbols. */

JSON_Value *hub_evp2_tb_storagetoken_request_payload_create(
	struct storagetoken_data *st_data);

int hub_evp2_storagetoken_response_parse(const JSON_Object *payload,
					 struct storagetoken_response *resp);

int hub_evp2_response_parse_reqid(const char *payload, uintmax_t *reqid);

#endif
