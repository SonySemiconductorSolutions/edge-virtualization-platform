/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>

#include <evp/sdk_types.h>
#include <parson.h>

struct direct_command_request {
	EVP_RPC_ID reqid;
	char *method;
	char *instance;
	char *params;
};

enum direct_command_response_status {
	DIRECT_COMMAND_RESPONSE_STATUS_OK,
	DIRECT_COMMAND_RESPONSE_STATUS_METHOD_NOT_FOUND,
	DIRECT_COMMAND_RESPONSE_STATUS_ERROR
};

struct direct_command_response {
	EVP_RPC_ID reqid;
	enum direct_command_response_status status;
	char *response;
	char *errorMessage;
	char *instance; // used only in EVP1
};

struct evp_agent_context;

/**
 * Allocate and initialise a direct command request.
 * @return NULL if initialisation failed
 */
struct direct_command_request *
direct_command_request_ctor(EVP_RPC_ID id, const char *method,
			    const char *instance, const char *params);

/**
 * Destroy and free a direct_command_response.
 */
void direct_command_request_dtor(struct direct_command_request *obj);

/**
 * Parse an EVP1 payload into a direct command request
 * @return NULL if payload is invalid or initialisation failed
 */
struct direct_command_request *parse_evp1_direct_command(EVP_RPC_ID id,
							 JSON_Value *payload);

/**
 * Parse an EVP2 payload into a direct command request
 * @return NULL if payload is invalid or initialisation failed
 */
struct direct_command_request *parse_evp2_direct_command(JSON_Value *payload);

/**
 * Allocate and initialise a direct_command_response.
 * @return NULL if initialisation failed
 */
struct direct_command_response *
direct_command_response_ctor(EVP_RPC_ID id, const char *response,
			     enum direct_command_response_status status,
			     const char *instance);

/**
 * Destroy and free a direct_command_response.
 */
void direct_command_response_dtor(struct direct_command_response *obj);

/**
 * Create a direct command response payload compliant with the EVP1 schema
 */
JSON_Value *compose_evp1_direct_command_response_payload(
	struct direct_command_response *response);

/**
 * Create a direct command response payload compliant with the EVP2 schema
 */
JSON_Value *compose_evp2_direct_command_response_payload(
	struct direct_command_response *response);

/**
 * Collect and process direct command responses from the modules.
 */
void direct_command_process(struct evp_agent_context *ctxt);

/**
 * Apply business logic to a direct command request received from the hub
 */
void evp_process_direct_command_request(struct evp_agent_context *ctxt,
					struct direct_command_request *req);
