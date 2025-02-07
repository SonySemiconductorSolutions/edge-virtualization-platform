/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE /* asprintf */
#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "evp/sdk.h"
#include "log.h"
#include "parson.h"

/* some data shared with main and callbacks */
struct context {
	int step;
	struct EVP_client *h;

	unsigned int n_calls;
	unsigned int n_requests;
	unsigned int n_responses;
};

static const char *module_name = "RPC";

struct state_cb_data {
	char *blob;
};

struct response_cb_data {
	char *blob;
	struct context *ctx;
	EVP_RPC_ID id;
};

static void
rpc_response_cb(EVP_RPC_RESPONSE_CALLBACK_REASON reason, void *userData)
{
	assert(userData != NULL);
	struct response_cb_data *d = userData;

	log_module(module_name,
		   "%s: EVP_RPC_RESPONSE_CALLBACK called with reason %ju "
		   "(id=%ju)\n",
		   module_name, (uintmax_t)reason, (uintmax_t)d->id);
	json_free_serialized_string(d->blob);
	struct context *ctx = d->ctx;
	assert(ctx != NULL);
	if (ctx->step == 1) {
		ctx->step = 2;
	}
	free(d);
	ctx->n_responses++;
	log_module(module_name, "%s: n_requests=%u, n_responses=%u\n",
		   module_name, ctx->n_requests, ctx->n_responses);
}

static void
rpc_request_cb(EVP_RPC_ID id, const char *method, const char *params,
	       void *userData)
{
	log_module(module_name,
		   "%s: Received RPC request (id=%ju, method=%s, params "
		   "len=%zu)\n",
		   module_name, (uintmax_t)id, method, strlen(params));
	assert(userData != NULL);
	struct context *ctx = userData;
	EVP_RPC_RESPONSE_STATUS status;

	struct response_cb_data *d = malloc(sizeof(*d));
	assert(d != NULL);
	if (!strcmp(method, "echo")) {
		JSON_Value *value = json_parse_string(params);
		assert(value != NULL);

		status = EVP_RPC_RESPONSE_STATUS_OK;
		if (ctx->step == 0) {
			ctx->step = 1;
		}
		d->blob = json_serialize_to_string(value);
		json_value_free(value);
		assert(d->blob != NULL);
		log_module(module_name,
			   "%s: Sending Response (id=%ju, response len=%zu)\n",
			   module_name, (uintmax_t)id, strlen(d->blob));
	} else {
		status = EVP_RPC_RESPONSE_STATUS_METHOD_NOT_FOUND;
		log_module(module_name,
			   "%s: Sending Not-Found Response (id=%ju, "
			   "response=NULL)\n",
			   module_name, (uintmax_t)id);
		d->blob = NULL;
	}
	d->ctx = ctx;
	d->id = id;
	EVP_RESULT result = EVP_sendRpcResponse(ctx->h, id, d->blob, status,
						rpc_response_cb, d);
	assert(result == EVP_OK);
	ctx->n_requests++;
	log_module(module_name, "%s: n_requests=%u, n_responses=%u\n",
		   module_name, ctx->n_requests, ctx->n_responses);
}

static void
state_cb(EVP_STATE_CALLBACK_REASON reason, void *userData)
{
	assert(userData != NULL);
	struct state_cb_data *d = userData;
	assert(d->blob != NULL);
	free(d->blob);
	free(d);
}

int
main(void)
{
	struct context ctx;

	EVP_RESULT result;
	ctx.step = 0;
	int reported_step = -1;

	struct EVP_client *h = EVP_initialize();
	ctx.h = h;
	result = EVP_setRpcCallback(h, rpc_request_cb, &ctx);
	assert(result == EVP_OK);
	ctx.step = 0;
	ctx.n_requests = 0;
	ctx.n_responses = 0;

	/*
	 * g_step = 0: wait for RPC
	 * g_step = 1: got the first "echo" RPC request and
	 *             scheduling the response
	 * g_step = 2: the RPC response completed
	 * g_step = 1000: success
	 */

	for (;;) {
		result = EVP_processEvent(h, 1000);
		if (result == EVP_SHOULDEXIT) {
			break;
		}
		assert(result == EVP_OK || result == EVP_TIMEDOUT);
		if (ctx.step == 2) {
			ctx.step = 1000;
		}
		if (reported_step != ctx.step) {
			const char *topic = "status";
			struct state_cb_data *d = malloc(sizeof(*d));
			assert(d != NULL);
			int ret = asprintf(&d->blob, "g_step = %u", ctx.step);
			assert(ret != -1);
			size_t blob_len = ret;
			log_module(module_name,
				   "%s: Sending State (topic=%s, size=%zu)\n",
				   module_name, topic, blob_len);
			result = EVP_sendState(h, topic, d->blob, blob_len,
					       state_cb, d);
			assert(result == EVP_OK);
			reported_step = ctx.step;
		}
	}
	return 0;
}
