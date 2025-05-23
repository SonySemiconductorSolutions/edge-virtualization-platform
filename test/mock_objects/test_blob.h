/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "test_blob_core.h"

// TODO: handle mocking properly
// This unwraps general mocking of webclient_perform method

int __real_webclient_perform(FAR struct webclient_context *ctx);
int
__wrap_webclient_perform(FAR struct webclient_context *ctx)
{
	char *str;
	xasprintf(&str, "%s %s", ctx->method, ctx->url);
	agent_write_to_pipe(str);
	free(str);
	for (size_t i = 0; i < ctx->nheaders; ++i) {
		agent_write_to_pipe(ctx->headers[i]);
	}
	return __real_webclient_perform(ctx);
}

int __real_evp_send_storagetoken_request(struct evp_agent_context *agent,
					 struct request *req, JSON_Value *v);
int
__wrap_evp_send_storagetoken_request(struct evp_agent_context *agent,
				     struct request *req, JSON_Value *v)
{
	struct test_blob_core_context *ctxt = &g_test_blob_core_context;

	JSON_Object *o = json_value_get_object(v);
	assert_non_null(o);
	o = json_object_get_object(o, "params");
	assert_non_null(o);

	if (agent_test_get_hub_type() != EVP_HUB_TYPE_EVP1_TB) {
		o = json_object_get_object(o, "storagetoken-request");
		assert_non_null(o);
	}

	char *payload = json_serialize_to_string(v);
	size_t i = 0;
	char *match = NULL;
	while (i < __arraycount(ctxt->stp_reqs) && !match) {
		// Requests order is not guarantied so we need to match payload
		// with match instance to map reqid.
		char *blob;
		xasprintf(&blob, ctxt->match_stp_prefix_fmt, i + 1);
		match = strstr(payload, blob);
		if (match) {
			print_message("[   INFO   ] Got storage token for %s "
				      "(reqid=%lu)\n",
				      blob, req->id);
			const char *name =
				json_object_get_string(o, "filename");
			assert_non_null(name);
			ctxt->stp_reqs[i].reqid = req->id;
			ctxt->stp_reqs[i].remote_name = strdup(name);
		} else {
			i++;
		}
		free(blob);
	}
	if (!match) {
		print_error("[   ERROR  ] No match found for reqid %lu\n",
			    req->id);
	}
	json_free_serialized_string(payload);
	return __real_evp_send_storagetoken_request(agent, req, v);
}
