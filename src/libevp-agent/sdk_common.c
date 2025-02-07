/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE
#include <config.h>

#include <assert.h>
#include <errno.h>
#include <semaphore.h>
#include <stdlib.h>
#include <string.h>

#include "blob.h"
#include "evp/sdk.h"
#include "evp/sdk_blob_http_ext.h"
#include "sdk_callback_impl_ops.h"
#include "sdk_common.h"
#include "sdk_impl.h"
#include "xlog.h"

EVP_RESULT
sdk_common_execute_event(const struct sdk_callback_impl_ops *ops,
			 const struct sdk_common_callbacks *cb,
			 struct sdk_event *event, void *ctx)
{
	switch (event->type) {
	case SDK_EVENT_CONFIG:
		{
			struct sdk_event_config *config = (void *)event;
			if (cb->config_cb != NULL) {
				ops->invoke_config_callback(
					ctx, cb->config_cb, config->topic,
					config->blob, config->bloblen,
					cb->config_cb_userdata);
			}
		}
		break;
	case SDK_EVENT_STATE:
		{
			struct sdk_event_state *state = (void *)event;
#if defined(SDK_LOG_VERBOSE)
			printf("state->cb %p %u %p\n", state->cb,
			       state->reason, state->cb_userdata);
#endif
			ops->invoke_state_callback(ctx, state->cb,
						   state->reason,
						   state->cb_userdata);
		}
		break;
	case SDK_EVENT_BLOB:
		{
			struct sdk_event_blob *blob = (void *)event;
			return sdk_execute_event_blob(blob, ops, ctx);
		}
	case SDK_EVENT_TELEMETRY:
		{
			struct sdk_event_telemetry *t = (void *)event;
			ops->invoke_telemetry_callback(ctx, t->cb, t->reason,
						       t->cb_userdata);
		}
		break;
	case SDK_EVENT_MESSAGE_RECEIVED:
		{
			struct sdk_event_message_received *m = (void *)event;
			if (cb->in_msg_cb != NULL) {
				ops->invoke_message_received_callback(
					ctx, cb->in_msg_cb, m->topic, m->blob,
					m->bloblen, cb->in_msg_cb_userdata);
			}
		}
		break;
	case SDK_EVENT_MESSAGE_SENT:
		{
			struct sdk_event_message_sent *m = (void *)event;
			ops->invoke_message_sent_callback(
				ctx, m->cb, m->reason, m->cb_userdata);
		}
		break;
	case SDK_EVENT_RPC_REQUEST:
		{
			struct sdk_event_rpc_request *rpc = (void *)event;
			if (cb->rpc_cb != NULL) {
				ops->invoke_rpc_request_callback(
					ctx, cb->rpc_cb, rpc->id, rpc->method,
					rpc->params, cb->rpc_cb_userdata);
			}
		}
		break;
	case SDK_EVENT_RPC_RESPONSE:
		{
			struct sdk_event_rpc_response *rpc = (void *)event;
			ops->invoke_rpc_response_callback(
				ctx, rpc->cb, rpc->reason, rpc->cb_userdata);
		}
		break;

	case SDK_EVENT_STREAM_READ_AVAILABLE:
		{
			struct sdk_event_stream_read_available *read =
				(void *)event;
			ops->invoke_stream_read_available_callback(
				ctx, read->cb, read->id, read->buf, read->n,
				read->cb_userdata);
		}

		break;
	case SDK_EVENT_BLOB_GET_UPLOAD_URL:
		{
			struct sdk_event_blob *blob = (void *)event;
			return sdk_execute_get_upload_url(blob, ops, ctx);
		}
	case SDK_EVENT_BLOB_IO_READ:
		{
			struct sdk_event_blob_io *io = (void *)event;
			return sdk_execute_blob_io_read(io, ops, ctx);
		}
	case SDK_EVENT_BLOB_IO_WRITE:
		{
			struct sdk_event_blob_io *io = (void *)event;
			return sdk_execute_blob_io_write(io, ops, ctx);
		}

		break;

	default:
		// TODO: Replace assert (programming error)
		assert(0);
	}
	return EVP_OK;
}

struct EVP_BlobRequestHttpExt *
EVP_BlobRequestHttpExt_initialize(void)
{
	struct EVP_BlobRequestHttpExt *request =
		malloc(sizeof(struct EVP_BlobRequestHttpExt));
	if (request) {
		request->url = NULL;
		request->nheaders = 0;
		request->headers = NULL;
	}
	return request;
}

void
EVP_BlobRequestHttpExt_free(struct EVP_BlobRequestHttpExt *request)
{
	for (unsigned int i = 0; i < request->nheaders; i++) {
		free((void *)request->headers[i]);
	}
	free((void *)request->headers);
	free((void *)request->url);
	free(request);
}

EVP_RESULT
EVP_BlobRequestHttpExt_addHeader(struct EVP_BlobRequestHttpExt *request,
				 const char *name, const char *value)
{
	if (!request || !name || !value) {
		return EVP_INVAL;
	}

	if (request->nheaders > 100) {
		return EVP_TOOBIG;
	}

	request->headers =
		realloc((void *)request->headers,
			(request->nheaders + 1) * sizeof(*request->headers));
	if (!request->headers) {
		return EVP_NOMEM;
	}

	int ret = asprintf((char **)&request->headers[request->nheaders],
			   "%s: %s", name, value);
	if (ret == -1) {
		return EVP_ERROR;
	}
	request->nheaders++;
	return EVP_OK;
}

EVP_RESULT
EVP_BlobRequestHttpExt_addAzureHeader(struct EVP_BlobRequestHttpExt *request)
{
	return EVP_BlobRequestHttpExt_addHeader(request, "x-ms-blob-type",
						"BlockBlob");
}

EVP_RESULT
EVP_BlobRequestHttpExt_setUrl(struct EVP_BlobRequestHttpExt *request,
			      char *url)
{
	if (!request || !url) {
		return EVP_INVAL;
	}

	char *new_url = strdup(url);
	if (!new_url) {
		return EVP_NOMEM;
	}
	free(request->url);
	request->url = new_url;

	return EVP_OK;
}
