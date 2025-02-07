/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "blob.h"
#include "cdefs.h"
#include "event.h"
#include "evp/sdk.h"
#include "local_socket.h"
#include "path_docker.h"
#include "sdk_callback_impl_ops.h"
#include "sdk_common.h"
#include "sdkenc/sdk_builder.h"
#include "sdkenc/sdk_reader.h"
#include "sdkenc/sdk_verifier.h"
#include "sdkrpc/client.h"
#include "sdkutil.h"
#include "stream/stream.h"
SDK_CALLBACK_IMPL_OPS_DECLARE(native);

#undef ns
#define ns(a) FLATBUFFERS_WRAP_NAMESPACE(EVP_SDK, a)

struct manifest_stream {
	TAILQ_ENTRY(manifest_stream) q;
	struct Stream stream;
};

struct EVP_client {
	TAILQ_HEAD(, sdk_event) events;

	struct sdk_client clnt;
	struct sdk_request *get_event_req;
	bool exiting;
	bool timed_out_on_server;

	struct sdk_common_callbacks cb;
	struct stream_queue streams;
	TAILQ_HEAD(, manifest_stream) manifest_streams;
	pthread_mutex_t mutex;
};

static struct EVP_client our_handle = {
	.streams = TAILQ_HEAD_INITIALIZER(our_handle.streams),
	.manifest_streams =
		TAILQ_HEAD_INITIALIZER(our_handle.manifest_streams),
	.clnt.transport.fds = {-1, -1},
	.mutex = PTHREAD_MUTEX_INITIALIZER,
};

static const char *
getenv_with_default(const char *name, const char *default_value)
{
	const char *value = getenv(name);
	if (value != NULL) {
		return value;
	}
	return default_value;
}

static const char *
get_sdk_socket_path(void)
{
	return getenv_with_default("EVP_MODULE_SDK_SOCKET_PATH",
				   DOCKER_SDK_SOCKET_PATH);
}

static const char *
get_default_workspace_path(void)
{
	return getenv_with_default("EVP_MODULE_SDK_DEFAULT_WORKSPACE_PATH",
				   DOCKER_DEFAULT_WORKSPACE_PATH);
}

static void
req_done(struct sdk_request *req)
{
	// TODO: Replace assert (programming error)
	assert(req != NULL);
	// TODO: Replace assert (programming error)
	assert(req->resp != NULL);
#if defined(SDK_LOG_VERBOSE)
	printf("req_done called for xid %ju\n", (uintmax_t)req->xid);
#endif
	if (req->user == NULL) {
		sdk_request_free(req);
	}
}

static void
get_event_done(struct sdk_request *req)
{
	// TODO: Replace assert (programming error)
	assert(req != NULL);
	// TODO: Replace assert (programming error)
	assert(req->resp != NULL);

	struct EVP_client *h = req->user;
	// TODO: Replace assert (programming error)
	assert(h != NULL);
	void *raw_resp = req->resp;

	int ret = ns(Response_verify_as_root(raw_resp, req->resplen));
	if (ret != 0) {
		printf("verify failed: %s\n", flatcc_verify_error_string(ret));
		sdk_request_free(req);
		/*
		 * we have no way to recover.
		 */
		h->exiting = true;
		return;
	}

	ns(Response_table_t) resp = ns(Response_as_root(raw_resp));
	// TODO: Replace assert (runtime error)
	assert(ns(Response_body_type(resp)) == ns(ResponseUnion_getEvent));
	ns(Event_table_t) ev = ns(Response_body(resp));
	EVP_SDK_EventBody_union_type_t event_type = ns(Event_body_type(ev));
#if defined(SDK_LOG_VERBOSE)
	printf("get_event_done called for xid %ju type %u\n",
	       (uintmax_t)req->xid, (unsigned int)event_type);
#endif
	if (event_type == ns(EventBody_exit)) {
		h->exiting = true;
	} else {
		switch (event_type) {
		case ns(EventBody_NONE):
			{
				/* nothing */
				h->timed_out_on_server = true;
				break;
			}
		case ns(EventBody_config):
			{
				ns(Config_table_t) e = ns(Event_body(ev));
				struct sdk_event_config *config =
					xmalloc(sizeof(*config));
				config->event.type = SDK_EVENT_CONFIG;
				config->event.buffer = raw_resp;
				req->resp = NULL;
				config->topic = ns(Config_topic(e));
				flatbuffers_uint8_vec_t blob_vec =
					ns(Config_blob(e));
				config->blob = blob_vec;
				config->bloblen =
					flatbuffers_uint8_vec_len(blob_vec);
				TAILQ_INSERT_TAIL(&h->events, &config->event,
						  q);
				break;
			}
		case ns(EventBody_state):
			{
				ns(StateOutput_table_t) e = ns(Event_body(ev));
				struct sdk_event_state *state =
					xmalloc(sizeof(*state));
				state->event.buffer = NULL;
				state->event.type = SDK_EVENT_STATE;
				state->cb = (void *)(uintptr_t)ns(
					StateOutput_cb(e));
				state->reason = ns(StateOutput_reason(e));
				state->cb_userdata = (void *)(uintptr_t)ns(
					StateOutput_cb_userdata(e));
				TAILQ_INSERT_TAIL(&h->events, &state->event,
						  q);
				break;
			}
		case ns(EventBody_blob):
			{
				ns(BlobOutput_table_t) e = ns(Event_body(ev));
				struct sdk_event_blob *blob =
					xmalloc(sizeof(*blob));
				blob->event.buffer = NULL;
				blob->event.type = SDK_EVENT_BLOB;
				blob->user_cb.cb = (void *)(uintptr_t)ns(
					BlobOutput_cb(e));
				blob->reason = ns(BlobOutput_reason(e));
				blob->user_cb.cb_data = (void *)(uintptr_t)ns(
					BlobOutput_cb_userdata(e));
				ns(BlobResultUnion_union_type_t) result_type =
					ns(BlobOutput_result_type(e));
				switch (result_type) {
				case ns(BlobResultUnion_NONE):
					blob->result = NULL;
					break;
				case ns(BlobResultUnion_azureBlob):
					{
						ns(BlobResultAzureBlob_table_t)
							result = ns(
								BlobOutput_result(
									e));
						struct EVP_BlobResultAzureBlob *
							azure_result = xmalloc(sizeof(
								*azure_result));
						azure_result->result = ns(
							BlobResultAzureBlob_result(
								result));
						azure_result->http_status = ns(
							BlobResultAzureBlob_http_status(
								result));
						azure_result->error = ns(
							BlobResultAzureBlob_error(
								result));
						blob->result = azure_result;
						break;
					}
				case ns(BlobResultUnion_evp):
					{
						ns(BlobResultEvp_table_t) result =
							ns(BlobOutput_result(
								e));
						struct EVP_BlobResultEvp *
							evp_result = xmalloc(sizeof(
								*evp_result));
						evp_result->result = ns(
							BlobResultEvp_result(
								result));
						evp_result->http_status = ns(
							BlobResultEvp_http_status(
								result));
						evp_result->error =
							ns(BlobResultEvp_error(
								result));
						blob->result = evp_result;
						break;
					}
				case ns(BlobResultUnion_http):
					{
						ns(BlobResultHttp_table_t)
							result = ns(
								BlobOutput_result(
									e));
						struct EVP_BlobResultHttp *
							http_result = xmalloc(sizeof(
								*http_result));
						http_result->result = ns(
							BlobResultHttp_result(
								result));
						http_result->http_status = ns(
							BlobResultHttp_http_status(
								result));
						http_result->error = ns(
							BlobResultHttp_error(
								result));
						blob->result = http_result;
						break;
					}
				}
				TAILQ_INSERT_TAIL(&h->events, &blob->event, q);
				break;
			}
		case ns(EventBody_telemetry):
			{
				ns(TelemetryOutput_table_t) e =
					ns(Event_body(ev));
				struct sdk_event_telemetry *t =
					xmalloc(sizeof(*t));
				t->event.buffer = NULL;
				t->event.type = SDK_EVENT_TELEMETRY;
				t->cb = (void *)(uintptr_t)ns(
					TelemetryOutput_cb(e));
				t->reason = ns(TelemetryOutput_reason(e));
				t->cb_userdata = (void *)(uintptr_t)ns(
					TelemetryOutput_cb_userdata(e));
				TAILQ_INSERT_TAIL(&h->events, &t->event, q);
				break;
			}
		case ns(EventBody_messageReceived):
			{
				ns(MessageReceived_table_t) e =
					ns(Event_body(ev));
				struct sdk_event_message_received *m =
					xmalloc(sizeof(*m));
				m->event.type = SDK_EVENT_MESSAGE_RECEIVED;
				m->event.buffer = raw_resp;
				req->resp = NULL;
				m->topic = ns(MessageReceived_topic(e));
				flatbuffers_uint8_vec_t blob_vec =
					ns(MessageReceived_blob(e));
				m->blob = blob_vec;
				m->bloblen =
					flatbuffers_uint8_vec_len(blob_vec);
				TAILQ_INSERT_TAIL(&h->events, &m->event, q);
				break;
			}
		case ns(EventBody_messageSent):
			{
				ns(MessageSentOutput_table_t) e =
					ns(Event_body(ev));
				struct sdk_event_message_sent *m =
					xmalloc(sizeof(*m));
				m->event.type = SDK_EVENT_MESSAGE_SENT;
				m->event.buffer = NULL;
				m->cb = (void *)(uintptr_t)ns(
					MessageSentOutput_cb(e));
				m->reason = ns(MessageSentOutput_reason(e));
				m->cb_userdata = (void *)(uintptr_t)ns(
					MessageSentOutput_cb_userdata(e));
				TAILQ_INSERT_TAIL(&h->events, &m->event, q);
				break;
			}
		case ns(EventBody_rpcRequest):
			{
				ns(RpcRequest_table_t) e = ns(Event_body(ev));
				struct sdk_event_rpc_request *r =
					xmalloc(sizeof(*r));
				r->event.type = SDK_EVENT_RPC_REQUEST;
				r->event.buffer = raw_resp;
				req->resp = NULL;
				r->id = ns(RpcRequest_id(e));
				r->method = ns(RpcRequest_method(e));
				r->params = ns(RpcRequest_params(e));
				TAILQ_INSERT_TAIL(&h->events, &r->event, q);
				break;
			}
		case ns(EventBody_rpcResponse):
			{
				ns(RpcResponseOutput_table_t) e =
					ns(Event_body(ev));
				struct sdk_event_rpc_response *r =
					xmalloc(sizeof(*r));
				r->event.type = SDK_EVENT_RPC_RESPONSE;
				r->event.buffer = NULL;
				r->cb = (void *)(uintptr_t)ns(
					RpcResponseOutput_cb(e));
				r->reason = ns(RpcResponseOutput_reason(e));
				r->cb_userdata = (void *)(uintptr_t)ns(
					RpcResponseOutput_cb_userdata(e));
				TAILQ_INSERT_TAIL(&h->events, &r->event, q);
				break;
			}
		}
	}

	h->get_event_req = NULL;
	sdk_request_free(req);
}

static void
sdk_free_event(struct sdk_event *event)
{
	switch (event->type) {
	case SDK_EVENT_CONFIG:
		/* fallthrough */

	case SDK_EVENT_STATE:
		/* nothing */
		break;

	case SDK_EVENT_BLOB:
		{
			struct sdk_event_blob *blob = (void *)event;
			free(blob->result);
			break;
		}

	case SDK_EVENT_TELEMETRY:
		/* nothing */
		break;

	case SDK_EVENT_MESSAGE_RECEIVED:
		/* nothing */
		break;

	case SDK_EVENT_MESSAGE_SENT:
		/* nothing */
		break;

	case SDK_EVENT_RPC_REQUEST:
		/* nothing */
		break;

	case SDK_EVENT_RPC_RESPONSE:
		/* nothing */
		break;

	case SDK_EVENT_STREAM_READ_AVAILABLE:
		{
			struct sdk_event_stream_read_available *read =
				(void *)event;
			read->free(read->free_args);
		}
		break;

	default:
		// TODO: Replace assert (programming error)
		assert(0);
	}
	free(__UNCONST(event->buffer));
	free(event);
}

static int
on_input_stream(void *addr, void *user)
{
	struct EVP_client *h = user;
	struct sdk_event_stream_read_available *r = addr;

	TAILQ_INSERT_TAIL(&h->events, &r->event, q);
	return 0;
}

struct EVP_client *
EVP_initialize(void)
{
	const char *path = get_sdk_socket_path();
	struct EVP_client *h = &our_handle;

	int fd;
	int ret;

	ret = local_connect_to(path, &fd);
	// TODO: Replace assert (runtime error)
	assert(ret == 0);
	// TODO: Replace assert (programming error)
	assert(fd >= 0);

	TAILQ_INIT(&h->events);
	h->get_event_req = NULL;
	h->exiting = false;
	h->timed_out_on_server = false;
	struct sdk_client *clnt = &h->clnt;
	sdk_clnt_setup(clnt, fd);
	struct sdk_transport *t = &clnt->transport;
	t->on_stream_input = on_input_stream;
	t->user = h;
	return h;
}

const char *
EVP_getWorkspaceDirectory(struct EVP_client *h, EVP_WORKSPACE_TYPE type)
{
	// TODO: Replace assert (programming error)
	assert(type == EVP_WORKSPACE_TYPE_DEFAULT);
	return get_default_workspace_path();
}

static EVP_RESULT
simple_call(struct EVP_client *h, void *buf, size_t buflen)
{
	if (buf == NULL) {
		return EVP_NOMEM;
	}
	struct sdk_request *req = sdk_request_alloc();
	if (req == NULL) {
		flatcc_builder_aligned_free(buf);
		return EVP_NOMEM;
	}
	req->done = req_done;
	req->user = h;
	req->buf = buf;
	req->buflen = buflen;
	req->buf_free = flatcc_builder_aligned_free;
	sdk_clnt_enqueue(&h->clnt, req);
	struct timespec abstimeout;
	unsigned int timeout_ms = 30 * 1000; // 30 seconds
	relms2absts_realtime(timeout_ms, &abstimeout);
	do {
		int ret = sdk_clnt_sync_ts(&h->clnt, &abstimeout);
		if (ret != 0) {
			/*
			 * tell req_done free the request
			 */
			req->user = NULL;
			if (ret == ETIMEDOUT) {
				return EVP_TIMEDOUT;
			}
			return EVP_ERROR;
		}
	} while (req->resp == NULL);
	const void *raw_resp = req->resp;
	int ret = ns(Response_verify_as_root(raw_resp, req->resplen));
	if (ret != 0) {
		printf("verify failed: %s\n", flatcc_verify_error_string(ret));
		sdk_request_free(req);
		return EVP_AGENT_PROTOCOL_ERROR;
	}
	ns(Response_table_t) resp = ns(Response_as_root(raw_resp));
	if (ns(Response_body_type(resp)) != ns(ResponseUnion_simple)) {
		sdk_request_free(req);
		return EVP_AGENT_PROTOCOL_ERROR;
	}
	ns(Simple_table_t) ev = ns(Response_body(resp));
	EVP_RESULT result = ns(Simple_result(ev));
	sdk_request_free(req);
	return result;
}

EVP_RESULT
EVP_setConfigurationCallback(struct EVP_client *h,
			     EVP_CONFIGURATION_CALLBACK cb, void *userData)
{
	if (h->cb.config_cb != NULL) {
		return EVP_ERROR;
	}

	flatcc_builder_t builder;
	flatcc_builder_t *b = &builder;
	flatcc_builder_init(b);
	ns(Request_start_as_root(b));
	ns(Request_body_requestResendConfig_start(b));
	ns(Request_body_requestResendConfig_end(b));
	ns(Request_end_as_root(b));
	size_t buflen;
	void *buf = flatcc_builder_finalize_aligned_buffer(b, &buflen);
	flatcc_builder_clear(b);
	EVP_RESULT result = simple_call(h, buf, buflen);
	if (result == EVP_OK) {
		h->cb.config_cb = cb;
		h->cb.config_cb_userdata = userData;
	}
	return result;
}

EVP_RESULT
EVP_sendState(struct EVP_client *h, const char *topic, const void *blob,
	      size_t bloblen, EVP_STATE_CALLBACK cb, void *userData)
{
	flatcc_builder_t builder;
	flatcc_builder_t *b = &builder;
	flatcc_builder_init(b);
	ns(Request_start_as_root(b));
	ns(Request_body_sendState_start(b));
	ns(StateInput_topic_create_str(b, topic));
	ns(StateInput_blob_create(b, blob, bloblen));
	ns(StateInput_cb_add(b, (uint64_t)(uintptr_t)cb));
	ns(StateInput_cb_userdata_add(b, (uint64_t)(uintptr_t)userData));
	ns(Request_body_sendState_end(b));
	ns(Request_end_as_root(b));
	size_t buflen;
	void *buf = flatcc_builder_finalize_aligned_buffer(b, &buflen);
	flatcc_builder_clear(b);
	return simple_call(h, buf, buflen);
}

EVP_RESULT
EVP_blobOperation(struct EVP_client *h, EVP_BLOB_TYPE type,
		  EVP_BLOB_OPERATION op, const void *request,
		  struct EVP_BlobLocalStore *localStore, EVP_BLOB_CALLBACK cb,
		  void *userData)
{
	/*
	 * quick parameter checks
	 */
	if ((type != EVP_BLOB_TYPE_AZURE_BLOB && type != EVP_BLOB_TYPE_EVP &&
	     type != EVP_BLOB_TYPE_HTTP && type != EVP_BLOB_TYPE_EVP_EXT &&
	     type != EVP_BLOB_TYPE_HTTP_EXT) ||
	    !(op == EVP_BLOB_OP_GET || op == EVP_BLOB_OP_PUT) ||
	    request == NULL || localStore == NULL ||
	    localStore->filename == NULL || cb == NULL) {
		return EVP_INVAL;
	}

	/* EVP blob get not supported. Check it here to avoid create a ST
	 * request in agent side */
	if ((op == EVP_BLOB_OP_GET) &&
	    ((type == EVP_BLOB_TYPE_EVP_EXT) || (type == EVP_BLOB_TYPE_EVP))) {
		return EVP_NOTSUP;
	}

	flatcc_builder_t builder;
	flatcc_builder_t *b = &builder;
	flatcc_builder_init(b);
	ns(Request_start_as_root(b));
	ns(Request_body_blobOperation_start(b));
	ns(BlobInput_type_add(b, type));
	ns(BlobInput_op_add(b, op));
	ns(BlobInput_filename_create_str(b, localStore->filename));
	ns(BlobInput_cb_add(b, (uint64_t)(uintptr_t)cb));
	ns(BlobInput_cb_userdata_add(b, (uint64_t)(uintptr_t)userData));

	/* type-specific stuff */
	switch (type) {
	case EVP_BLOB_TYPE_AZURE_BLOB:
		{
			const struct EVP_BlobRequestAzureBlob *azure_request =
				request;
			if (azure_request->url == NULL) {
				flatcc_builder_clear(b);
				return EVP_INVAL;
			}
			ns(BlobInput_request_azureBlob_start(b));
			ns(BlobRequestAzureBlob_url_create_str(
				b, azure_request->url));
			ns(BlobInput_request_azureBlob_end(b));
			break;
		}

	case EVP_BLOB_TYPE_EVP:
		{
			const struct EVP_BlobRequestEvp *evp_request = request;
			if (evp_request->remote_name == NULL) {
				flatcc_builder_clear(b);
				return EVP_INVAL;
			}
			ns(BlobInput_request_evp_start(b));
			ns(BlobRequestEvp_remoteName_create_str(
				b, evp_request->remote_name));
			ns(BlobInput_request_evp_end(b));
			break;
		}
	case EVP_BLOB_TYPE_HTTP:
		{
			const struct EVP_BlobRequestHttp *http_request =
				request;
			if (http_request->url == NULL) {
				flatcc_builder_clear(b);
				return EVP_INVAL;
			}
			ns(BlobInput_request_http_start(b));
			ns(BlobRequestHttp_url_create_str(b,
							  http_request->url));
			ns(BlobInput_request_http_end(b));
			break;
		}
	case EVP_BLOB_TYPE_HTTP_EXT:
		{
			const struct EVP_BlobRequestHttpExt *http_ext_request =
				request;
			if (http_ext_request->url == NULL) {
				flatcc_builder_clear(b);
				return EVP_INVAL;
			}
			ns(BlobInput_request_http_start(b));
			ns(BlobRequestHttpExt_url_create_str(
				b, http_ext_request->url));
			ns(BlobRequestHttpExt_headers_start(b));
			for (size_t i = 0; i < http_ext_request->nheaders;
			     i++) {
				ns(BlobRequestHttpExt_headers_push_start(b));
				ns(BlobRequestHttpExt_headers_push_create_str(
					b, http_ext_request->headers[i]));
				ns(BlobRequestHttpExt_headers_push_end(b));
			}
			ns(BlobRequestHttpExt_headers_end(b));
			ns(BlobInput_request_http_end(b));
			break;
		}
	case EVP_BLOB_TYPE_EVP_EXT:
		{
			const struct EVP_BlobRequestEvpExt *evp_ext_request =
				request;
			if (evp_ext_request->remote_name == NULL) {
				flatcc_builder_clear(b);
				return EVP_INVAL;
			}

			ns(BlobInput_request_evp_start(b));
			ns(BlobRequestEvp_remoteName_create_str(
				b, evp_ext_request->remote_name));
			if (evp_ext_request->storage_name != NULL) {
				ns(BlobRequestEvp_storageName_create_str(
					b, evp_ext_request->storage_name));
			}
			ns(BlobInput_request_evp_end(b));
			break;
		}
	case _EVP_BLOB_TYPE_dummy:
		// TODO: Replace assert (programming error)
		assert(false);
	}

	ns(Request_body_blobOperation_end(b));
	ns(Request_end_as_root(b));
	size_t buflen;
	void *buf = flatcc_builder_finalize_aligned_buffer(b, &buflen);
	flatcc_builder_clear(b);
	return simple_call(h, buf, buflen);
}

EVP_RESULT
EVP_sendTelemetry(struct EVP_client *h,
		  const struct EVP_telemetry_entry *entries, size_t nentries,
		  EVP_TELEMETRY_CALLBACK cb, void *userData)
{
	flatcc_builder_t builder;
	flatcc_builder_t *b = &builder;
	flatcc_builder_init(b);
	ns(Request_start_as_root(b));
	ns(Request_body_sendTelemetry_start(b));
	unsigned int i;
	ns(TelemetryInput_entries_start(b));
	for (i = 0; i < nentries; i++) {
		const struct EVP_telemetry_entry *entry = &entries[i];
		ns(TelemetryInput_entries_push_start(b));
		ns(TelemetryEntry_key_create_str(b, entry->key));
		ns(TelemetryEntry_value_create_str(b, entry->value));
		ns(TelemetryInput_entries_push_end(b));
	}
	ns(TelemetryInput_entries_end(b));
	ns(TelemetryInput_cb_add(b, (uint64_t)(uintptr_t)cb));
	ns(TelemetryInput_cb_userdata_add(b, (uint64_t)(uintptr_t)userData));
	ns(Request_body_sendTelemetry_end(b));
	ns(Request_end_as_root(b));
	size_t buflen;
	void *buf = flatcc_builder_finalize_aligned_buffer(b, &buflen);
	flatcc_builder_clear(b);
	return simple_call(h, buf, buflen);
}

EVP_RESULT
EVP_setMessageCallback(struct EVP_client *h,
		       EVP_MESSAGE_RECEIVED_CALLBACK incoming_cb,
		       void *userData)
{
	// TODO: Replace assert (programming error)
	assert(incoming_cb != NULL);
	// TODO: Replace assert (programming error)
	assert(h->cb.in_msg_cb == NULL);
	h->cb.in_msg_cb = incoming_cb;
	h->cb.in_msg_cb_userdata = userData;
	return EVP_OK;
}

EVP_RESULT
EVP_setRpcCallback(struct EVP_client *h, EVP_RPC_REQUEST_CALLBACK cb,
		   void *userData)
{
	// TODO: Replace assert (programming error)
	assert(cb != NULL);
	// TODO: Replace assert (programming error)
	assert(h->cb.rpc_cb == NULL);
	h->cb.rpc_cb = cb;
	h->cb.rpc_cb_userdata = userData;
	return EVP_OK;
}

EVP_RESULT
EVP_sendMessage(struct EVP_client *h, const char *topic, const void *blob,
		size_t bloblen, EVP_MESSAGE_SENT_CALLBACK cb, void *userData)
{
	flatcc_builder_t builder;
	flatcc_builder_t *b = &builder;
	flatcc_builder_init(b);
	ns(Request_start_as_root(b));
	ns(Request_body_sendMessage_start(b));
	ns(MessageSentInput_topic_create_str(b, topic));
	ns(MessageSentInput_blob_create(b, blob, bloblen));
	ns(MessageSentInput_cb_add(b, (uint64_t)(uintptr_t)cb));
	ns(MessageSentInput_cb_userdata_add(b, (uint64_t)(uintptr_t)userData));
	ns(Request_body_sendMessage_end(b));
	ns(Request_end_as_root(b));
	size_t buflen;
	void *buf = flatcc_builder_finalize_aligned_buffer(b, &buflen);
	flatcc_builder_clear(b);
	return simple_call(h, buf, buflen);
}

EVP_RESULT
EVP_sendRpcResponse(struct EVP_client *h, EVP_RPC_ID id, const char *response,
		    EVP_RPC_RESPONSE_STATUS status,
		    EVP_RPC_RESPONSE_CALLBACK cb, void *userData)
{
	flatcc_builder_t builder;
	flatcc_builder_t *b = &builder;
	flatcc_builder_init(b);
	ns(Request_start_as_root(b));
	ns(Request_body_sendRpcResponse_start(b));
	ns(RpcResponseInput_id_add(b, id));
	if (response != NULL) {
		ns(RpcResponseInput_response_create_str(b, response));
	}
	ns(RpcResponseInput_status_add(b, (uint32_t)status));
	ns(RpcResponseInput_cb_add(b, (uint64_t)(uintptr_t)cb));
	ns(RpcResponseInput_cb_userdata_add(b, (uint64_t)(uintptr_t)userData));
	ns(Request_body_sendRpcResponse_end(b));
	ns(Request_end_as_root(b));
	size_t buflen;
	void *buf = flatcc_builder_finalize_aligned_buffer(b, &buflen);
	flatcc_builder_clear(b);
	return simple_call(h, buf, buflen);
}

EVP_RESULT
EVP_processEvent(struct EVP_client *h, int timeout_ms)
{
	struct timespec abstimeout;
	relms2absts_realtime(timeout_ms, &abstimeout);
	struct sdk_event *event;
	bool sent_request = false;

	while ((event = TAILQ_FIRST(&h->events)) == NULL && !h->exiting) {
		if (h->get_event_req == NULL) {
			struct sdk_request *req = sdk_request_alloc();
			if (req == NULL) {
				return EVP_NOMEM;
			}

			flatcc_builder_t builder;
			flatcc_builder_t *b = &builder;
			flatcc_builder_init(b);
			ns(Request_start_as_root(b));
			ns(Request_body_getEvent_start(b));
			ns(GetEvent_timeout_sec_add(b, abstimeout.tv_sec));
			ns(GetEvent_timeout_nsec_add(b, abstimeout.tv_nsec));
			ns(Request_body_getEvent_end(b));
			ns(Request_end_as_root(b));
			size_t buflen;
			void *buf = flatcc_builder_finalize_aligned_buffer(
				b, &buflen);
			flatcc_builder_clear(b);
			if (buf == NULL) {
				sdk_request_free(req);
				return EVP_NOMEM;
			}

			req->done = get_event_done;
			req->user = h;
			req->buf = buf;
			req->buflen = buflen;
			req->buf_free = flatcc_builder_aligned_free;
			sdk_clnt_enqueue(&h->clnt, req);
			h->get_event_req = req;
			h->timed_out_on_server = false;
			sent_request = true;
		}
		int ret = sdk_clnt_sync_ts(&h->clnt, &abstimeout);
		/*
		 * If we have sent our own request (with our timeout value) and
		 * it timed out on the server, declare a timeout.
		 */
		if (ret == ETIMEDOUT ||
		    (sent_request && h->timed_out_on_server)) {
			// TODO: Replace assert (programming error)
			assert(TAILQ_EMPTY(&h->events));
			return EVP_TIMEDOUT;
		}
		if (ret != 0) {
			/*
			 * we got an unusual error.
			 * probably the connection is broken.
			 *
			 * Note: it's unrecoverable because we don't
			 * support reconnect.
			 */
			fprintf(stderr, "sdk_clnt_sync_ts returned %d\n", ret);

			/*
			 * signal the module instance to exit.
			 *
			 * XXX probably we should provide a way to
			 * distinguish from the "graceful exit" case.
			 */
			h->exiting = true;
		}
	}
	if (event != NULL) {
		TAILQ_REMOVE(&h->events, event, q);
	} else {
		// TODO: Replace assert (programming error)
		assert(h->exiting);
		return EVP_SHOULDEXIT;
	}
	EVP_RESULT result = sdk_common_execute_event(
		&sdk_callback_impl_ops_native, &h->cb, event, NULL);
	sdk_free_event(event);
	return result;
}

EVP_RESULT
EVP_streamInputOpen(struct EVP_client *h, const char *name,
		    EVP_STREAM_READ_CALLBACK cb, void *userData,
		    EVP_STREAM *stream)
{
	return EVP_impl_streamInputOpen(h, name, cb, userData, stream);
}

EVP_RESULT
EVP_streamOutputOpen(struct EVP_client *h, const char *name,
		     EVP_STREAM *stream)
{
	return EVP_impl_streamOutputOpen(h, name, stream);
}

EVP_RESULT
EVP_streamClose(struct EVP_client *h, EVP_STREAM stream)
{
	return EVP_impl_streamClose(h, stream);
}

EVP_RESULT
EVP_streamWrite(struct EVP_client *h, EVP_STREAM stream, const void *buf,
		size_t n)
{
	return EVP_impl_streamWrite(h, stream, buf, n);
}

struct stream_impl *
stream_from_stream(struct EVP_client *h, EVP_STREAM stream)
{
	return stream_impl_from_stream(&h->streams, stream);
}

struct stream_impl *
stream_from_name(struct EVP_client *h, const char *name)
{
	return stream_impl_from_name(&h->streams, name);
}

static int
prepare_stream_params_buffer(struct EVP_client *h, const char *name,
			     void **outbuf, size_t *n)
{
	int ret = -1;
	int error;
	flatcc_builder_t builder;
	flatcc_builder_t *b = &builder;
	void *buf = NULL;

	flatcc_builder_init(b);

	if (ns(Request_start_as_root(b) != 0)) {
		fprintf(stderr, "%s: Request_start_as_root failed\n",
			__func__);
		goto end;
	}

	flatbuffers_string_ref_t fb_name =
		flatbuffers_string_create_str(b, name);
	if (fb_name == 0) {
		fprintf(stderr, "%s: flatbuffers_string_create_str failed\n",
			__func__);
		goto end;
	}

	error = ns(Request_body_streamParamsRequest_create(b, fb_name));
	if (error != 0) {
		fprintf(stderr,
			"%s: Request_body_streamParamsRequest_create failed: "
			"%s\n",
			__func__, flatcc_verify_error_string(error));
		goto end;
	}

	if (ns(Request_end_as_root(b) == 0)) {
		fprintf(stderr, "%s: Request_end_as_root failed\n", __func__);
		goto end;
	}

	buf = flatcc_builder_finalize_aligned_buffer(b, n);
	if (buf == NULL) {
		fprintf(stderr,
			"%s: flatcc_builder_finalize_aligned_buffer failed\n",
			__func__);
		goto end;
	}

	*outbuf = buf;
	ret = 0;

end:
	if (ret != 0) {
		flatcc_builder_aligned_free(buf);
	}
	flatcc_builder_clear(b);
	return ret;
}

static struct sdk_request *
enqueue_stream_params_request(struct EVP_client *h, void *buf, size_t n)
{
	struct sdk_request *req = sdk_request_alloc();
	if (req == NULL) {
		return NULL;
	}

	req->done = req_done;
	req->user = h;
	req->buf = buf;
	req->buflen = n;
	req->buf_free = flatcc_builder_aligned_free;
	sdk_clnt_enqueue(&h->clnt, req);
	return req;
}

static EVP_RESULT
wait_stream_response(struct EVP_client *h, struct sdk_request *req)
{
	struct timespec abstimeout;
	const unsigned timeout_ms = 30ul * 1000ul;
	relms2absts_realtime(timeout_ms, &abstimeout);
	do {
		int ret = sdk_clnt_sync_ts(&h->clnt, &abstimeout);
		if (ret != 0) {
			/*
			 * tell req_done free the request
			 */
			req->user = NULL;
			if (ret == ETIMEDOUT) {
				return EVP_TIMEDOUT;
			}
			return EVP_ERROR;
		}
	} while (req->resp == NULL);

	return EVP_OK;
}

static EVP_RESULT
process_null_params(ns(StreamParamsResponse_table_t) body,
		    union StreamParams *p)
{
	return EVP_OK;
}

static EVP_RESULT
process_nng_params(const ns(StreamParamsResponse_table_t) body,
		   union StreamParams *p)
{
	EVP_RESULT ret;
	char *connectiondup = NULL;
	const struct ns(StreamNng_table) *params =
		ns(StreamParamsResponse_params(body));

	if (params == NULL) {
		fprintf(stderr, "%s: StreamParamsResponse_params failed\n",
			__func__);
		ret = EVP_AGENT_PROTOCOL_ERROR;
		goto end;
	}

	flatbuffers_string_t connection = ns(StreamNng_connection_get(params));
	if (connection == NULL) {
		fprintf(stderr, "%s: unexpected null connection\n", __func__);
		ret = EVP_AGENT_PROTOCOL_ERROR;
		goto end;
	}

	connectiondup = strdup(connection);
	if (connectiondup == NULL) {
		fprintf(stderr, "%s: realloc(3) failed with errno %d\n",
			__func__, errno);
		ret = EVP_NOMEM;
		goto end;
	}

	p->nng = (struct StreamNng){
		.mode = ns(StreamNng_mode_get(params)),
		.protocol = ns(StreamNng_protocol_get(params)),
		.connection = connectiondup,
	};

	ret = EVP_OK;
end:
	if (ret != EVP_OK) {
		free(connectiondup);
	}
	return ret;
}

static EVP_RESULT
process_stream_response(const struct sdk_request *req, const char *name,
			struct Stream *stream)
{
	EVP_RESULT ret;
	struct Stream s = {0};
	int error = ns(Response_verify_as_root(req->resp, req->resplen));
	if (error != 0) {
		fprintf(stderr, "%s: verify failed: %s\n", __func__,
			flatcc_verify_error_string(error));
		ret = EVP_AGENT_PROTOCOL_ERROR;
		goto end;
	}

	ns(Response_table_t) resp = ns(Response_as_root(req->resp));
	if (resp == NULL) {
		fprintf(stderr, "%s: unexpected null response\n", __func__);
		ret = EVP_AGENT_PROTOCOL_ERROR;
		goto end;
	}

	EVP_SDK_ResponseUnion_union_type_t type = ns(Response_body_type(resp));
	if (type != ns(ResponseUnion_streamParamsResponse)) {
		fprintf(stderr, "%s: unexpected response body type: %ju\n",
			__func__, (uintmax_t)type);
		ret = EVP_AGENT_PROTOCOL_ERROR;
		goto end;
	}

	ns(StreamParamsResponse_table_t) body = ns(Response_body(resp));
	if (body == NULL) {
		fprintf(stderr, "%s: unexpected null response body\n",
			__func__);
		ret = EVP_AGENT_PROTOCOL_ERROR;
		goto end;
	}

	ret = ns(StreamParamsResponse_result(body));
	if (ret != EVP_OK) {
		goto end;
	}

	s = (struct Stream){.name = strdup(name),
			    .type = ns(StreamParamsResponse_type(body)),
			    .direction =
				    ns(StreamParamsResponse_direction(body))};

	if (s.name == NULL) {
		fprintf(stderr, "%s: strdup(3) failed with errno %d\n",
			__func__, errno);
		ret = EVP_NOMEM;
		goto end;
	}

	static EVP_RESULT (*f[])(ns(StreamParamsResponse_table_t),
				 union StreamParams *p) = {
		[STREAM_TYPE_NULL] = process_null_params,
		[STREAM_TYPE_NNG] = process_nng_params,
	};

	if (s.type >= __arraycount(f)) {
		fprintf(stderr, "%s: unexpected type %d\n", __func__, s.type);
		ret = EVP_AGENT_PROTOCOL_ERROR;
		goto end;
	}

	ret = f[s.type](body, &s.params);
	if (ret != EVP_OK) {
		goto end;
	}

	*stream = s;
end:
	if (ret != EVP_OK) {
		stream_free(&s);
	}

	return ret;
}

static EVP_RESULT
get_stream_params_response(struct EVP_client *h, struct sdk_request *req,
			   const char *name, struct Stream *stream)
{
	EVP_RESULT ret = wait_stream_response(h, req);
	if (ret != EVP_OK) {
		return ret;
	}

	ret = process_stream_response(req, name, stream);
	if (ret != EVP_OK) {
		return ret;
	}

	return EVP_OK;
}

static EVP_RESULT
insert_manifest_stream(struct EVP_client *h, const struct Stream *src,
		       const struct Stream **out)
{
	struct manifest_stream *sm = malloc(sizeof(*sm));

	if (sm == NULL) {
		return EVP_NOMEM;
	}

	*sm = (struct manifest_stream){.stream = *src};
	TAILQ_INSERT_TAIL(&h->manifest_streams, sm, q);
	*out = &sm->stream;
	return EVP_OK;
}

static EVP_RESULT
request_stream_params(struct EVP_client *h, const char *name,
		      const struct Stream **out)
{
	void *buf = NULL;
	struct sdk_request *req = NULL;
	size_t n;
	EVP_RESULT ret;
	struct Stream stream = {0};

	ret = prepare_stream_params_buffer(h, name, &buf, &n);
	if (ret != EVP_OK) {
		goto end;
	}

	req = enqueue_stream_params_request(h, buf, n);
	if (req == NULL) {
		ret = EVP_NOMEM;
		goto end;
	}

	ret = get_stream_params_response(h, req, name, &stream);
	if (ret != EVP_OK) {
		goto end;
	}

	ret = insert_manifest_stream(h, &stream, out);
	if (ret != EVP_OK) {
		goto end;
	}

end:
	if (ret != EVP_OK) {
		stream_free(&stream);
	}
	/* When req != NULL, sdk_request_free already calls
	 * flatcc_builder_aligned_free. */
	if (req == NULL) {
		flatcc_builder_aligned_free(buf);
	} else {
		/* As opposed to other free(3)-like functions, sdk_request_free
		 * triggers a run-time assertion if req == NULL.*/
		sdk_request_free(req);
	}
	return ret;
}

EVP_RESULT
stream_get_params(struct EVP_client *h, const char *name,
		  const struct Stream **out)
{
	const struct manifest_stream *sm;

	TAILQ_FOREACH (sm, &h->manifest_streams, q) {
		const struct Stream *s = &sm->stream;

		if (!strcmp(s->name, name)) {
			*out = s;
			return EVP_OK;
		}
	}

	return request_stream_params(h, name, out);
}

EVP_RESULT
stream_insert(struct EVP_client *h, struct stream_impl *si)
{
	return stream_impl_insert(&h->streams, si);
}

static void
free_manifest_stream(struct EVP_client *h, const struct stream_impl *si)
{
	struct manifest_stream *sm;

	TAILQ_FOREACH (sm, &h->manifest_streams, q) {
		struct Stream *s = &sm->stream;

		if (!strcmp(s->name, si->cfg.name)) {
			TAILQ_REMOVE(&h->manifest_streams, sm, q);
			stream_free(s);
			free(sm);
			break;
		}
	}
}

EVP_RESULT
stream_remove(struct EVP_client *h, struct stream_impl *si)
{
	free_manifest_stream(h, si);
	return stream_impl_remove(&h->streams, si);
}

int
stream_insert_read_event(struct EVP_client *h,
			 struct sdk_event_stream_read_available *ev)
{
	int ret = -1;
	struct sdk_transport *tr = &h->clnt.transport;
	/* ev is dynamically allocated, so only transfer its address. */
	size_t rem = sizeof(ev);
	const void *buf = ev;
	int error = pthread_mutex_lock(&h->mutex);

	if (error) {
		fprintf(stderr, "%s: pthread_mutex_lock(3): %s\n", __func__,
			strerror(error));
		return -1;
	}

	while (rem) {
		ssize_t n = write(tr->fds[1], ev, rem);

		if (n < 0) {
			fprintf(stderr, "%s: write(2): %s\n", __func__,
				strerror(errno));
			goto end;
		}

		rem -= n;
		buf = (const char *)buf + n;
	}

	ret = 0;

end:
	error = pthread_mutex_unlock(&h->mutex);

	if (error) {
		fprintf(stderr, "%s: pthread_mutex_unlock(3): %s\n", __func__,
			strerror(error));
		ret = -1;
	}

	return ret;
}
