/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <errno.h>
#include <sdkenc/sdk_builder.h>
#include <sdkenc/sdk_reader.h>
#include <sdkenc/sdk_verifier.h>
#include <stdio.h>

#include <internal/request.h>
#include <internal/util.h>

#include "blob.h"
#include "event.h"
#include "main_loop.h"
#include "module_instance.h"
#include "sdk_impl.h"
#include "xlog.h"
#include "xpthread.h"

#undef ns
#define ns(a) FLATBUFFERS_WRAP_NAMESPACE(EVP_SDK, a)

static int
process_get_event(struct EVP_client *h, ns(Request_table_t) req,
		  const void *rawbuf, struct sdk_response **respp)
{
	int ret = 0;
	ns(GetEvent_table_t) getevent = ns(Request_body(req));
	struct timespec abstimeout;

	/*
	 * XXX this timestamp comes from the sdk socket peer,
	 * which is usually a docker container.
	 * it's assumed that time is reasonably synced between
	 * the container and us.
	 */
	abstimeout.tv_sec = ns(GetEvent_timeout_sec(getevent));
	abstimeout.tv_nsec = ns(GetEvent_timeout_nsec(getevent));
	struct sdk_event *event;
	bool exiting;

	sdk_lock();
	while (TAILQ_EMPTY(&h->events) && !h->exiting) {
		sdk_mark_unlocked();
		/*
		 * XXX only reason to implement timeout here is to workaround
		 * issues from the single-threaded server implmenetation.
		 */
		int ret = xpthread_cond_timedwait(&h->event_cv, &g_sdk_lock,
						  &abstimeout);
		sdk_mark_locked();
		if (ret == ETIMEDOUT) {
			break;
		}
	}
	event = TAILQ_FIRST(&h->events);
	if (event != NULL) {
		TAILQ_REMOVE(&h->events, event, q);
	}
	exiting = h->exiting;
	sdk_unlock();

	flatcc_builder_t builder;
	flatcc_builder_t *b = &builder;
	flatcc_builder_init(b);
	ns(Response_start_as_root(b));
	ns(Response_body_getEvent_start(b));
	if (event == NULL) {
		if (exiting) {
			xlog_debug("process_get_event: got exit event");
			ns(Event_body_exit_start(b));
			ns(Event_body_exit_end(b));
		} else {
#if defined(SDK_LOG_VERBOSE)
			xlog_debug("process_get_event: got no event");
#endif
		}
	} else {
		switch (event->type) {
		case SDK_EVENT_CONFIG:
			{
#if defined(SDK_LOG_VERBOSE)
				xlog_debug("process_get_event: got an event "
					   "type %u",
					   event->type);
#endif
				struct sdk_event_config *config =
					(void *)event;
				ns(Event_body_config_start(b));
				ns(Config_topic_create_str(b, config->topic));
				ns(Config_blob_create(b, config->blob,
						      config->bloblen));
				ns(Event_body_config_end(b));
				sdk_free_event(event);
				break;
			}
		case SDK_EVENT_STATE:
			{
#if defined(SDK_LOG_VERBOSE)
				xlog_debug("process_get_event: got an event "
					   "type %u",
					   event->type);
#endif
				struct sdk_event_state *state = (void *)event;
				ns(Event_body_state_start(b));
				ns(StateOutput_reason_add(b, state->reason));
				ns(StateOutput_cb_add(
					b, (uint64_t)(uintptr_t)state->cb));
				ns(StateOutput_cb_userdata_add(
					b, (uint64_t)(uintptr_t)
						   state->cb_userdata));
				ns(Event_body_state_end(b));
				sdk_free_event(event);
				break;
			}
		case SDK_EVENT_BLOB:
			{
#if defined(SDK_LOG_VERBOSE)
				xlog_debug("process_get_event: got an event "
					   "type %u",
					   event->type);
#endif
				struct sdk_event_blob *blob = (void *)event;
				// TODO: Replace assert (programming error)
				assert(blob->owner == NULL);
				ns(Event_body_blob_start(b));
				ns(BlobOutput_reason_add(b, blob->reason));
				ns(BlobOutput_cb_add(
					b, (uint64_t)(uintptr_t)
						   blob->user_cb.cb));
				ns(BlobOutput_cb_userdata_add(
					b, (uint64_t)(uintptr_t)
						   blob->user_cb.cb_data));
				if (blob->reason ==
				    EVP_BLOB_CALLBACK_REASON_DONE) {
					struct blob_work *wk = blob->work;
					// TODO: Replace assert (programming
					// error)
					assert(wk != NULL);
					// TODO: Replace assert (programming
					// error)
					assert(wk->user == blob);
					/*
					 * assert here instead of adding
					 * default clause in the following
					 * switch statement to benefit from
					 * -Wswitch.
					 */
					assert(wk->type ==
						       BLOB_TYPE_AZURE_BLOB ||
					       wk->type == BLOB_TYPE_HTTP ||
					       wk->type == BLOB_TYPE_EVP_EXT ||
					       wk->type == BLOB_TYPE_HTTP_EXT);
					switch (wk->type) {
					case BLOB_TYPE_AZURE_BLOB:
						ns(BlobOutput_result_azureBlob_start(
							b));
						ns(BlobResultAzureBlob_result_add(
							b, wk->result));
						ns(BlobResultAzureBlob_error_add(
							b, wk->error));
						ns(BlobResultAzureBlob_http_status_add(
							b, wk->http_status));
						ns(BlobOutput_result_azureBlob_end(
							b));
						break;
					case deprecated_BLOB_TYPE_EVP:
						// TODO: Replace assert
						// (programming error)
						assert(false);
						break;
					case BLOB_TYPE_EVP_EXT:
						ns(BlobOutput_result_evp_start(
							b));
						ns(BlobResultEvp_result_add(
							b, wk->result));
						ns(BlobResultEvp_error_add(
							b, wk->error));
						ns(BlobResultEvp_http_status_add(
							b, wk->http_status));
						ns(BlobOutput_result_evp_end(
							b));
						break;
					case BLOB_TYPE_HTTP:
					case BLOB_TYPE_HTTP_EXT:
						ns(BlobOutput_result_http_start(
							b));
						ns(BlobResultHttp_result_add(
							b, wk->result));
						ns(BlobResultHttp_error_add(
							b, wk->error));
						ns(BlobResultHttp_http_status_add(
							b, wk->http_status));
						ns(BlobOutput_result_http_end(
							b));
						break;
					}
				}
				ns(Event_body_blob_end(b));
				sdk_free_event(event);
				break;
			}
		case SDK_EVENT_TELEMETRY:
			{
#if defined(SDK_LOG_VERBOSE)
				xlog_debug("process_get_event: got an event "
					   "type %u",
					   event->type);
#endif
				struct sdk_event_telemetry *t = (void *)event;
				ns(Event_body_telemetry_start(b));
				ns(TelemetryOutput_reason_add(b, t->reason));
				ns(TelemetryOutput_cb_add(
					b, (uint64_t)(uintptr_t)t->cb));
				ns(TelemetryOutput_cb_userdata_add(
					b,
					(uint64_t)(uintptr_t)t->cb_userdata));
				ns(Event_body_telemetry_end(b));
				sdk_free_event(event);
				break;
			}
		case SDK_EVENT_MESSAGE_RECEIVED:
			{
#if defined(SDK_LOG_VERBOSE)
				xlog_debug("process_get_event: got an event "
					   "type %u",
					   event->type);
#endif
				struct sdk_event_message_received *m =
					(void *)event;
				ns(Event_body_messageReceived_start(b));
				ns(MessageReceived_topic_create_str(b,
								    m->topic));
				ns(MessageReceived_blob_create(b, m->blob,
							       m->bloblen));
				ns(Event_body_messageReceived_end(b));
				sdk_free_event(event);
				break;
			}
		case SDK_EVENT_MESSAGE_SENT:
			{
#if defined(SDK_LOG_VERBOSE)
				xlog_debug("process_get_event: got an event "
					   "type %u",
					   event->type);
#endif
				struct sdk_event_message_sent *m =
					(void *)event;
				ns(Event_body_messageSent_start(b));
				ns(MessageSentOutput_reason_add(b, m->reason));
				ns(MessageSentOutput_cb_add(
					b, (uint64_t)(uintptr_t)m->cb));
				ns(MessageSentOutput_cb_userdata_add(
					b,
					(uint64_t)(uintptr_t)m->cb_userdata));
				ns(Event_body_messageSent_end(b));
				sdk_free_event(event);
				break;
			}
		case SDK_EVENT_RPC_REQUEST:
			{
#if defined(SDK_LOG_VERBOSE)
				xlog_debug("process_get_event: got an event "
					   "type %u",
					   event->type);
#endif
				struct sdk_event_rpc_request *r =
					(void *)event;
				ns(Event_body_rpcRequest_start(b));
				ns(RpcRequest_id_add(b, r->id));
				ns(RpcRequest_method_create_str(b, r->method));
				ns(RpcRequest_params_create_str(b, r->params));
				ns(Event_body_rpcRequest_end(b));
				sdk_free_event(event);
				break;
			}
		case SDK_EVENT_RPC_RESPONSE:
			{
#if defined(SDK_LOG_VERBOSE)
				xlog_debug("process_get_event: got an event "
					   "type %u",
					   event->type);
#endif
				struct sdk_event_rpc_response *r =
					(void *)event;
				ns(Event_body_rpcResponse_start(b));
				ns(RpcResponseOutput_reason_add(b, r->reason));
				ns(RpcResponseOutput_cb_add(
					b, (uint64_t)(uintptr_t)r->cb));
				ns(RpcResponseOutput_cb_userdata_add(
					b,
					(uint64_t)(uintptr_t)r->cb_userdata));
				ns(Event_body_rpcResponse_end(b));
				sdk_free_event(event);
				break;
			}
		case SDK_EVENT_STREAM_READ_AVAILABLE:
			xlog_error("SDK_EVENT_STREAM_READ_AVAILABLE is never "
				   "available for "
				   "remote SDK implementations");
			ret = -1;
			break;
		case SDK_EVENT_BLOB_GET_UPLOAD_URL:
			xlog_error("SDK_EVENT_BLOB_GET_UPLOAD_URL is never "
				   "used by "
				   "remote SDK implementations");
			ret = -1;
			break;
		case SDK_EVENT_BLOB_IO_READ:
			xlog_error("SDK_EVENT_BLOB_IO_READ is never "
				   "used by "
				   "remote SDK implementations");
			ret = -1;
			break;
		case SDK_EVENT_BLOB_IO_WRITE:
			xlog_error("SDK_EVENT_BLOB_IO_READ is never "
				   "used by "
				   "remote SDK implementations");
			ret = -1;
			break;
		}
	}
	ns(Response_body_getEvent_end(b));
	ns(Response_end_as_root(b));
	size_t buflen;
	void *buf = flatcc_builder_finalize_aligned_buffer(b, &buflen);
	flatcc_builder_clear(b);

	struct sdk_response *resp = sdk_response_alloc();
	*resp = (struct sdk_response){
		.buf = buf,
		.buflen = buflen,
		.buf_free = flatcc_builder_aligned_free,
	};
	*respp = resp;
	free(__UNCONST(rawbuf));
	return ret;
}

void *
sdk_build_simple_response(size_t *sizep, EVP_RESULT result)
{
	flatcc_builder_t builder;
	flatcc_builder_t *b = &builder;
	flatcc_builder_init(b);
	ns(Response_start_as_root(b));
	ns(Response_body_simple_start(b));
	ns(Simple_result_add(b, result));
	ns(Response_body_simple_end(b));
	ns(Response_end_as_root(b));
	size_t buflen;
	void *buf = flatcc_builder_finalize_aligned_buffer(b, &buflen);
	flatcc_builder_clear(b);
	*sizep = buflen;
	return buf;
}

static int
process_request_resend_config(struct EVP_client *h, ns(Request_table_t) req,
			      const void *rawbuf, struct sdk_response **respp)
{
	xlog_debug("setting g_resend_request in behalf of %s", h->name);
	sdk_lock();
	g_resend_request = true;
	sdk_unlock();
	main_loop_wakeup("RESEND-REQUEST");

	struct sdk_response *resp = sdk_response_alloc();
	size_t simple_response_len;
	void *simple_response =
		sdk_build_simple_response(&simple_response_len, EVP_OK);
	*resp = (struct sdk_response){
		.buf = simple_response,
		.buflen = simple_response_len,
		.buf_free = flatcc_builder_aligned_free,
	};
	*respp = resp;
	free(__UNCONST(rawbuf));
	return 0;
}

static int
process_send_state(struct EVP_client *h, ns(Request_table_t) req,
		   const void *rawbuf, struct sdk_response **respp)
{
#if defined(SDK_LOG_VERBOSE)
	xlog_debug("calling EVP_sendState in behalf of %s", h->name);
#endif
	ns(StateInput_table_t) state = ns(Request_body(req));
	// TODO: Replace assert (runtime error)
	assert(state != NULL);
	const char *topic = ns(StateInput_topic(state));
	flatbuffers_uint8_vec_t blob_vec = ns(StateInput_blob(state));
	size_t bloblen = flatbuffers_uint8_vec_len(blob_vec);
	void *cb = (void *)(uintptr_t)ns(StateInput_cb(state));
	void *cb_userdata =
		(void *)(uintptr_t)ns(StateInput_cb_userdata(state));
	EVP_RESULT ret = EVP_impl_sendState(h, rawbuf, topic, blob_vec,
					    bloblen, cb, cb_userdata);
	struct sdk_response *resp = sdk_response_alloc();
	size_t simple_response_len;
	void *simple_response =
		sdk_build_simple_response(&simple_response_len, ret);
	*resp = (struct sdk_response){
		.buf = simple_response,
		.buflen = simple_response_len,
		.buf_free = flatcc_builder_aligned_free,
	};
	*respp = resp;
	return 0;
}

static int
process_blob_operation(struct EVP_client *h, ns(Request_table_t) req,
		       const void *rawbuf, struct sdk_response **respp)
{
	ns(BlobInput_table_t) blob = ns(Request_body(req));
	// TODO: Replace assert (runtime error)
	assert(blob != NULL);
	EVP_BLOB_TYPE type = ns(BlobInput_type(blob));
	EVP_BLOB_OPERATION op = ns(BlobInput_op(blob));
	const char *filename = ns(BlobInput_filename(blob));
	void *cb = (void *)(uintptr_t)ns(BlobInput_cb(blob));
	void *cb_userdata = (void *)(uintptr_t)ns(BlobInput_cb_userdata(blob));

	if (!(type == EVP_BLOB_TYPE_AZURE_BLOB || type == EVP_BLOB_TYPE_EVP ||
	      type == EVP_BLOB_TYPE_HTTP || type == EVP_BLOB_TYPE_EVP_EXT ||
	      type == EVP_BLOB_TYPE_HTTP_EXT) ||
	    !(op == EVP_BLOB_OP_GET || op == EVP_BLOB_OP_PUT)) {
		return EINVAL;
	}
	if ((ns(BlobInput_request_type(blob)) !=
	     ns(BlobRequestUnion_azureBlob)) &&
	    (ns(BlobInput_request_type(blob)) != ns(BlobRequestUnion_evp)) &&
	    (ns(BlobInput_request_type(blob)) != ns(BlobRequestUnion_http))) {
		return EINVAL;
	}

	/* type-specific stuff */
	struct EVP_BlobRequestAzureBlob azure_request;
	struct EVP_BlobRequestEvp evp_request;
	struct EVP_BlobRequestHttp http_request;
	struct EVP_BlobRequestHttpExt http_ext_request;
	struct EVP_BlobRequestEvpExt evp_ext_request;
	http_ext_request.headers = NULL;
	http_ext_request.url = NULL;
	http_ext_request.nheaders = 0;
	const void *request;
	switch (ns(BlobInput_request_type(blob))) {
	case ns(BlobRequestUnion_azureBlob):
		{
			ns(BlobRequestAzureBlob_table_t) azure =
				ns(BlobInput_request(blob));
			azure_request.url =
				ns(BlobRequestAzureBlob_url(azure));
			request = &azure_request;
			break;
		}
	case ns(BlobRequestUnion_evp):
		{
			ns(BlobRequestEvp_table_t) evp =
				ns(BlobInput_request(blob));
			if (type == EVP_BLOB_TYPE_EVP_EXT) {
				evp_ext_request.remote_name =
					ns(BlobRequestEvp_remoteName(evp));
				evp_ext_request.storage_name =
					ns(BlobRequestEvp_storageName(evp));
				request = &evp_ext_request;
			} else {
				evp_request.remote_name =
					ns(BlobRequestEvp_remoteName(evp));
				request = &evp_request;
			}
			break;
		}
	case ns(BlobRequestUnion_http):
		{
			ns(BlobRequestHttp_table_t) http =
				ns(BlobInput_request(blob));
			http_request.url = ns(BlobRequestHttp_url(http));
			request = &http_request;
			break;
		}
	case ns(BlobRequestUnion_http_ext):
		{
			ns(BlobRequestHttpExt_table_t) http_ext =
				ns(BlobInput_request(blob));
			http_ext_request.url =
				strdup(ns(BlobRequestHttpExt_url(http_ext)));
			if (!http_ext_request.url) {
				return errno;
			}

			flatbuffers_string_vec_t headers_vec =
				ns(BlobRequestHttpExt_headers(http_ext));
			http_ext_request.nheaders =
				flatbuffers_string_vec_len(headers_vec);
			flatbuffers_string_t *headers_aux =
				calloc(http_ext_request.nheaders,
				       sizeof(*headers_aux));
			if (!headers_aux) {
				free((void *)http_ext_request.url);
				return errno;
			}

			for (size_t i = 0; i < http_ext_request.nheaders;
			     i++) {
				headers_aux[i] = flatbuffers_string_vec_at(
					headers_vec, i);
			}

			http_ext_request.headers = headers_aux;
			request = &http_ext_request;
			break;
		}
	default:
		return EINVAL;
	}

	struct EVP_BlobLocalStore localStore;
	localStore.filename = filename;

	// memory (non null) blob operations are not supported by
	// remote SDK
	localStore.io_cb = NULL;
	localStore.blob_len = 0;

#if defined(SDK_LOG_VERBOSE)
	xlog_debug("calling EVP_impl_blobOperation in behalf of %s", h->name);
#endif
	EVP_RESULT ret = EVP_impl_blobOperation(h, rawbuf, type, op, request,
						&localStore, cb, cb_userdata);
	struct sdk_response *resp = sdk_response_alloc();
	size_t simple_response_len;
	void *simple_response =
		sdk_build_simple_response(&simple_response_len, ret);
	*resp = (struct sdk_response){
		.buf = simple_response,
		.buflen = simple_response_len,
		.buf_free = flatcc_builder_aligned_free,
	};
	*respp = resp;

	free((void *)http_ext_request.headers);
	free((void *)http_ext_request.url);
	return 0;
}

static int
process_send_telemetry(struct EVP_client *h, ns(Request_table_t) req,
		       const void *rawbuf, struct sdk_response **respp)
{
	ns(TelemetryInput_table_t) t = ns(Request_body(req));
	// TODO: Replace assert (runtime error)
	assert(t != NULL);
	ns(TelemetryEntry_vec_t) vec = ns(TelemetryInput_entries(t));
	size_t nentries = ns(TelemetryEntry_vec_len(vec));

	/* +1 to avoid zero-sized malloc */

	struct EVP_telemetry_entry *entries =
		malloc(nentries * sizeof(*entries) + 1);
	if (entries == NULL) {
		return ENOMEM;
	}
	unsigned int i;
	for (i = 0; i < nentries; i++) {
		struct EVP_telemetry_entry *entry = &entries[i];
		ns(TelemetryEntry_table_t) e =
			ns(TelemetryEntry_vec_at(vec, i));
		entry->key = ns(TelemetryEntry_key(e));
		entry->value = ns(TelemetryEntry_value(e));
	}
	void *cb = (void *)(uintptr_t)ns(TelemetryInput_cb(t));
	void *cb_userdata =
		(void *)(uintptr_t)ns(TelemetryInput_cb_userdata(t));
#if defined(SDK_LOG_VERBOSE)
	xlog_debug("calling EVP_impl_sendTelemetry in behalf of %s", h->name);
#endif
	EVP_RESULT ret = EVP_impl_sendTelemetry(h, rawbuf, entries, entries,
						nentries, cb, cb_userdata);
	if (EVP_OK != ret) {
		/* If no error, entries are managed by
		 * EVP_impl_sendTelemetry
		 */
		free(entries);
	}

	struct sdk_response *resp = sdk_response_alloc();
	size_t simple_response_len;
	void *simple_response =
		sdk_build_simple_response(&simple_response_len, ret);
	*resp = (struct sdk_response){
		.buf = simple_response,
		.buflen = simple_response_len,
		.buf_free = flatcc_builder_aligned_free,
	};
	*respp = resp;
	return 0;
}

static int
process_send_message(struct EVP_client *h, ns(Request_table_t) req,
		     const void *rawbuf, struct sdk_response **respp)
{
	ns(MessageSentInput_table_t) m = ns(Request_body(req));
	// TODO: Replace assert (runtime error)
	assert(m != NULL);
	const char *topic = ns(MessageSentInput_topic(m));
	flatbuffers_uint8_vec_t blob_vec = ns(MessageSentInput_blob(m));
	size_t bloblen = flatbuffers_uint8_vec_len(blob_vec);
	void *cb = (void *)(uintptr_t)ns(MessageSentInput_cb(m));
	void *cb_userdata =
		(void *)(uintptr_t)ns(MessageSentInput_cb_userdata(m));
#if defined(SDK_LOG_VERBOSE)
	xlog_debug("calling EVP_impl_sendMessage in behalf of %s", h->name);
#endif
	EVP_RESULT ret = EVP_impl_sendMessage(h, rawbuf, topic, blob_vec,
					      bloblen, cb, cb_userdata);
	struct sdk_response *resp = sdk_response_alloc();
	size_t simple_response_len;
	void *simple_response =
		sdk_build_simple_response(&simple_response_len, ret);
	*resp = (struct sdk_response){
		.buf = simple_response,
		.buflen = simple_response_len,
		.buf_free = flatcc_builder_aligned_free,
	};

	*respp = resp;
	return 0;
}

static int
process_send_rpc_response(struct EVP_client *h, ns(Request_table_t) req,
			  const void *rawbuf, struct sdk_response **respp)
{
	ns(RpcResponseInput_table_t) m = ns(Request_body(req));
	// TODO: Replace assert (runtime error)
	assert(m != NULL);
	EVP_RPC_ID id = ns(RpcResponseInput_id(m));
	const char *response = ns(RpcResponseInput_response(m));
	EVP_RPC_RESPONSE_STATUS status = ns(RpcResponseInput_status(m));
	void *cb = (void *)(uintptr_t)ns(RpcResponseInput_cb(m));
	void *cb_userdata =
		(void *)(uintptr_t)ns(RpcResponseInput_cb_userdata(m));
#if defined(SDK_LOG_VERBOSE)
	xlog_debug("calling EVP_impl_sendRpcResponse in behalf of %s",
		   h->name);
#endif
	EVP_RESULT ret = EVP_impl_sendRpcResponse(h, rawbuf, id, response,
						  status, cb, cb_userdata);
	struct sdk_response *resp = sdk_response_alloc();
	size_t simple_response_len;
	void *simple_response =
		sdk_build_simple_response(&simple_response_len, ret);
	*resp = (struct sdk_response){
		.buf = simple_response,
		.buflen = simple_response_len,
		.buf_free = flatcc_builder_aligned_free,
	};
	*respp = resp;
	return 0;
}

static int
send_invalid_stream_response(struct sdk_response **respp)
{
	int ret = -1;
	int error;
	flatcc_builder_t builder;
	flatcc_builder_t *b = &builder;
	void *buf = NULL;
	struct sdk_response *resp = NULL;

	flatcc_builder_init(b);

	error = ns(Response_start_as_root(b));
	if (error != 0) {
		xlog_error("Response_start_as_root failed: %s",
			   flatcc_verify_error_string(error));
		goto end;
	}

	error = ns(Response_body_streamParamsResponse_start(b));
	if (error != 0) {
		xlog_error("Response_body_streamParamsResponse_start "
			   "failed: %s",
			   flatcc_verify_error_string(error));
		goto end;
	}

	error = ns(StreamParamsResponse_result_add(b, EVP_INVAL));
	if (error != 0) {
		xlog_error("StreamParamsResponse_result_add failed: %s",
			   flatcc_verify_error_string(error));
		goto end;
	}

	error = ns(Response_body_streamParamsResponse_end(b));
	if (error != 0) {
		xlog_error("Response_body_streamParamsResponse_end "
			   "failed: %s",
			   flatcc_verify_error_string(error));
		goto end;
	}

	if (ns(Response_end_as_root(b)) == 0) {
		xlog_error("Response_end_as_root failed");
		goto end;
	}

	size_t n;
	buf = flatcc_builder_finalize_aligned_buffer(b, &n);
	if (buf == NULL) {
		xlog_error("flatcc_builder_finalize_aligned_buffer "
			   "failed");
		goto end;
	}

	resp = sdk_response_alloc();
	if (resp == NULL) {
		xlog_error("sdk_response_alloc failed");
		goto end;
	}

	*resp = (struct sdk_response){
		.buf = buf,
		.buflen = n,
		.buf_free = flatcc_builder_aligned_free,
	};
	*respp = resp;
	ret = 0;

end:
	if (ret != 0) {
		flatcc_builder_aligned_free(buf);
		sdk_response_free(resp);
	}
	flatcc_builder_clear(b);
	return ret;
}

static int
add_null_stream_params(const struct Stream *stream, flatcc_builder_t *b)
{
	return 0;
}

static int
add_stream_params(const struct Stream *stream, flatcc_builder_t *b)
{
	int error = ns(StreamParamsResponse_type_add(b, stream->type));
	if (error != 0) {
		xlog_error("StreamParamsResponse_type_add failed: %s",
			   flatcc_verify_error_string(error));
		return -1;
	}

	error = ns(StreamParamsResponse_direction_add(b, stream->direction));
	if (error != 0) {
		xlog_error("StreamParamsResponse_direction_add "
			   "failed: %s",
			   flatcc_verify_error_string(error));
		return -1;
	}

	static int (*const f[])(const struct Stream *, flatcc_builder_t *) = {
		[STREAM_TYPE_NULL] = add_null_stream_params,
	};

	return f[stream->type](stream, b);
}

static int
send_stream_params(const struct Stream *stream, struct sdk_response **respp)
{
	int ret = -1;
	int error;
	flatcc_builder_t builder;
	flatcc_builder_t *b = &builder;
	void *buf = NULL;
	struct sdk_response *resp = NULL;

	flatcc_builder_init(b);

	error = ns(Response_start_as_root(b));
	if (error != 0) {
		xlog_error("Response_start_as_root failed: %s",
			   flatcc_verify_error_string(error));
		goto end;
	}

	error = ns(Response_body_streamParamsResponse_start(b));
	if (error != 0) {
		xlog_error("Response_body_streamParamsResponse_start "
			   "failed: %s",
			   flatcc_verify_error_string(error));
		goto end;
	}

	error = ns(StreamParamsResponse_result_add(b, EVP_OK));
	if (error != 0) {
		xlog_error("StreamParamsResponse_result_add failed: %s",
			   flatcc_verify_error_string(error));
		goto end;
	}

	if (add_stream_params(stream, b)) {
		xlog_error("add_stream_params failed");
		goto end;
	}

	error = ns(Response_body_streamParamsResponse_end(b));
	if (error != 0) {
		xlog_error("Response_body_streamParamsResponse_end "
			   "failed: %s",
			   flatcc_verify_error_string(error));
		goto end;
	}

	if (ns(Response_end_as_root(b)) == 0) {
		xlog_error("Response_end_as_root failed");
		goto end;
	}

	size_t n;
	buf = flatcc_builder_finalize_aligned_buffer(b, &n);
	if (buf == NULL) {
		xlog_error("flatcc_builder_finalize_aligned_buffer "
			   "failed");
		goto end;
	}

	resp = sdk_response_alloc();
	if (resp == NULL) {
		xlog_error("sdk_response_alloc failed");
		goto end;
	}

	*resp = (struct sdk_response){
		.buf = buf,
		.buflen = n,
		.buf_free = flatcc_builder_aligned_free,
	};
	*respp = resp;
	ret = 0;

end:
	if (ret != 0) {
		flatcc_builder_aligned_free(buf);
		sdk_response_free(resp);
	}
	flatcc_builder_clear(b);
	return ret;
}

static int
process_stream_params_request(struct EVP_client *h, ns(Request_table_t) req,
			      const void *rawbuf, struct sdk_response **respp)
{
	const struct module_instance *m = get_module_instance_by_name(h->name);
	if (m == NULL) {
		xlog_error("get_module_instance_by_name failed");
		return -1;
	}

	ns(StreamParamsRequest_table_t) t = ns(Request_body(req));
	if (t == NULL) {
		xlog_error("Request_body failed");
		return -1;
	}

	const char *name = ns(StreamParamsRequest_name(t));
	if (name == NULL || *name == '\0') {
		xlog_error("invalid stream name");
		return -1;
	}

	const struct Stream *stream =
		module_instance_stream_from_name(m, name);
	if (stream == NULL) {
		int ret = send_invalid_stream_response(respp);
		if (ret != 0) {
			xlog_error("send_invalid_stream_response failed");
		}
		return ret;
	}

	return send_stream_params(stream, respp);
}

int
sdk_process_request(const void *buf, size_t sz, struct sdk_response **respp,
		    void *ctx)
{
	int ret = ns(Request_verify_as_root(buf, sz));
	if (ret != 0) {
		xlog_warning("verify failed: %s",
			     flatcc_verify_error_string(ret));
		free(__UNCONST(buf));
		return EINVAL;
	}
	ns(Request_table_t) req = ns(Request_as_root(buf));
	struct EVP_client *h = ctx;
	// TODO: Replace assert (runtime error)
	assert(h != NULL);
	// TODO: Replace assert (runtime error)
	assert(req != NULL);
	ns(RequestUnion_union_type_t) method = ns(Request_body_type(req));
#if defined(SDK_LOG_VERBOSE)
	xlog_debug("sdk_process_request: name %s  method %ju", h->name,
		   (uintmax_t)method);
#endif

	int (*fn)(struct EVP_client *, ns(Request_table_t), const void *,
		  struct sdk_response **) = NULL;
	switch (method) {
	case ns(RequestUnion_getEvent):
		fn = process_get_event;
		break;
	case ns(RequestUnion_requestResendConfig):
		fn = process_request_resend_config;
		break;
	case ns(RequestUnion_sendState):
		fn = process_send_state;
		break;
	case ns(RequestUnion_blobOperation):
		fn = process_blob_operation;
		break;
	case ns(RequestUnion_sendTelemetry):
		fn = process_send_telemetry;
		break;
	case ns(RequestUnion_sendMessage):
		fn = process_send_message;
		break;
	case ns(RequestUnion_sendRpcResponse):
		fn = process_send_rpc_response;
		break;
	case ns(RequestUnion_streamParamsRequest):
		fn = process_stream_params_request;
		break;
	}
	// TODO: Replace assert (runtime error)
	assert(fn != NULL);
	struct sdk_response *resp;
	int error = fn(h, req, buf, &resp);
	if (error != 0) {
		free(__UNCONST(buf));
		return error;
	}
	// TODO: Replace assert (programming error)
	assert(resp->buf != NULL);
	// TODO: Replace assert (programming error)
	assert(resp->buflen > 0);
	*respp = resp;
	return 0;
}
