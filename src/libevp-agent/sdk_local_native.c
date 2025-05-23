/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "blob.h"
#include "evp/sdk.h"
#include "main_loop.h"
#include "sdk_agent.h"
#include "sdk_callback_impl_ops.h"
#include "sdk_common.h"
#include "sdk_impl.h"
#include "xlog.h"

SDK_CALLBACK_IMPL_OPS_DECLARE(native);

#if defined(__NuttX__)
struct EVP_client *
EVP_initialize(void)
{
	pid_t pid = getpid();
	struct EVP_client *h;
retry:
	sdk_lock();
	h = sdk_find_handle(pid);
	sdk_unlock();
	if (h == NULL) {
		/* XXX workaround for a theoretical race with module_instance.c
		 */
		printf("EVP_initialize: waiting for pid set\n");
		sleep(1);
		goto retry;
	}
	return h;
}
#endif

const char *
EVP_getWorkspaceDirectory(struct EVP_client *h, EVP_WORKSPACE_TYPE type)
{
	sdk_assert_unlocked();
	// TODO: Replace assert (programming error)
	assert(type == EVP_WORKSPACE_TYPE_DEFAULT);
	return h->workspace;
}

EVP_RESULT
EVP_setConfigurationCallback(struct EVP_client *h,
			     EVP_CONFIGURATION_CALLBACK cb, void *userData)
{
	sdk_assert_unlocked();
	if (h->cb.config_cb != NULL) {
		return EVP_ERROR;
	}
	sdk_lock();
	h->cb.config_cb = cb;
	h->cb.config_cb_userdata = userData;
	g_resend_request = true;
	sdk_unlock();
	main_loop_wakeup("RESEND-REQUEST");
	return EVP_OK;
}

EVP_RESULT
EVP_sendState(struct EVP_client *h, const char *topic, const void *blob,
	      size_t bloblen, EVP_STATE_CALLBACK cb, void *userData)
{
	return EVP_impl_sendState(h, NULL, topic, blob, bloblen, cb, userData);
}

EVP_RESULT
EVP_setMessageCallback(struct EVP_client *h,
		       EVP_MESSAGE_RECEIVED_CALLBACK incoming_cb,
		       void *userData)
{
	// TODO: Replace assert (programming error)
	assert(incoming_cb != NULL);

	sdk_lock();
	// TODO: Replace assert (programming error)
	assert(h->cb.in_msg_cb == NULL);
	h->cb.in_msg_cb = incoming_cb;
	h->cb.in_msg_cb_userdata = userData;
	sdk_unlock();

	return EVP_OK;
}

EVP_RESULT
EVP_setRpcCallback(struct EVP_client *h, EVP_RPC_REQUEST_CALLBACK cb,
		   void *userData)
{
	// TODO: Replace assert (programming error)
	assert(cb != NULL);

	sdk_lock();
	// TODO: Replace assert (programming error)
	assert(h->cb.rpc_cb == NULL);
	h->cb.rpc_cb = cb;
	h->cb.rpc_cb_userdata = userData;
	sdk_unlock();
	return EVP_OK;
}

EVP_RESULT
EVP_blobOperation(struct EVP_client *h, EVP_BLOB_TYPE type,
		  EVP_BLOB_OPERATION op, const void *request,
		  struct EVP_BlobLocalStore *localStore, EVP_BLOB_CALLBACK cb,
		  void *userData)
{
	// TODO: Replace assert (programming error)
	assert(localStore != NULL);
	return EVP_impl_blobOperation(h, NULL, type, op, request, localStore,
				      cb, userData);
}

EVP_RESULT
EVP_sendMessage(struct EVP_client *h, const char *topic, const void *blob,
		size_t bloblen, EVP_MESSAGE_SENT_CALLBACK cb, void *userData)
{
	return EVP_impl_sendMessage(h, NULL, topic, blob, bloblen, cb,
				    userData);
}

EVP_RESULT
EVP_sendTelemetry(struct EVP_client *h,
		  const struct EVP_telemetry_entry *entries, size_t nentries,
		  EVP_TELEMETRY_CALLBACK cb, void *userData)
{
	return EVP_impl_sendTelemetry(h, NULL, NULL, entries, nentries, cb,
				      userData);
}

EVP_RESULT
EVP_sendRpcResponse(struct EVP_client *h, EVP_RPC_ID id, const char *response,
		    EVP_RPC_RESPONSE_STATUS status,
		    EVP_RPC_RESPONSE_CALLBACK cb, void *userData)
{
	return EVP_impl_sendRpcResponse(h, NULL, id, response, status, cb,
					userData);
}

EVP_RESULT
EVP_processEvent(struct EVP_client *h, int timeout_ms)
{
	struct sdk_event *event;
	EVP_RESULT result;
	result = EVP_impl_getEvent(h, timeout_ms, &event);
	// TODO: Replace assert (runtime error)
	assert((result == EVP_OK) == (event != NULL));
	if (result == EVP_OK) {
		result = sdk_common_execute_event(
			&sdk_callback_impl_ops_native, &h->cb, event, NULL);
		sdk_free_event(event);
	}
	return result;
}

EVP_RESULT
EVP_streamOutputOpen(struct EVP_client *h, const char *name,
		     EVP_STREAM *stream)
{
	return EVP_impl_streamOutputOpen_local(h, name, stream);
}

EVP_RESULT
EVP_streamInputOpen(struct EVP_client *h, const char *name,
		    EVP_STREAM_READ_CALLBACK cb, void *userData,
		    EVP_STREAM *stream)
{
	return EVP_impl_streamInputOpen_local(h, name, cb, userData, stream);
}

EVP_RESULT
EVP_streamClose(struct EVP_client *h, EVP_STREAM stream)
{
	return EVP_impl_streamClose_local(h, stream);
}

EVP_RESULT
EVP_streamWrite(struct EVP_client *h, EVP_STREAM stream, const void *buf,
		size_t n)
{
	return EVP_impl_streamWrite_local(h, stream, buf, n);
}
