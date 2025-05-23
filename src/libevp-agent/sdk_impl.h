/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if !defined(__SDK_IMPL_H__)
#define __SDK_IMPL_H__

#include <config.h>

#include <pthread.h>
#include <stdbool.h>
#if defined(CONFIG_EVP_MODULE_IMPL_DLFCN) && defined(__NuttX__)
#include <unistd.h>
#endif

#include <pthread.h>

#include <evp/sdk.h>

#include <internal/chan.h>
#include <internal/queue.h>

#include "sdk_common.h"
#include "stream/stream.h"
#include "xpthread.h"

extern struct evp_lock g_sdk_lock;
extern bool g_resend_request EVP_GUARDED_BY(g_sdk_lock);

/*
 * XXX todo: consider to embed this in struct module_instance
 */
struct EVP_client {
	TAILQ_ENTRY(EVP_client) q EVP_GUARDED_BY(g_sdk_lock);
	pthread_cond_t event_cv EVP_GUARDED_BY(g_sdk_lock);
#if defined(CONFIG_EVP_MODULE_IMPL_DLFCN) && defined(__NuttX__)
	pid_t pid;
#endif

	/*
	 * Things sent from the agent to the module instance
	 */

	TAILQ_HEAD(, sdk_event) events EVP_GUARDED_BY(g_sdk_lock);
	const char *name; /* module instance name */
	char *workspace;
	bool exiting;
#if defined(CONFIG_EVP_MODULE_IMPL_WASM)
	uint32_t workspace_wasm;
#endif

	/*
	 * Things sent from the module instance to the agent
	 */

	TAILQ_HEAD(, sdk_event) states EVP_GUARDED_BY(g_sdk_lock);
	TAILQ_HEAD(, sdk_event) blob_ops EVP_GUARDED_BY(g_sdk_lock);
	TAILQ_HEAD(, sdk_event) outbox_messages EVP_GUARDED_BY(g_sdk_lock);
	TAILQ_HEAD(, sdk_event) telemetry_list EVP_GUARDED_BY(g_sdk_lock);
	TAILQ_HEAD(, sdk_event) rpc_responses EVP_GUARDED_BY(g_sdk_lock);
	struct stream_queue streams EVP_GUARDED_BY(g_sdk_lock);

	/*
	 * Things only used by the module instance.
	 * The agent doesn't need to know these.
	 */

	struct sdk_common_callbacks cb;
	pthread_mutex_t mutex;
	struct chan *ch;
};

void sdk_assert_locked(void);
void sdk_mark_locked(void);
void sdk_mark_unlocked(void);
void sdk_lock(void) EVP_ACQUIRES(g_sdk_lock);
void sdk_unlock(void) EVP_RELEASES(g_sdk_lock);

void sdk_free_event(struct sdk_event *event);

#if defined(CONFIG_EVP_MODULE_IMPL_DLFCN) && defined(__NuttX__)
#include <unistd.h>
struct EVP_client *sdk_find_handle(pid_t pid) EVP_REQUIRES(g_sdk_lock);
#endif

/*
 * SDK API internal implementations
 */

EVP_RESULT EVP_impl_sendState(struct EVP_client *h, const void *rawbuf,
			      const char *topic, const void *blob,
			      size_t bloblen, EVP_STATE_CALLBACK cb,
			      void *userData) EVP_EXCLUDES(g_sdk_lock);
EVP_RESULT EVP_impl_blobOperation(struct EVP_client *h, const void *rawbuf,
				  EVP_BLOB_TYPE type, EVP_BLOB_OPERATION op,
				  const void *request,
				  struct EVP_BlobLocalStore *localStore,
				  EVP_BLOB_CALLBACK cb, void *userData)
	EVP_EXCLUDES(g_sdk_lock);
EVP_RESULT EVP_impl_sendMessage(struct EVP_client *h, const void *rawbuf,
				const char *topic, const void *blob,
				size_t bloblen, EVP_MESSAGE_SENT_CALLBACK cb,
				void *userData) EVP_EXCLUDES(g_sdk_lock);
EVP_RESULT EVP_impl_sendTelemetry(struct EVP_client *h, const void *rawbuf,
				  void *extra_alloc,
				  const struct EVP_telemetry_entry *entries,
				  size_t nentries, EVP_TELEMETRY_CALLBACK cb,
				  void *userData) EVP_EXCLUDES(g_sdk_lock);
EVP_RESULT EVP_impl_sendRpcResponse(struct EVP_client *h, const void *rawbuf,
				    EVP_RPC_ID id, const char *response,
				    EVP_RPC_RESPONSE_STATUS status,
				    EVP_RPC_RESPONSE_CALLBACK cb,
				    void *userData) EVP_EXCLUDES(g_sdk_lock);
EVP_RESULT EVP_impl_getEvent(struct EVP_client *h, int timeout_ms,
			     struct sdk_event **eventp);
EVP_RESULT EVP_impl_streamInputOpen_local(struct EVP_client *h,
					  const char *name,
					  EVP_STREAM_READ_CALLBACK cb,
					  void *userData, EVP_STREAM *stream);
EVP_RESULT EVP_impl_streamOutputOpen_local(struct EVP_client *h,
					   const char *name,
					   EVP_STREAM *stream);
EVP_RESULT EVP_impl_streamClose_local(struct EVP_client *h, EVP_STREAM stream);
EVP_RESULT EVP_impl_streamWrite_local(struct EVP_client *h, EVP_STREAM stream,
				      const void *buf, size_t n);

#endif /* !defined(__SDK_IMPL_H__) */
