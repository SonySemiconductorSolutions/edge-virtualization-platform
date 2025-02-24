/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <evp/sdk.h>
#include <mbedtls/base64.h>

#include <internal/queue.h>
#include <internal/util.h>

#include "base64.h"
#include "blob.h"
#include "cdefs.h"
#include "direct_command.h"
#include "event.h"
#include "global.h"
#include "main_loop.h"
#include "manifest.h"
#include "module_instance.h"
#include "mqtt_custom.h"
#include "path.h"
#include "sdk_agent.h"
#include "sdk_callback_impl_ops.h"
#include "sdk_impl.h"
#include "transport.h"
#include "xlog.h"
#include "xmqtt.h"
#include "xpthread.h"

struct evp_lock g_sdk_lock;

#if defined(__NuttX__) || defined(__GLIBC__)
#define PTHREAD_NONE ((pthread_t) - 1)
#else
/* musl, macOS, NetBSD, ... */
#define PTHREAD_NONE NULL
#endif
static pthread_t g_sdk_lock_holder = PTHREAD_NONE;
TAILQ_HEAD(, EVP_client)
g_handles EVP_GUARDED_BY(g_sdk_lock) = TAILQ_HEAD_INITIALIZER(g_handles);
bool g_resend_request EVP_GUARDED_BY(g_sdk_lock);

static TAILQ_HEAD(, blob_work) g_sdk_blob_rpcs
	EVP_GUARDED_BY(g_sdk_lock) = TAILQ_HEAD_INITIALIZER(g_sdk_blob_rpcs);

/* -------------- */

void
sdk_assert_locked(void)
{
	// TODO: Replace assert (programming error)
	assert(pthread_equal(g_sdk_lock_holder, pthread_self()));
}

void
sdk_assert_unlocked(void)
{
	// TODO: Replace assert (programming error)
	assert(!pthread_equal(g_sdk_lock_holder, pthread_self()));
}

void
sdk_mark_locked(void)
{
	// TODO: Replace assert (programming error)
	assert(pthread_equal(g_sdk_lock_holder, PTHREAD_NONE));
	g_sdk_lock_holder = pthread_self();
}

void
sdk_mark_unlocked(void)
{
	g_sdk_lock_holder = PTHREAD_NONE;
}

void
sdk_lock(void)
{
	xpthread_mutex_lock(&g_sdk_lock);
	sdk_mark_locked();
}

void
sdk_unlock(void)
{
	sdk_mark_unlocked();
	xpthread_mutex_unlock(&g_sdk_lock);
}

/* -------------- */

static EVP_RESULT
convert_oserrno_to_evp(int error)
{
	EVP_RESULT result;

	switch (error) {
	case EINVAL:
		result = EVP_INVAL;
		break;
	case ENOMEM:
		result = EVP_NOMEM;
		break;
	case E2BIG:
		result = EVP_TOOBIG;
		break;
	case ETIMEDOUT:
		result = EVP_TIMEDOUT;
		break;
	default:
		result = EVP_ERROR;
		break;
	}
	return result;
}

void
sdk_init(void)
{
	int ret = pthread_mutex_init(&g_sdk_lock.lock, NULL);
	if (ret != 0) {
		// Exit (xlog_abort): system error
		xlog_abort("pthread_mutex_init error %d", ret);
	}
}

#if defined(CONFIG_EVP_MODULE_IMPL_DLFCN) && defined(__NuttX__)
struct EVP_client *
sdk_find_handle(pid_t pid) EVP_REQUIRES(g_sdk_lock)
{
	struct EVP_client *h;

	sdk_assert_locked();
	TAILQ_FOREACH (h, &g_handles, q) {
		if (h->pid == pid) {
			return h;
		}
	}
	return NULL;
}
#endif

static struct sdk_event_message_received *
sdk_create_received_message(const void *blob, size_t bloblen,
			    const char *topic)
{
	struct sdk_event_message_received *msg =
		xcalloc(1, sizeof(struct sdk_event_message_received));
	msg->event.type = SDK_EVENT_MESSAGE_RECEIVED;
	void *blob2 = xmemdup(blob, bloblen);
	msg->blob = blob2;
	msg->bloblen = bloblen;
	msg->topic = xstrdup(topic);
	return msg;
}

static void
sdk_destroy_received_message(struct sdk_event_message_received *msg)
{
	// TODO: Replace assert (programming error)
	assert(msg);
	// TODO: Replace assert (programming error)
	assert(msg->topic);
	free(__UNCONST(msg->topic));
	// TODO: Replace assert (programming error)
	assert(msg->blob);
	free(__UNCONST(msg->blob));
}

static struct EVP_client *
sdk_find_handle_by_module_instance_name(const char *name)
	EVP_REQUIRES(g_sdk_lock)
{
	struct EVP_client *h;

	sdk_assert_locked();
	TAILQ_FOREACH (h, &g_handles, q) {
		if (strcmp(h->name, name) == 0) {
			return h;
		}
	}
	return NULL;
}

static void
on_event(struct chan_msg *msg)
{
	struct EVP_client *h = msg->param;
	struct sdk_event *event;
	EVP_RESULT result = EVP_impl_getEvent(h, 0, &event);
	extern const struct sdk_callback_impl_ops sdk_callback_impl_ops_native;

	if (result != EVP_OK) {
		xlog_error("an event was expected");
		return;
	}

	sdk_common_execute_event(&sdk_callback_impl_ops_native, &h->cb, event,
				 NULL);
	sdk_free_event(event);
}

static void
sdk_wakeup_handle(struct EVP_client *h)
{
	sdk_assert_locked();
	int ret = pthread_cond_broadcast(&h->event_cv);
	if (ret != 0) {
		// Exit (xlog_abort): system error
		xlog_abort("pthread_cond_broadcast error %d", ret);
	}

	if (h->ch) {
		struct chan_msg msg = {
			.fn = on_event,
			.param = h,
		};

		if (!chan_send(h->ch, &msg)) {
			xlog_error("chan_send failed");
		}
	}
}

void
sdk_queue_config(const char *name, const char *topic, const void *blob,
		 size_t bloblen)
{
	/* this function always consumes 'blob'. */
	sdk_lock();
	struct EVP_client *h = sdk_find_handle_by_module_instance_name(name);
	if (h != NULL && !h->exiting) {
		struct sdk_event *event;
		struct sdk_event_config *config;
		TAILQ_FOREACH (event, &h->events, q) {
			if (event->type == SDK_EVENT_CONFIG) {
				config = (void *)event;
				if (!strcmp(config->topic, topic)) {
					break;
				}
			}
		}
		if (event != NULL) {
			free(__UNCONST(config->topic));
			free(__UNCONST(config->blob));
		} else {
			config = xcalloc(1, sizeof(*config));
			TAILQ_INSERT_TAIL(&h->events, &config->event, q);
			sdk_wakeup_handle(h);
		}
		config->event.type = SDK_EVENT_CONFIG;
		config->topic = xstrdup(topic);
		config->blob = blob;
		config->bloblen = bloblen;
	} else {
		free(__UNCONST(blob));
	}
	sdk_unlock();
}

void
sdk_queue_message(const char *module_instance_name,
		  const char *subscribe_alias, const void *blob,
		  size_t bloblen)
{
	/* this function never consumes 'blob'. */
	sdk_lock();
	struct EVP_client *h =
		sdk_find_handle_by_module_instance_name(module_instance_name);
	if (h != NULL && !h->exiting) {
		struct sdk_event_message_received *inbox_msg =
			sdk_create_received_message(blob, bloblen,
						    subscribe_alias);
		struct sdk_event *event = (struct sdk_event *)inbox_msg;
		TAILQ_INSERT_TAIL(&h->events, event, q);
		sdk_wakeup_handle(h);
	}
	sdk_unlock();
}

void
sdk_queue_rpc_request(const char *module_instance_name, EVP_RPC_ID id,
		      const char *method, const char *params)
{
	/* this function always consumes 'params'. */
	sdk_lock();
	struct EVP_client *h =
		sdk_find_handle_by_module_instance_name(module_instance_name);
	if (h != NULL && !h->exiting) {
		struct sdk_event_rpc_request *r = xcalloc(1, sizeof(*r));
		r->event.type = SDK_EVENT_RPC_REQUEST;
		r->id = id;
		r->method = xstrdup(method);
		r->params = params;
		TAILQ_INSERT_TAIL(&h->events, &r->event, q);
		sdk_wakeup_handle(h);
	} else {
		free(__UNCONST(params));
	}
	sdk_unlock();
}

bool
sdk_check_resend_request(void)
{
	bool val;

	sdk_lock();
	val = g_resend_request;
	g_resend_request = false;
	sdk_unlock();
	return val;
}

void
sdk_collect_states(void (*cb)(const char *, const char *, const void *, size_t,
			      void *),
		   void *user)
{
	struct EVP_client *h;

	sdk_lock();
	TAILQ_FOREACH (h, &g_handles, q) {
		struct sdk_event *event;
		TAILQ_FOREACH (event, &h->states, q) {
			// TODO: Replace assert (programming error)
			assert(event->type == SDK_EVENT_STATE);
			struct sdk_event_state *state = (void *)event;
			cb(h->name, state->topic, state->blob, state->bloblen,
			   user);
			state->collected = true;
		}
	}
	sdk_unlock();
}

void
sdk_complete_collected_states(EVP_STATE_CALLBACK_REASON reason)
{
	struct EVP_client *h;

	sdk_lock();
	TAILQ_FOREACH (h, &g_handles, q) {
		struct sdk_event *event;
		struct sdk_event *next;
		TAILQ_FOREACH_SAFE (event, &h->states, q, next) {
			// TODO: Replace assert (programming error)
			assert(event->type == SDK_EVENT_STATE);
			struct sdk_event_state *state = (void *)event;
			if (!state->collected) {
				continue;
			}
			TAILQ_REMOVE(&h->states, event, q);
			state->reason = reason;
			TAILQ_INSERT_TAIL(&h->events, event, q);
			sdk_wakeup_handle(h);
		}
	}
	sdk_unlock();
}

void
sdk_collect_telemetry(int (*cb)(const char *,
				const struct EVP_telemetry_entry *, size_t,
				void *),
		      void *user)
{
	struct EVP_client *h;

	sdk_lock();
	TAILQ_FOREACH (h, &g_handles, q) {
		struct sdk_event *event;
		TAILQ_FOREACH (event, &h->telemetry_list, q) {
			// TODO: Replace assert (programming error)
			assert(event->type == SDK_EVENT_TELEMETRY);
			struct sdk_event_telemetry *t = (void *)event;

			int error = cb(h->name, t->entries, t->nentries, user);

			if (error) {
				xlog_error("failed to collect telemetry list");

				if (error == EAGAIN) {
					t->reason =
						EVP_TELEMETRY_CALLBACK_REASON_DENIED;
				} else {
					t->reason =
						EVP_TELEMETRY_CALLBACK_REASON_ERROR;
				}
			} else {
				t->reason = EVP_TELEMETRY_CALLBACK_REASON_SENT;
			}

			TAILQ_REMOVE(&h->telemetry_list, event, q);
			TAILQ_INSERT_TAIL(&h->events, event, q);
			sdk_wakeup_handle(h);
		}
	}

	sdk_unlock();
}

void
sdk_collect_rpc_responses(int (*cb)(const char *, EVP_RPC_ID, const char *,
				    EVP_RPC_RESPONSE_STATUS status, void *),
			  void *user)
{
	struct EVP_client *h;

	sdk_lock();
	TAILQ_FOREACH (h, &g_handles, q) {
		struct sdk_event *event;
		while ((event = TAILQ_FIRST(&h->rpc_responses))) {
			// TODO: Replace assert (programming error)
			assert(event->type == SDK_EVENT_RPC_RESPONSE);
			TAILQ_REMOVE(&h->rpc_responses, event, q);
			struct sdk_event_rpc_response *r = (void *)event;
			int ret = cb(h->name, r->id, r->response, r->status,
				     user);
			switch (ret) {
			case 0:
				r->reason =
					EVP_RPC_RESPONSE_CALLBACK_REASON_SENT;
				break;
			case ENOMEM:
				r->reason =
					EVP_RPC_RESPONSE_CALLBACK_REASON_DENIED;
				break;
			default:
				r->reason =
					EVP_RPC_RESPONSE_CALLBACK_REASON_ERROR;
				break;
			}
			TAILQ_INSERT_TAIL(&h->events, event, q);
			sdk_wakeup_handle(h);
		}
	}
	sdk_unlock();
}

struct blob_work *
sdk_dequeue_blob_rpc(void)
{
	struct blob_work *wk;

	sdk_lock();
	wk = TAILQ_FIRST(&g_sdk_blob_rpcs);
	if (wk != NULL) {
		TAILQ_REMOVE(&g_sdk_blob_rpcs, wk, rpcq);
	}
	sdk_unlock();
	return wk;
}

void
sdk_handoff_blob_rpc(struct blob_work *wk)
{
	sdk_lock();
	if (wk->user != NULL) {
		blob_work_enqueue(wk);
	} else {
		/* already detached by sdk_detach_blob_work */
		xlog_debug("freeing detached blob work");
		blob_work_free(wk);
	}
	sdk_unlock();
}

static void
sdk_detach_blob_work(struct sdk_event_blob *blob)
{
	sdk_assert_locked();
	struct blob_work *wk = blob->work;
	// TODO: Replace assert (programming error)
	assert(wk != NULL);
	// TODO: Replace assert (programming error)
	assert(wk->user == blob);
	blob->work = NULL;
	int error = blob_work_cancel(wk);
	if (error == 0) {
		/* cancelled successfully. safe to free it. */
		blob_work_free(wk);
	} else {
		xlog_debug("Failed to cancel with %d", error);
		/* Leave it go. sdk_blob_done will free it. */
		wk->user = NULL;
	}
	blob->owner = NULL;
}

void
sdk_process_outbox_messages(void)
{
	struct sdk_event *event;
	TAILQ_HEAD(, sdk_event) todo;
	struct EVP_client *h;

	/*
	 * Note: module_instance and global public/subscribe lists
	 * are stable here, because the agent main loop is
	 * single-threaded.
	 *
	 * Note: struct EVP_client *s are also stable because
	 * sdk_cleanup is also a part of the main loop.
	 */

	TAILQ_INIT(&todo);
	sdk_lock();
	/* for each module instance's (handle) ... */
	TAILQ_FOREACH (h, &g_handles, q) {
		/* ... iterate its outbox messages ... */
		while ((event = TAILQ_FIRST(&h->outbox_messages)) != NULL) {
			TAILQ_REMOVE(&h->outbox_messages, event, q);
			// TODO: Replace assert (programming error)
			assert(event->type == SDK_EVENT_MESSAGE_SENT);
			struct sdk_event_message_sent *msg = (void *)event;
			msg->from = h;
			TAILQ_INSERT_TAIL(&todo, event, q);
		}
	}
	sdk_unlock();

	TAILQ_FOREACH (event, &todo, q) {
		// TODO: Replace assert (programming error)
		assert(event->type == SDK_EVENT_MESSAGE_SENT);
		struct sdk_event_message_sent *msg = (void *)event;
		struct module_instance *m;

		h = msg->from;
		// TODO: Replace assert (programming error)
		assert(h != NULL);
		m = get_module_instance_by_name(h->name);
		// TODO: Replace assert (runtime error)
		assert(m != NULL);
		module_instance_message_send(m, msg);
	}

	/* transform messages into events */
	sdk_lock();
	while ((event = TAILQ_FIRST(&todo)) != NULL) {
		// TODO: Replace assert (programming error)
		assert(event->type == SDK_EVENT_MESSAGE_SENT);
		struct sdk_event_message_sent *msg = (void *)event;
		TAILQ_REMOVE(&todo, event, q);
		/* for mqtt messages, update the callback reason
		 * depending on mqtt_sync result */
		if (msg->mqtt_published) {
			msg->reason = EVP_MESSAGE_SENT_CALLBACK_REASON_SENT;
		}
		/* ... adding it to events */
		h = msg->from;
		// TODO: Replace assert (programming error)
		assert(h != NULL);
		TAILQ_INSERT_TAIL(&h->events, event, q);
		sdk_wakeup_handle(h);
	}
	sdk_unlock();
}

void
sdk_clear_events(struct EVP_client *h)
{
	struct sdk_event *event;

	sdk_lock();

	/* cancel all states */
	while ((event = TAILQ_FIRST(&h->states)) != NULL) {
		TAILQ_REMOVE(&h->states, event, q);
		sdk_free_event(event);
	}

	/* try to cancel all blob ops */
	while ((event = TAILQ_FIRST(&h->blob_ops)) != NULL) {
		TAILQ_REMOVE(&h->blob_ops, event, q);
		struct sdk_event_blob *blob = (void *)event;
		sdk_detach_blob_work(blob);
		sdk_free_event(event);
	}

	/* cancel all outbox messages */
	while ((event = TAILQ_FIRST(&h->outbox_messages)) != NULL) {
		TAILQ_REMOVE(&h->outbox_messages, event, q);
		sdk_free_event(event);
	}

	/* cancel all telemetry requests */
	while ((event = TAILQ_FIRST(&h->telemetry_list)) != NULL) {
		TAILQ_REMOVE(&h->telemetry_list, event, q);
		sdk_free_event(event);
	}

	/* cancel all RPC responses */
	while ((event = TAILQ_FIRST(&h->rpc_responses)) != NULL) {
		TAILQ_REMOVE(&h->rpc_responses, event, q);
		sdk_free_event(event);
	}

	sdk_unlock();
}

void
sdk_signal_exit(struct EVP_client *h)
{
	// TODO: Replace assert (programming error)
	assert(h != NULL);
	sdk_lock();
	if (h->exiting) {
		sdk_unlock();
		return;
	}
	h->exiting = true;

	struct sdk_event *event;

	/* cancel all states */
	while ((event = TAILQ_FIRST(&h->states)) != NULL) {
		TAILQ_REMOVE(&h->states, event, q);
		// TODO: Replace assert (programming error)
		assert(event->type == SDK_EVENT_STATE);
		struct sdk_event_state *state = (void *)event;
		state->reason = EVP_STATE_CALLBACK_REASON_EXIT;
		TAILQ_INSERT_TAIL(&h->events, event, q);
	}

	/* try to cancel all blob ops */
	while ((event = TAILQ_FIRST(&h->blob_ops)) != NULL) {
		TAILQ_REMOVE(&h->blob_ops, event, q);
		// TODO: Replace assert (programming error)
		assert(event->type == SDK_EVENT_BLOB);
		struct sdk_event_blob *blob = (void *)event;
		blob->reason = EVP_BLOB_CALLBACK_REASON_EXIT;
		sdk_detach_blob_work(blob);
		TAILQ_INSERT_TAIL(&h->events, event, q);
	}

	/* cancel all outbox messages */
	while ((event = TAILQ_FIRST(&h->outbox_messages)) != NULL) {
		TAILQ_REMOVE(&h->outbox_messages, event, q);
		// TODO: Replace assert (programming error)
		assert(event->type == SDK_EVENT_MESSAGE_SENT);
		struct sdk_event_message_sent *message = (void *)event;
		message->reason = EVP_MESSAGE_SENT_CALLBACK_REASON_EXIT;
		TAILQ_INSERT_TAIL(&h->events, event, q);
	}

	/* cancel all telemetry requests */
	while ((event = TAILQ_FIRST(&h->telemetry_list)) != NULL) {
		TAILQ_REMOVE(&h->telemetry_list, event, q);
		// TODO: Replace assert (programming error)
		assert(event->type == SDK_EVENT_TELEMETRY);
		struct sdk_event_telemetry *t = (void *)event;
		t->reason = EVP_TELEMETRY_CALLBACK_REASON_EXIT;
		TAILQ_INSERT_TAIL(&h->events, event, q);
	}

	/* cancel all RPC responses */
	while ((event = TAILQ_FIRST(&h->rpc_responses)) != NULL) {
		TAILQ_REMOVE(&h->rpc_responses, event, q);
		// TODO: Replace assert (programming error)
		assert(event->type == SDK_EVENT_RPC_RESPONSE);
		struct sdk_event_rpc_response *r = (void *)event;
		r->reason = EVP_RPC_RESPONSE_CALLBACK_REASON_EXIT;
		TAILQ_INSERT_TAIL(&h->events, event, q);
	}
	sdk_wakeup_handle(h);
	sdk_unlock();
}

void
sdk_free_event(struct sdk_event *event)
{
	switch (event->type) {
	case SDK_EVENT_CONFIG:
		{
			struct sdk_event_config *config = (void *)event;
			free(__UNCONST(config->topic));
			free(__UNCONST(config->blob));
		}
		break;
	case SDK_EVENT_STATE:
		/* nothing */
		break;
	case SDK_EVENT_BLOB_GET_UPLOAD_URL:
	case SDK_EVENT_BLOB:
		{
			struct sdk_event_blob *blob = (void *)event;
			struct blob_work *wk = blob->work;
			if (wk) {
				blob_work_free(wk);
			}
		}
		break;
	case SDK_EVENT_MESSAGE_SENT:
		/* nothing */
		break;
	case SDK_EVENT_MESSAGE_RECEIVED:
		{
			struct sdk_event_message_received *received_message =
				(void *)event;
			sdk_destroy_received_message(received_message);
		}
		break;
	case SDK_EVENT_TELEMETRY:
		/* nothing */
		break;
	case SDK_EVENT_RPC_REQUEST:
		{
			struct sdk_event_rpc_request *rpc = (void *)event;
			free(__UNCONST(rpc->method));
			free(__UNCONST(rpc->params));
		}
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
	case SDK_EVENT_BLOB_IO_READ:
		/* nothing */
	case SDK_EVENT_BLOB_IO_WRITE:
		/* nothing */
		break;
	default:
		// TODO: Replace assert (programming error)
		assert(0);
	}
	free(event->extra_alloc);
	free(__UNCONST(event->buffer));
	free(event);
}

void
sdk_cleanup(struct EVP_client *h)
{
	// TODO: Replace assert (programming error)
	assert(h != NULL);
	// TODO: Replace assert (programming error)
	assert(h->exiting);
	sdk_handle_remove(h);
	sdk_handle_destroy(h);
	sdk_handle_free(h);
}

static struct work *
sdk_blob_done(struct work *gwk)
{
	struct blob_work *wk = (void *)gwk;
	sdk_lock();
	struct sdk_event_blob *blob = wk->user;
	if (blob != NULL) {
		struct EVP_client *h = blob->owner;
		// TODO: Replace assert (programming error)
		assert(h != NULL);
		blob->owner = NULL;
		// TODO: Wondering if reason EXIT is relevant enough
		//       or if we should also have blob reason cancelled.
		if (wk->wk.status == WORK_STATUS_CANCELLED) {
			blob->reason = EVP_BLOB_CALLBACK_REASON_EXIT;
		} else if (wk->result == BLOB_RESULT_DENIED) {
			blob->reason = EVP_BLOB_CALLBACK_REASON_DENIED;
		} else {
			blob->reason = EVP_BLOB_CALLBACK_REASON_DONE;
		}
		TAILQ_REMOVE(&h->blob_ops, &blob->event, q);
		TAILQ_INSERT_TAIL(&h->events, &blob->event, q);
		sdk_wakeup_handle(h);
	} else {
		blob_work_free(wk);
	}
	sdk_unlock();
	return NULL;
}

/*
 * Message forwarding related functions
 * ====================================
 *
 * The following functions are related to message forwarding
 * (for intermodule communication, etc), according to what is stated
 * in the deployment manifest.
 *
 * For a given manifest example:
 *
 * {
 *  "instanceSpecs": {
 *   "moduleA": {
 *    ...
 *    "publish": {
 *     "moduleAPublishAlias1" : "publishTopic1" // forward step #1
 *    }
 *   }
 *   "moduleB": {
 *    ...
 *    "subscribe": {
 *     "moduleAsSubscribeAlias1" : "subscribeTopic1" // forward step #4
 *    }
 *   }
 *  },
 *  "publish_topics": {
 *   "publishTopic1": { // forward step #2.1
 *    "type": "local",
 *    "topic": "topic1" // forward step #2.2
 *   }
 *  },
 *  "subscribe_topics": {
 *   "subscribeTopic1": { // forward step #3.2
 *    "type": "local",
 *    "topic": "topic1" // forward step #3.1
 *   }
 *  }
 * }
 *
 * The message path from a message from A using "moduleAPublishAlias1" as topic
 * is:
 *
 * moduleAPublishAlias1
 *  -> forwarding step #1
 *   publishTopic1
 *    -> forwarding step #2
 *     topic1
 *      -> forwarding step #3
 *       subscribeTopic1
 *        -> forwarding step #4
 *         moduleAsSubscribeAlias1
 *          -> forwarding step #5
 *           destination module "inbox"
 *
 */

void
sdk_handle_init(struct EVP_client *h, const char *name)
{
	int ret;
	ret = pthread_cond_init(&h->event_cv, NULL);
	if (ret != 0) {
		// Exit (xlog_abort): system error
		xlog_abort("pthread_cond_init error %d", ret);
	}
	TAILQ_INIT(&h->events);
	TAILQ_INIT(&h->states);
	TAILQ_INIT(&h->blob_ops);
	TAILQ_INIT(&h->outbox_messages);
	TAILQ_INIT(&h->telemetry_list);
	TAILQ_INIT(&h->rpc_responses);
	TAILQ_INIT(&h->streams);
	h->name = name;

	int error = pthread_mutex_init(&h->mutex, NULL);

	if (error) {
		xlog_error("pthread_mutex_init failed with %d", error);
	}

#if defined(CONFIG_EVP_MODULE_IMPL_DLFCN) && defined(__NuttX__)
	h->pid = -1;
#endif
#if defined(CONFIG_EVP_MODULE_IMPL_DLFCN) ||                                  \
	defined(CONFIG_EVP_MODULE_IMPL_WASM)
	const char *module_instance_dir = path_get(MODULE_INSTANCE_PATH_ID);
	xasprintf(&h->workspace, "%s/%s/%s", module_instance_dir, h->name,
		  DEFAULT_WORKSPACE_DIR);
#else
	h->workspace = xstrdup("not implemented");
#endif
}

void
sdk_handle_rename(struct EVP_client *h, const char *name)
{
	sdk_lock();
	h->name = name;
	sdk_unlock();
}

#if defined(CONFIG_EVP_MODULE_IMPL_DLFCN) && defined(__NuttX__)
void
sdk_handle_setpid(struct EVP_client *h, pid_t pid)
{
	sdk_lock();
	// TODO: Replace assert (programming error)
	assert(h->pid == -1);
	h->pid = pid;
	sdk_unlock();
}
#endif

void
sdk_handle_insert(struct EVP_client *h)
{
	sdk_lock();
	struct EVP_client *h1 =
		sdk_find_handle_by_module_instance_name(h->name);
	if (h1 == NULL) {
		TAILQ_INSERT_TAIL(&g_handles, h, q);
	} else {
		// TODO: Replace assert (programming error)
		assert(h1 == h);
	}
	sdk_unlock();
}

void
sdk_handle_remove(struct EVP_client *h)
{
	sdk_lock();
	struct EVP_client *h1 =
		sdk_find_handle_by_module_instance_name(h->name);
	if (h1 != NULL) {
		// TODO: Replace assert (programming error)
		assert(h1 == h);
		TAILQ_REMOVE(&g_handles, h, q);
	}
	// TODO: Replace assert (runtime error)
	assert(sdk_find_handle_by_module_instance_name(h->name) == NULL);
	sdk_unlock();
}

void
sdk_handle_destroy(struct EVP_client *h)
{
	int ret;
	ret = pthread_cond_destroy(&h->event_cv);
	if (ret != 0) {
		// Exit (xlog_abort): system error
		xlog_abort("pthread_cond_destroy error %d", ret);
	}
	// TODO: Replace assert (programming error)
	assert(TAILQ_EMPTY(&h->states));
	// TODO: Replace assert (programming error)
	assert(TAILQ_EMPTY(&h->blob_ops));
	// TODO: Replace assert (programming error)
	assert(TAILQ_EMPTY(&h->outbox_messages));
	// TODO: Replace assert (programming error)
	assert(TAILQ_EMPTY(&h->telemetry_list));
	// TODO: Replace assert (programming error)
	assert(TAILQ_EMPTY(&h->rpc_responses));
	// TODO: Replace assert (programming error)
	assert(TAILQ_EMPTY(&h->streams));
	struct sdk_event *event;
	while ((event = TAILQ_FIRST(&h->events)) != NULL) {
		TAILQ_REMOVE(&h->events, event, q);
		/*
		 * The following unnatural assertion was added to suppress
		 * a clang ananlyzer warning.
		 * "warning: Use of memory after it is freed [unix.Malloc]"
		 */
		// TODO: Replace assert (programming error)
		assert(event != TAILQ_FIRST(&h->events));
		sdk_free_event(event);
	}
	free(h->workspace);
}

struct EVP_client *
sdk_handle_alloc(void)
{
	struct EVP_client *h = xcalloc(1, sizeof(*h));
	return h;
}

void
sdk_handle_free(struct EVP_client *h)
{
	free(h);
}

/* -------------- */

EVP_RESULT
EVP_impl_sendState(struct EVP_client *h, const void *rawbuf, const char *topic,
		   const void *blob, size_t bloblen, EVP_STATE_CALLBACK cb,
		   void *userData)
{
	EVP_RESULT ret;
	size_t len, base64len;
	bool needs_main_wakeup = false;
	struct sdk_event_state *state = NULL;

	/*
	 * FIXME: We check that this new state inserted in the current object
	 * fits in a mqtt package, but this function does not update the
	 * current object. If this function is called again before current is
	 * updated this new state will not be used in the size calculation.
	 * The check is done using a base64 encoding because it is the worst
	 * case between EVP1 and EVP2 way of encoding the state.
	 */
	base64len = 0;
	len = snprintf(NULL, 0, "{ \"state/%s/%s\" : \"\" },\n", h->name,
		       topic);
	mbedtls_base64_encode(NULL, 0, &base64len, blob, bloblen);
	len += base64len;

	xpthread_mutex_lock(&g_evp_global.instance_states_lock);
	len += g_evp_global.instance_states_len;
	xpthread_mutex_unlock(&g_evp_global.instance_states_lock);

	if (g_mqtt_client == NULL) {
		ret = EVP_ERROR;
		goto end;
	}

	sdk_assert_unlocked();
	if (!xmqtt_request_fits(g_mqtt_client, len)) {
		ret = EVP_TOOBIG;
		goto end;
	}

	/*
	 * We just record the (topic, state) pair here.
	 * at some time later, periodic_report will gather them and
	 * send to the cloud.
	 */

	state = malloc(sizeof(*state));
	if (state == NULL) {
		ret = convert_oserrno_to_evp(errno);
		goto end;
	}
	*state = (struct sdk_event_state){
		.event =
			{
				.type = SDK_EVENT_STATE,
				.buffer = rawbuf,
			},
		.topic = topic,
		.blob = blob,
		.bloblen = bloblen,
		.cb = cb,
		.cb_userdata = userData,
	};

	sdk_lock();
	/* if there's a pending state with the same topic, cancel it. */
	struct sdk_event *oevent;
	TAILQ_FOREACH (oevent, &h->states, q) {
		// TODO: Replace assert (programming error)
		assert(oevent->type == SDK_EVENT_STATE);
		struct sdk_event_state *ostate = (void *)oevent;

		if (!strcmp(ostate->topic, topic)) {
			TAILQ_REMOVE(&h->states, oevent, q);
			ostate->reason = EVP_STATE_CALLBACK_REASON_OVERWRITTEN;
			TAILQ_INSERT_TAIL(&h->events, oevent, q);
			sdk_wakeup_handle(h);
			break;
		}
	}
	if (h->exiting) {
		/* Don't accept new State while exiting */
		state->reason = EVP_STATE_CALLBACK_REASON_EXIT;
		TAILQ_INSERT_TAIL(&h->events, &state->event, q);
		sdk_wakeup_handle(h);
	} else {
		TAILQ_INSERT_TAIL(&h->states, &state->event, q);
		needs_main_wakeup = true;
	}
	if (needs_main_wakeup) {
		main_loop_wakeup("STATE");
	}
	ret = EVP_OK;
	sdk_unlock();
end:
	if (ret) {
		free(state);
	}
	return ret;
}

static int
wait_io_event(enum sdk_event_type type, const union sdk_event_blob_io_buf *b,
	      size_t n, void *vp)
{
	struct sdk_event_blob_io_callback_closure *closure = vp;
	EVP_BLOB_IO_CALLBACK cb = closure->cb;
	void *cb_userdata = closure->cb_data;
	struct EVP_client *h = closure->h;
	int out_errno = -ECANCELED;
	sem_t sem;

	if (sem_init(&sem, 0, 0)) {
		out_errno = -errno;
		xlog_error("sem_init failed with errno %d", errno);
		goto end;
	}

	sdk_lock();
	if (!h->exiting) {
		struct sdk_event_blob_io *event = malloc(sizeof(*event));

		if (event == NULL) {
			out_errno = -errno;
			xlog_error("malloc(3) failed with errno %d", errno);
			goto end_locked;
		}

		*event = (struct sdk_event_blob_io){.event.type = type,
						    .cb = cb,
						    .buf = *b,
						    .n = n,
						    .cb_data = cb_userdata,
						    .h = h,
						    .out_errno = &out_errno,
						    .sem = &sem};

		TAILQ_INSERT_TAIL(&h->events, &event->event, q);
		sdk_wakeup_handle(h);
		sdk_unlock();

		if (sem_wait(&sem)) {
			out_errno = -errno;
			xlog_error("sem_wait failed with errno %d", errno);
		}
		goto end_unlocked;
	}

end_locked:
	sdk_unlock();

end_unlocked:
	if (sem_destroy(&sem)) {
		out_errno = -errno;
		xlog_error("sem_destroy failed with errno %d", errno);
	}
end:
	return out_errno;
}

static int
sdk_blob_forward_write_func(unsigned http_status, char **bufp, int offset,
			    int datend, int *buflen, void *vp)
{
	union sdk_event_blob_io_buf b = {.ro = *bufp + offset};
	size_t n = datend - offset;

	return wait_io_event(SDK_EVENT_BLOB_IO_WRITE, &b, n, vp);
}

static int
sdk_blob_forward_read_func(void *buffer, size_t *sizep, const void **datap,
			   size_t reqsize, void *vp)
{
	size_t n = reqsize > *sizep ? *sizep : reqsize;
	union sdk_event_blob_io_buf b = {.rw = buffer};
	int ret = wait_io_event(SDK_EVENT_BLOB_IO_READ, &b, n, vp);

	if (!ret) {
		*sizep = n;
	}

	return ret;
}

/*
 *   START
 *     +
 *     |
 *     |EVP_blobOperation
 *     |
 *     | alloc sdk_event_blob
 *     | alloc blob_work
 *     |
 *     v
 * +---+---+                  +-------+  Module Instance
 * |       | I/O completion   |       |  gets the result
 * |       +----------------->+       +-------------------> DONE
 * |       | sdk_blob_done    |       | EVP_processEvent   free sdk_event_blob
 * +---+---+                  +---+---+                    free blob_work
 *     |                          |
 *     |                          |
 *     +<-------------------------+
 *     |
 *     |
 *     |Module Instance exits
 *     |
 *     |sdk_signal_exit
 *     |
 *     |
 *     |Detach blob_work from sdk_event_blob
 *     +----------------------+
 *     |                      |
 * (blob_work)         (sdk_event_blob)
 *     |                      |
 *     |                  +---+---+
 *     |                  |       |
 *     |                  |       +-----------------------> EXIT
 *     |                  |       |  EVP_processEvent      free sdk_event_blob
 *     |                  +---+---+
 *     |
 *     v
 * +---+---+
 * |       | I/O cancel succeed
 * |       +-------------------> free blob_work
 * |       |
 * +---+---+
 *     |
 *     |I/O cancel
 *     |failed
 *     |
 *     v
 * +---+---+
 * |       | I/O completion
 * |       +-------------------> free blob_work
 * |       | sdk_blob_done
 * +-------+
 */

__CTASSERT((enum blob_work_type)EVP_BLOB_TYPE_AZURE_BLOB ==
	   BLOB_TYPE_AZURE_BLOB);
__CTASSERT((enum blob_work_op)EVP_BLOB_OP_GET == BLOB_OP_GET);
__CTASSERT((enum blob_work_op)EVP_BLOB_OP_PUT == BLOB_OP_PUT);
__CTASSERT((enum blob_work_type)EVP_BLOB_TYPE_EVP == deprecated_BLOB_TYPE_EVP);
__CTASSERT((enum blob_work_type)EVP_BLOB_TYPE_HTTP == BLOB_TYPE_HTTP);
__CTASSERT((enum blob_work_type)EVP_BLOB_TYPE_EVP_EXT == BLOB_TYPE_EVP_EXT);
__CTASSERT((enum blob_work_type)EVP_BLOB_TYPE_HTTP_EXT == BLOB_TYPE_HTTP_EXT);

static int
check_blob_type(EVP_BLOB_TYPE type)
{
	switch (type) {
	case EVP_BLOB_TYPE_AZURE_BLOB:
	case EVP_BLOB_TYPE_EVP:
	case EVP_BLOB_TYPE_HTTP:
	case EVP_BLOB_TYPE_EVP_EXT:
	case EVP_BLOB_TYPE_HTTP_EXT:
		return 0;
	default:
		break;
	}

	return -1;
}

static int
check_blob_op(EVP_BLOB_OPERATION op)
{
	switch (op) {
	case EVP_BLOB_OP_GET:
	case EVP_BLOB_OP_PUT:
		return 0;
	default:
		break;
	}

	return -1;
}

static EVP_RESULT
blob_check_convert_filename(struct EVP_client *h,
			    const struct EVP_BlobLocalStore *localStore,
			    char **path_in_agent)
{
	/*
	 * check and convert the filename.
	 */

	if (localStore != NULL && localStore->filename != NULL) {
		struct module_instance *m =
			get_module_instance_by_name(h->name);
		// TODO: Replace assert (runtime error)
		assert(m != NULL);
		int error = module_instance_convert_path(
			m, localStore->filename, path_in_agent);
		if (error != 0) {
			return convert_oserrno_to_evp(error);
		}
	}

	return EVP_OK;
}

union request_args {
	const void *request;
	const struct EVP_BlobRequestAzureBlob *azure_request;
	const struct EVP_BlobRequestEvp *evp_request;
	const struct EVP_BlobRequestHttp *http_request;
	const struct EVP_BlobRequestEvpExt *evp_ext_request;
	const struct EVP_BlobRequestHttpExt *http_ext_request;
};

static EVP_RESULT
init_blob_work_azure(struct blob_work *wk, struct EVP_client *h,
		     const union request_args *req)
{
	const struct EVP_BlobRequestAzureBlob *azure = req->azure_request;
	char *url = strdup(azure->url);

	if (url == NULL) {
		return convert_oserrno_to_evp(errno);
	}

	wk->url = url;
	return EVP_OK;
}

static EVP_RESULT
init_blob_work_evp(struct blob_work *wk, struct EVP_client *h,
		   const union request_args *req)
{
	EVP_RESULT ret;
	const struct EVP_BlobRequestEvp *evp = req->evp_request;
	char *instance_name = strdup(h->name);
	char *remote_name = strdup(evp->remote_name);

	if (instance_name == NULL || remote_name == NULL) {
		ret = convert_oserrno_to_evp(errno);
		goto end;
	}

	wk->type = BLOB_TYPE_EVP_EXT;
	wk->remote_name = remote_name;
	wk->module_instance_name = instance_name;
	wk->storage_name = NULL;
	ret = EVP_OK;

end:
	if (ret != EVP_OK) {
		free(instance_name);
		free(remote_name);
	}

	return ret;
}

static EVP_RESULT
init_blob_work_evp_ext(struct blob_work *wk, struct EVP_client *h,
		       const union request_args *req)
{
	EVP_RESULT ret;
	const struct EVP_BlobRequestEvpExt *evp_ext = req->evp_ext_request;
	char *storage_name = NULL;
	char *remote_name = strdup(evp_ext->remote_name);
	char *instance_name = strdup(h->name);

	if (evp_ext->storage_name != NULL) {
		storage_name = strdup(evp_ext->storage_name);

		if (storage_name == NULL) {
			ret = convert_oserrno_to_evp(errno);
			goto end;
		}
	} else {
		/*
		 * The defaut EVP storage will be used when
		 * storage_name is NULL.
		 */
	}
	wk->storage_name = storage_name;
	wk->remote_name = remote_name;
	wk->module_instance_name = instance_name;
	ret = EVP_OK;

end:
	if (ret != EVP_OK) {
		free(storage_name);
		free(remote_name);
		free(instance_name);
	}
	return ret;
}

static EVP_RESULT
init_blob_work_http(struct blob_work *wk, struct EVP_client *h,
		    const union request_args *req)
{
	const struct EVP_BlobRequestHttp *http = req->http_request;
	char *url = strdup(http->url);

	if (url == NULL) {
		return convert_oserrno_to_evp(errno);
	}

	wk->url = url;
	return EVP_OK;
}

static EVP_RESULT
init_blob_work_http_ext(struct blob_work *wk, struct EVP_client *h,
			const union request_args *req)
{
	const struct EVP_BlobRequestHttpExt *http_ext = req->http_ext_request;
	char *url = strdup(http_ext->url);
	if (url == NULL) {
		return convert_oserrno_to_evp(errno);
	}

	char **headers_aux = xcalloc(http_ext->nheaders, sizeof(*headers_aux));
	if (headers_aux == NULL) {
		goto url_cleanup;
	}
	unsigned int nheaders = 0;
	for (nheaders = 0; nheaders < http_ext->nheaders; nheaders++) {
		headers_aux[nheaders] = xstrdup(http_ext->headers[nheaders]);
		if (headers_aux[nheaders] == NULL) {
			goto headers_cleanup;
		}
	}
	wk->headers_rw = headers_aux;
	wk->nheaders = nheaders;
	wk->url = url;
	return EVP_OK;
headers_cleanup:
	for (unsigned int i = 0; i < nheaders; i++) {
		free((void *)headers_aux[i]);
	}
	free(headers_aux);
url_cleanup:
	free(url);
	return convert_oserrno_to_evp(errno);
}

static EVP_RESULT
check_blob_limit(struct EVP_client *h)
{
	size_t n = 0;
	const struct sdk_event *ev;

	TAILQ_FOREACH (ev, &h->blob_ops, q) {
		n++;
	}

	if (n >= CONFIG_EVP_AGENT_MAX_LIVE_BLOBS_PER_INSTANCE) {
		xlog_error("exceeded maximum allowed number of ongoing blob "
			   "requests for module instance %s (%d)",
			   h->name,
			   CONFIG_EVP_AGENT_MAX_LIVE_BLOBS_PER_INSTANCE);
		return EVP_DENIED;
	}

	return EVP_OK;
}

static EVP_RESULT
init_blob_work(struct blob_work **wk, EVP_BLOB_TYPE type,
	       EVP_BLOB_OPERATION op, struct sdk_event_blob *blob)
{
	struct blob_work *ret = blob_work_alloc();

	if (ret == NULL) {
		return convert_oserrno_to_evp(errno);
	}

	*ret = (struct blob_work){
		.type = (enum blob_work_type)type,
		.op = (enum blob_work_op)op,
		.headers = NULL,
		.nheaders = 0,
		.webclient_sink_callback = sdk_blob_forward_write_func,
		.webclient_sink_callback_arg = &blob->io_cb,
		.webclient_body_callback = sdk_blob_forward_read_func,
		.webclient_body_callback_arg = &blob->io_cb,
		.wk.done = sdk_blob_done,
		.user = blob,
	};

	*wk = ret;
	return EVP_OK;
}

static EVP_RESULT
store_blob_work(struct EVP_client *h, struct blob_work **wkp,
		struct sdk_event_blob *blob, const void *request,
		EVP_BLOB_TYPE type, EVP_BLOB_OPERATION op,
		const struct EVP_BlobLocalStore *localStore)
{
	/*
	 * NOTE: blob_work can live longer than the requesting
	 * Module Instance.
	 * after calling blob_work_enqueue, "wk" is shared among
	 * threads.
	 */
	EVP_RESULT ret;
	char *path_in_agent = NULL;
	struct blob_work *wk = NULL;

	ret = check_blob_limit(h);
	if (ret != EVP_OK) {
		goto end;
	}

	ret = init_blob_work(&wk, type, op, blob);
	if (ret != EVP_OK) {
		goto end;
	}

	/* Get the valid blob struct */
	union request_args req = {.request = request};

	static EVP_RESULT (*const init[])(struct blob_work *,
					  struct EVP_client *h,
					  const union request_args *) = {
		[EVP_BLOB_TYPE_AZURE_BLOB] = init_blob_work_azure,
		[EVP_BLOB_TYPE_EVP] = init_blob_work_evp,
		[EVP_BLOB_TYPE_EVP_EXT] = init_blob_work_evp_ext,
		[EVP_BLOB_TYPE_HTTP] = init_blob_work_http,
		[EVP_BLOB_TYPE_HTTP_EXT] = init_blob_work_http_ext,
	};

	if (type < 0 || type >= __arraycount(init)) {
		ret = EVP_INVAL;
		goto end;
	}

	ret = init[type](wk, h, &req);
	if (ret != EVP_OK) {
		goto end;
	}

	ret = blob_check_convert_filename(h, localStore, &path_in_agent);
	if (ret != EVP_OK) {
		goto end;
	} else if (path_in_agent != NULL) {
		wk->filename = path_in_agent;
	} else {
		wk->blob_len = localStore->blob_len;
	}

	blob_work_set_proxy(wk);
	*wkp = wk;
	ret = EVP_OK;
end:
	if (ret != EVP_OK) {
		free(path_in_agent);
		free(wk);
	}
	return ret;
}

static EVP_RESULT
init_blob_common(struct sdk_event_blob **blob, const void *rawbuf,
		 const struct EVP_BlobLocalStore *localStore,
		 EVP_BLOB_CALLBACK cb, void *userData, struct EVP_client *h)
{
	struct sdk_event_blob *ret = malloc(sizeof(*ret));

	if (ret == NULL) {
		return convert_oserrno_to_evp(errno);
	}

	*ret = (struct sdk_event_blob){.event =
					       {
						       .type = SDK_EVENT_BLOB,
						       .buffer = rawbuf,
					       },
				       .user_cb =
					       {
						       .cb = cb,
						       .cb_data = userData,
					       },
				       .io_cb = {.cb = localStore->io_cb,
						 .cb_data = userData,
						 .h = h}};
	*blob = ret;
	return EVP_OK;
}

EVP_RESULT
EVP_impl_blobOperation(struct EVP_client *h, const void *rawbuf,
		       EVP_BLOB_TYPE type, EVP_BLOB_OPERATION op,
		       const void *request,
		       struct EVP_BlobLocalStore *localStore,
		       EVP_BLOB_CALLBACK cb, void *userData)
{
	EVP_RESULT ret;
	struct sdk_event_blob *blob = NULL;
	struct blob_work *wk = NULL;

	if (check_blob_type(type) || check_blob_op(op)) {
		ret = EVP_INVAL;
		goto unlocked;
	}

	/* EVP blob get not supported. Check it here to avoid create a ST
	 * request in agent side */
	if ((op == EVP_BLOB_OP_GET) &&
	    ((type == EVP_BLOB_TYPE_EVP_EXT) || (type == EVP_BLOB_TYPE_EVP))) {
		return EVP_NOTSUP;
	}

	sdk_assert_unlocked();
	ret = init_blob_common(&blob, rawbuf, localStore, cb, userData, h);
	if (ret != EVP_OK) {
		goto unlocked;
	}

	sdk_lock();

	if (h->exiting) {
		/* Don't accept new request while exiting */
		blob->reason = EVP_BLOB_CALLBACK_REASON_EXIT;
		TAILQ_INSERT_TAIL(&h->events, &blob->event, q);
		sdk_wakeup_handle(h);
	} else {
		ret = store_blob_work(h, &wk, blob, request, type, op,
				      localStore);

		if (ret != EVP_OK) {
			goto locked;
		} else if (type == EVP_BLOB_TYPE_EVP_EXT ||
			   type == EVP_BLOB_TYPE_EVP) {
			/* EVP_BLOB_TYPE_EVP_EXT needs extra steps */
			xlog_debug(
				"Enqueuing an EVP_BLOB_TYPE_EVP_EXT request "
				"for RPCs");
			TAILQ_INSERT_TAIL(&g_sdk_blob_rpcs, wk, rpcq);
			main_loop_wakeup("BLOB-RPC");
		} else {
			blob_work_enqueue(wk);
		}
		TAILQ_INSERT_TAIL(&h->blob_ops, &blob->event, q);

		blob->work = wk;
		blob->owner = h;
	}

	ret = EVP_OK;
locked:
	sdk_unlock();
unlocked:
	if (ret != EVP_OK) {
		free(blob);
		free(wk);
	}
	return ret;
}

__CTASSERT((enum blob_work_result)EVP_BLOB_RESULT_SUCCESS ==
	   BLOB_RESULT_SUCCESS);
__CTASSERT((enum blob_work_result)EVP_BLOB_RESULT_ERROR == BLOB_RESULT_ERROR);
__CTASSERT((enum blob_work_result)EVP_BLOB_RESULT_ERROR_HTTP ==
	   BLOB_RESULT_ERROR_HTTP);

EVP_RESULT
EVP_impl_sendMessage(struct EVP_client *h, const void *rawbuf,
		     const char *topic, const void *blob, size_t bloblen,
		     EVP_MESSAGE_SENT_CALLBACK cb, void *userData)
{
	bool needs_main_wakeup = false;
	sdk_assert_unlocked();

	struct sdk_event_message_sent *event_message =
		malloc(sizeof(*event_message));
	if (event_message == NULL) {
		return convert_oserrno_to_evp(errno);
	}
	*event_message = (struct sdk_event_message_sent){
		.event =
			{
				.type = SDK_EVENT_MESSAGE_SENT,
				.buffer = rawbuf,
			},
		.topic = topic,
		.blob = blob,
		.bloblen = bloblen,
		.cb = cb,
		.cb_userdata = userData,
	};

	sdk_lock();
	if (h->exiting) {
		/* Don't accept new messages while exiting */
		event_message->reason = EVP_MESSAGE_SENT_CALLBACK_REASON_EXIT;
		TAILQ_INSERT_TAIL(&h->events, &event_message->event, q);
		sdk_wakeup_handle(h);
	} else {
		TAILQ_INSERT_TAIL(&h->outbox_messages, &event_message->event,
				  q);
		needs_main_wakeup = true;
	}
	sdk_unlock();
	if (needs_main_wakeup) {
		main_loop_wakeup("MESSAGE");
	}
	return EVP_OK;
}

EVP_RESULT
EVP_impl_sendTelemetry(struct EVP_client *h, const void *rawbuf,
		       void *extra_alloc,
		       const struct EVP_telemetry_entry *entries,
		       size_t nentries, EVP_TELEMETRY_CALLBACK cb,
		       void *userData)
{
	bool needs_main_wakeup = false;
	sdk_assert_unlocked();
	int total_size = 0;

	/* Add json extra chars
	 * The worst case for telemetry is something like
	 * {"<module_instance_name>/<telemetry_key>":
	 * "<telemetry_value>",}
	 */
	for (size_t i = 0; i < nentries; i++) {
		total_size += strlen(entries[i].key);
		total_size += strlen(entries[i].value);
	}

	total_size += nentries * strlen(h->name);
	total_size += nentries * strlen("\"/\": \"\",");
	/* Take into account the main Json brackets */
	total_size += strlen("{}");

	if (g_mqtt_client == NULL) {
		return EVP_ERROR;
	}

	if (!xmqtt_request_fits(g_mqtt_client, total_size)) {
		return EVP_TOOBIG;
	}

	struct sdk_event_telemetry *t = malloc(sizeof(*t));
	if (t == NULL) {
		return convert_oserrno_to_evp(errno);
	}

	*t = (struct sdk_event_telemetry){
		.event =
			{
				.type = SDK_EVENT_TELEMETRY,
				.buffer = rawbuf,
				.extra_alloc = extra_alloc,
			},
		.entries = entries,
		.nentries = nentries,
		.cb = cb,
		.cb_userdata = userData,
	};

	sdk_lock();
	if (h->exiting) {
		t->reason = EVP_TELEMETRY_CALLBACK_REASON_EXIT;
		TAILQ_INSERT_TAIL(&h->events, &t->event, q);
		sdk_wakeup_handle(h);
	} else {
		TAILQ_INSERT_TAIL(&h->telemetry_list, &t->event, q);
		needs_main_wakeup = true;
	}
	sdk_unlock();
	if (needs_main_wakeup) {
		main_loop_wakeup("TELEMETRY");
	}
	return EVP_OK;
}

static size_t
get_mdc_response_buf_size(struct EVP_client *h, const void *rawbuf,
			  EVP_RPC_ID id, const char *response,
			  EVP_RPC_RESPONSE_STATUS status)
{
	/*
	 * FIXME: expected buffer size calculated below is currently done via
	 * heuristics. This should be replaced by more exact methods (e.g.:
	 * asking the serialization library itself) or even with a protocol
	 * that, as opposed to MQTT, does not limit maximum packet size e.g.:
	 * HTTP.
	 *
	 * The following payloads are considered:
	 *
	 * - EVP1:
	 *
	 * {
	 *   "moduleInstance": <module instance name>,
	 *   "response": <a JSON value>
	 * }
	 *
	 * - EVP2:
	 *
	 * {
	 * 	"direct-command-response": {
	 * 		"response": "a string value",
	 * 		"status" : "ok",
	 * 		"reqid": 12435
	 * 	}
	 * }
	 * EVP2 is then considered the worst possible case for the buffer size
	 * calculation below.
	 */
	size_t ret = strlen("{}");
	ret += strlen("\"direct-command-response\": {}");
	ret += strlen("\"status\": \"ok\", ");
	/* As of the time of this writing, EVP_RPC_ID is defined as a
	 * 64-bit unsigned integer. */
	ret += strlen("\"reqid\": 18446744073709551615, ");
	if (response != NULL) {
		ret += strlen(response);
		ret += strlen("\"response\": \"\", ");
	}
	return ret;
}

EVP_RESULT
EVP_impl_sendRpcResponse(struct EVP_client *h, const void *rawbuf,
			 EVP_RPC_ID id, const char *response,
			 EVP_RPC_RESPONSE_STATUS status,
			 EVP_RPC_RESPONSE_CALLBACK cb, void *userData)
{
	bool needs_main_wakeup = false;

	if (response == NULL) {
		xlog_error("EVP_sendRpcResponse invoked with NULL response "
			   "data. Returning EVP_EINVAL.");
		return EVP_INVAL;
	}

	size_t outsz =
		get_mdc_response_buf_size(h, rawbuf, id, response, status);

	if (g_mqtt_client == NULL) {
		return EVP_ERROR;
	}

	sdk_assert_unlocked();
	if (!xmqtt_request_fits(g_mqtt_client, outsz)) {
		return EVP_TOOBIG;
	}

	struct sdk_event_rpc_response *r = malloc(sizeof(*r));
	if (r == NULL) {
		return EVP_NOMEM;
	}
	*r = (struct sdk_event_rpc_response){
		.event =
			{
				.type = SDK_EVENT_RPC_RESPONSE,
				.buffer = rawbuf,
			},
		.id = id,
		.response = response,
		.status = status,
		.cb = cb,
		.cb_userdata = userData,
	};
	sdk_lock();
	if (h->exiting) {
		r->reason = EVP_RPC_RESPONSE_CALLBACK_REASON_EXIT;
		TAILQ_INSERT_TAIL(&h->events, &r->event, q);
		sdk_wakeup_handle(h);
	} else {
		TAILQ_INSERT_TAIL(&h->rpc_responses, &r->event, q);
		needs_main_wakeup = true;
	}
	sdk_unlock();
	if (needs_main_wakeup) {
		main_loop_wakeup("RPC-RESPONSE");
	}
	return EVP_OK;
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

EVP_RESULT
stream_get_params(struct EVP_client *h, const char *name,
		  const struct Stream **out)
{
	const struct module_instance *m = get_module_instance_by_name(h->name);
	if (m == NULL) {
		return EVP_ERROR;
	}

	const struct Stream *stream =
		module_instance_stream_from_name(m, name);
	if (stream == NULL) {
		return EVP_INVAL;
	}

	*out = stream;
	return EVP_OK;
}

EVP_RESULT
stream_insert(struct EVP_client *h, struct stream_impl *si)
{
	return stream_impl_insert(&h->streams, si);
}

EVP_RESULT
stream_remove(struct EVP_client *h, struct stream_impl *si)
{
	return stream_impl_remove(&h->streams, si);
}

int
stream_insert_read_event(struct EVP_client *h,
			 struct sdk_event_stream_read_available *ev)
{
	int error = pthread_mutex_lock(&h->mutex);

	if (error) {
		fprintf(stderr, "%s: pthread_mutex_lock failed with %d\n",
			__func__, error);
		return -1;
	}

	TAILQ_INSERT_TAIL(&h->events, &ev->event, q);
	sdk_lock();
	sdk_wakeup_handle(h);
	sdk_unlock();

	if (pthread_mutex_unlock(&h->mutex)) {
		fprintf(stderr, "%s: pthread_mutex_lock unfailed with %d\n",
			__func__, error);
		return -1;
	}

	return 0;
}

#if defined(CONFIG_EVP_BLOB_GET_UPLOAD_URL)
EVP_RESULT
EVP_blobGetUploadURL(struct EVP_client *h, const char *storageName,
		     const char *remoteName, EVP_BLOB_CALLBACK cb,
		     void *userData)
{

	sdk_assert_unlocked();

	struct sdk_event_blob *blob = xmalloc(sizeof(*blob));

	*blob = (struct sdk_event_blob){
		.event.type = SDK_EVENT_BLOB_GET_UPLOAD_URL,
		.user_cb.cb = cb,
		.user_cb.cb_data = userData,
	};

	sdk_lock();
	struct blob_work *wk = blob_work_alloc();

	wk->type = BLOB_TYPE_EVP_EXT;
	wk->op = BLOB_OP_GET_BLOB_URL;
	if (storageName != NULL) {
		wk->storage_name = xstrdup(storageName);
	} else {
		/*
		 * The defaut EVP storage will be used when
		 * storage_name is NULL.
		 */
		wk->storage_name = NULL;
	}
	wk->remote_name = xstrdup(remoteName);
	wk->module_instance_name = xstrdup(h->name);
	wk->blob_len = 0;
	wk->wk.done = sdk_blob_done;
	wk->user = blob;
	blob->work = wk;
	blob->owner = h;
	blob_work_set_proxy(wk);
	xlog_debug("Enqueuing an EVP_BLOB_TYPE_EVP_EXT request "
		   "for RPCs");
	TAILQ_INSERT_TAIL(&g_sdk_blob_rpcs, wk, rpcq);
	main_loop_wakeup("BLOB-RPC");

	TAILQ_INSERT_TAIL(&h->blob_ops, &blob->event, q);

	sdk_unlock();

	return EVP_OK;
}
#else
EVP_RESULT
EVP_blobGetUploadURL(struct EVP_client *h, const char *storageName,
		     const char *remoteName, EVP_BLOB_CALLBACK cb,
		     void *userData)
{
	return EVP_NOTSUP;
}
#endif /*defined(CONFIG_EVP_BLOB_GET_UPLOAD_URL)*/

struct EVP_client *
sdk_handle_from_name(const char *name) EVP_REQUIRES(g_sdk_lock)
{
	struct EVP_client *h;

	sdk_assert_locked();
	TAILQ_FOREACH (h, &g_handles, q) {
		if (!strcmp(h->name, name)) {
			return h;
		}
	}
	return NULL;
}
