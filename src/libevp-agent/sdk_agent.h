/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if !defined(__SDK_AGENT_H__)
#define __SDK_AGENT_H__

#include "event.h"

/*
 * The Agent-side API
 */

void sdk_init(void);
void sdk_queue_config(const char *name, const char *topic, const void *blob,
		      size_t bloblen);
void sdk_queue_message(const char *module_instance_name,
		       const char *subscribe_alias, const void *blob,
		       size_t bloblen);
void sdk_queue_rpc_request(const char *name, EVP_RPC_ID id, const char *method,
			   const char *params);
bool sdk_forward_local_to_publish_topic(struct sdk_event_message_sent *msg,
					const char *publish_topic_name);
bool sdk_check_resend_request(void);
void sdk_collect_states(void (*)(const char *, const char *, const void *,
				 size_t, void *),
			void *);
void sdk_complete_collected_states(EVP_STATE_CALLBACK_REASON reason);
struct EVP_telemetry_entry;
void sdk_collect_telemetry(int (*)(const char *,
				   const struct EVP_telemetry_entry *, size_t,
				   void *),
			   void *user);
void sdk_telemetry_set_reason(struct sdk_event_telemetry *t,
			      EVP_TELEMETRY_CALLBACK_REASON reason);
void sdk_collect_rpc_responses(int (*cb)(const char *, EVP_RPC_ID,
					 const char *, EVP_RPC_RESPONSE_STATUS,
					 void *),
			       void *user);
struct blob_work *sdk_dequeue_blob_rpc(void);
void sdk_handoff_blob_rpc(struct blob_work *wk);

struct mqtt_client;
void sdk_process_outbox_messages(void);
void sdk_clear_events(struct EVP_client *h);
void sdk_signal_exit(struct EVP_client *);
void sdk_cleanup(struct EVP_client *);

#if defined(__NuttX__)
#include <unistd.h> /* pid_t */
void sdk_handle_setpid(struct EVP_client *h, pid_t pid);
#endif
void sdk_handle_init(struct EVP_client *h, const char *name);
void sdk_handle_rename(struct EVP_client *h, const char *name);
void sdk_handle_insert(struct EVP_client *h);
void sdk_handle_remove(struct EVP_client *h);
void sdk_handle_destroy(struct EVP_client *h);
struct EVP_client *sdk_handle_alloc(void);
void sdk_handle_free(struct EVP_client *h);
struct EVP_client *sdk_handle_from_name(const char *name);

void sdk_assert_unlocked(void);

struct sdk_request;
struct sdk_response;
int sdk_process_request(const void *, size_t, struct sdk_response **respp,
			void *);
void *sdk_build_simple_response(size_t *sizep, EVP_RESULT result);

#endif /* !defined(__SDK_AGENT_H__) */
