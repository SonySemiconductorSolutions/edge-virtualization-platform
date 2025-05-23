/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef REQ_H
#define REQ_H

#include <stdbool.h>
#include <time.h>

#include <evp/sdk_types.h>

#include <internal/evp_config.h>
#include <internal/queue.h>

#include "transport.h"

EVP_RPC_ID request_id_alloc(void);

struct request {
	TAILQ_ENTRY(request) q;
	EVP_RPC_ID id;

	/*
	 * Note: If callback == NULL, the request is fire-and-forget.
	 * Otherwise, resend or timeout_ms != 0 has to be set and
	 * the callback is called exactly once, when:
	 * - It got a response from the hub,
	 * - Or, it failed for some reasons. (usually a timeout)
	 *
	 * id           The id used to match request and response
	 *              (usually used only for diagnostic purposes)
	 * cb_data      req->callback_data
	 * payload      data received in mqtt response
	 * delay        time (ms) to get the response
	 *              (usually used only for diagnostic purposes)
	 * error        an errno. typically 0 (success) or ETIMEDOUT.
	 */
	void (*callback)(EVP_RPC_ID id, void *cb_data, void *payload,
			 uint32_t delay, int error);
	void *callback_data;        /* cb_data for the above callback */
	const char *topic_template; /* It cannot be NULL */
	const char *payload;        /* It cannot be NULL */
	void (*payload_free)(struct request *, void *);
	void *payload_free_arg; /* the user pointer for payload_free */
	uint64_t when_ms;       /* timestamp when request was sent */
	uint64_t created_ms;    /* timestamp when request was created */

	/*
	 * If callback != NULL and timeout_ms != 0,
	 * the request times out after timeout_ms period.
	 */
	uint32_t timeout_ms;

	/*
	 * If callback != NULL and resend == true, keep resending the request
	 * until it gets a response or the request timed out.
	 * The resend interval is currently hardcoded in req.c. (5000 ms)
	 */
	bool resend;

	/*
	 * QOS value [0-2]
	 */
	int qos;

	/*
	 * A lower value means higher priority.
	 */
	enum req_priority {
		REQ_PRIORITY_MFS,
		REQ_PRIORITY_LOW,
		REQ_PRIORITY_DEFAULT = REQ_PRIORITY_LOW
	} priority;
};

struct request *request_alloc(void);
void request_free(struct request *);
int request_insert(struct request *);
void request_unlink(struct request *);
void request_free_json_payload(struct request *, void *);
void request_free_text_payload(struct request *, void *);

/*
 * Remove queue from queue. It checks if request is waiting a response
 * This function is used for the request/reply matching.
 */
struct request *request_remove(EVP_RPC_ID);
void request_handle_response(struct evp_agent_context *agent, EVP_RPC_ID id,
			     void *payload);

struct mqtt_client;

/*
 * (re)send request added in queue.
 * Requests with no_reply=false will retried every 5s or until deleted with
 * request_remove.
 * For the request-response pattern, it is necessary to specify
 * callback method. And timeout parameter is used (ignored if no_reply=false)
 *
 * @param mqtt_client 	the mqtt client to use
 * @return 0 if success, otherwise the specific errno
 */
int resend_requests(struct transport_ctxt *);

/*
 * Update message queue based on timeouts
 */
int clean_expired_requests(struct evp_agent_context *agent);

#endif
