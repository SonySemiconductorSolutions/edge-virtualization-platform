/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <parson.h>

#include <internal/evp_config.h>
#include <internal/util.h>

#include "cdefs.h"
#include "main_loop.h"
#include "req.h"
#include "timeutil.h"
#include "xlog.h"

#define REQ_DEFAULT_TIMEOUT (20 * 1000)
#define REQ_RETRY_INTERVAL  (5 * 1000)
#define REQ_DEFAULT_QOS     0

static struct req_queue {
	TAILQ_HEAD(, request) queue;
	const char *name;
	size_t accum;
} queues[] = {
	[REQ_PRIORITY_MFS] = {.name = "REQ_PRIORITY_MFS",
			      .queue = TAILQ_HEAD_INITIALIZER(
				      queues[REQ_PRIORITY_MFS].queue)},
	[REQ_PRIORITY_LOW] = {.name = "REQ_PRIORITY_LOW",
			      .queue = TAILQ_HEAD_INITIALIZER(
				      queues[REQ_PRIORITY_LOW].queue)},
};

static size_t
get_request_size(const struct request *req)
{
	char *topic;
	size_t ret;
	xasprintf(&topic, req->topic_template, (uintmax_t)req->id);
	ret = strlen(req->payload) + strlen(topic);
	free(topic);
	return ret;
}

EVP_RPC_ID
request_id_alloc(void)
{
	static EVP_RPC_ID request_id = 10001;
	EVP_RPC_ID result = request_id;
	request_id++;
	/*
	 * Don't use too large values.
	 * Also, avoid using 0 just in case.
	 *
	 * Note: TB request IDs are Java "int".
	 * https://github.com/thingsboard/thingsboard/blob/e7c1901346615fb01c2a7e6f94fae7ebeb173577/application/src/main/java/org/thingsboard/server/actors/device/DeviceActorMessageProcessor.java#L132-L133
	 */
	if (request_id > 2147483647) {
		request_id = 1;
	}
	return result;
}

struct request *
request_alloc(void)
{
	struct request *req = xmalloc(sizeof(*req));

	req->id = request_id_alloc();
	req->callback = NULL;
	req->callback_data = NULL;
	req->payload = "";
	req->payload_free = NULL;
	req->payload_free_arg = NULL;
	req->when_ms = 0;
	req->created_ms = gettime_ms();
	req->timeout_ms = REQ_DEFAULT_TIMEOUT;
	req->resend = false;
	req->qos = REQ_DEFAULT_QOS;
	req->priority = REQ_PRIORITY_DEFAULT;
	return req;
}

void
request_free_json_payload(struct request *req, void *userData)
{
	json_free_serialized_string((void *)req->payload);
}

void
request_free_text_payload(struct request *req, void *userData)
{
	free(__UNCONST(req->payload));
}

void
request_free(struct request *req)
{
	if (req->payload_free) {
		req->payload_free(req, req->payload_free_arg);
	}
	free(req);
}

static int
getmax(const struct request *req, size_t *max)
{
	intmax_t tmpmax;
	if (config_get_int(EVP_CONFIG_TRANSPORT_QUEUE_LIMIT, &tmpmax)) {
		xlog_error("failed to read EVP_CONFIG_TRANSPORT_QUEUE_LIMIT");
		return ENOENT;
	} else if (tmpmax <= 0 || (uintmax_t)tmpmax > SIZE_MAX) {
		xlog_error("invalid value for "
			   "EVP_CONFIG_TRANSPORT_QUEUE_LIMIT: %jd",
			   tmpmax);
		return EINVAL;
	}
	*max = tmpmax;
	return 0;
}

int
request_insert(struct request *req)
{
	/* If callback is not NULL, resend or timeout_ms != 0 has to be set.
	 * This is by design: If a callback is set it is because you expect an
	 * answer. */
	// TODO: Replace assert (programming error)
	assert(req->callback == NULL || req->resend || req->timeout_ms != 0);
	// TODO: Replace assert (programming error)
	assert(req->payload != NULL);
	// TODO: Replace assert (programming error)
	assert(req->topic_template != NULL);
	// TODO: Replace assert (programming error)
	assert(req->priority >= 0 && req->priority < __arraycount(queues));
	size_t max;
	struct req_queue *reqq = &queues[req->priority];
	int res = getmax(req, &max);
	if (res == ENOENT)
		;
	else if (res) {
		return res;
	} else {
		const size_t sz = get_request_size(req);
		if (reqq->accum + sz > max) {
			xlog_warning(
				"request exceeds maximum queue size for %s: "
				"requested=%zu, total_payload_size=%zu, "
				"max=%zu",
				reqq->name, sz, reqq->accum, max);
			return ENOMEM;
		}
		reqq->accum += sz;
	}
	TAILQ_INSERT_TAIL(&reqq->queue, req, q);
	return 0;
}

void
request_unlink(struct request *req)
{
	struct req_queue *reqq = &queues[req->priority];
	size_t max;
	int res = getmax(req, &max);
	if (res == ENOENT)
		;
	else if (res)
		xlog_error("getmax failed");
	else {
		const size_t sz = get_request_size(req);
		if (reqq->accum < sz) {
			xlog_warning("total requested size (%zu) smaller than "
				     "requested "
				     "size (%zu) for queue %s",
				     reqq->accum, sz, reqq->name);
			reqq->accum = 0;
		} else {
			size_t newaccum = reqq->accum - sz;
			if (reqq->accum == max) {
				xlog_warning("queue %s no longer full, "
					     "before=%zu, now=%zu",
					     reqq->name, max, newaccum);
			}
			reqq->accum = newaccum;
			xlog_trace("queue %s: total_payload_size bytes=%zu, "
				   "requested "
				   "size=%zu",
				   reqq->name, reqq->accum, sz);
		}
	}
	TAILQ_REMOVE(&reqq->queue, req, q);
}

struct request *
request_remove(EVP_RPC_ID id)
{
	for (size_t i = 0; i < __arraycount(queues); i++) {
		struct req_queue *reqq = &queues[i];
		struct request *req;

		TAILQ_FOREACH (req, &reqq->queue, q) {
			if ((req->callback != NULL) && req->id == id) {
				request_unlink(req);
				return req;
			}
		}
	}
	return NULL;
}

void
request_handle_response(struct evp_agent_context *agent, EVP_RPC_ID id,
			void *payload)
{
	uint64_t now_ms = gettime_ms();
	struct request *req = request_remove(id);
	if (req == NULL) {
		/*
		 * This usually means we resend a request and
		 * got responses for each of resent requests.
		 */
		xlog_warning("Ignoring unknown request id %ju", (uintmax_t)id);
	} else {
		uint32_t delay = now_ms - req->when_ms;
		// To dicuss: Exposing the counter id it is a clue to
		// impersonate the request/response
		xlog_debug("got request id %ju in %" PRIu32 " ms",
			   (uintmax_t)id, delay);
		if (req->callback) {
			req->callback(req->id, req->callback_data, payload,
				      delay, 0);
		}
		request_free(req);
	}
}

static int
request_send(struct transport_ctxt *t, struct request *req)
{
	char *topic;
	int rc;

	xasprintf(&topic, req->topic_template, (uintmax_t)req->id);

	size_t payloadlen = strlen(req->payload);
	rc = transport_send(t, topic, req->payload, payloadlen, req->qos);
	xlog_debug("%s req.id=%ju topic=%s, payload=%s, qos=%d, rc=%d",
		   (req->when_ms == 0) ? "SEND" : "RESEND", req->id, topic,
		   req->payload, req->qos, (int)rc);
	free(topic);
	if (rc != 0) {
		xlog_warning("transport_send failed with %d", rc);
		return EAGAIN;
	}
	return 0;
}

/* Check that an already sent request should be resent */
static bool
request_should_resend(struct request *req, uint64_t now_ms, uint32_t retry_ms)
{
	// TODO: Replace assert (programming error)
	assert(req->when_ms != 0);
	return req->resend && (now_ms - req->when_ms > retry_ms);
}

int
clean_expired_requests(struct evp_agent_context *agent)
{
	for (size_t i = 0; i < __arraycount(queues); i++) {
		struct req_queue *reqq = &queues[i];
		struct request *req;
		struct request *next;
		uint64_t now_ms = gettime_ms();
		const uint32_t retry_ms = REQ_RETRY_INTERVAL;

		TAILQ_FOREACH_SAFE (req, &reqq->queue, q, next) {
			/* If timeout has expired, notify callback then delete
			 * it */
			if (req->timeout_ms != 0) {
				uint32_t delay_ms =
					(uint32_t)(now_ms - req->created_ms);
				if (delay_ms >= req->timeout_ms) {
					xlog_debug("Timeout of req.id %ju, "
						   "timeout %" PRIu32 ", "
						   "delayed %" PRIu32,
						   (uintmax_t)req->id,
						   req->timeout_ms, delay_ms);
					if (req->callback != NULL) {
						req->callback(
							req->id,
							req->callback_data,
							NULL, delay_ms,
							ETIMEDOUT);
					}
					request_unlink(req);
					request_free(req);
					continue;
				}
			}

			/* Propose next wake-up time */
			if (req->when_ms != 0) {
				uint32_t delay_ms = (req->timeout_ms != 0)
							    ? req->timeout_ms
							    : retry_ms;
				main_loop_add_abs_timeout_ms(
					"REQ", req->when_ms + delay_ms + 1);
			}
		}
	}
	return 0;
}

static int
process_request(struct transport_ctxt *t, struct request *req, uint64_t now_ms,
		uint32_t retry_ms)
{
	if (req->when_ms != 0 &&
	    !request_should_resend(req, now_ms, retry_ms)) {
		return 0;
	}
	// XXX should renew req->id when resending?
	int error = request_send(t, req);
	if (error != 0) {
		/*
		 * NOTE: the error here came from mqtt_publish. (Typically
		 * MQTT_ERROR_SEND_BUFFER_IS_FULL or MQTT_ERROR_SOCKET_ERROR)
		 * In that case, no try to send the rest of requests because we
		 * can't transmit anything until the mqtt error is cleared
		 * anyway. We still need to check the rest of the requests on
		 * reqq for timeout expiration.
		 */
		return error;
	}

	/*
	 * We successfully handed the request to the
	 * MQTT layer. If it doesn't need any further
	 * processing, free it.
	 */
	if (req->callback == NULL) {
		request_unlink(req);
		request_free(req);
		return 0;
	}

	req->when_ms = now_ms;
	return 0;
}

int
resend_requests(struct transport_ctxt *t)
{
	for (size_t i = 0; i < __arraycount(queues); i++) {
		struct req_queue *reqq = &queues[i];
		struct request *req;
		struct request *next;
		uint64_t now_ms = gettime_ms();
		const uint32_t retry_ms = REQ_RETRY_INTERVAL;

		TAILQ_FOREACH_SAFE (req, &reqq->queue, q, next) {
			int ret = process_request(t, req, now_ms, retry_ms);
			if (ret) {
				return ret;
			}
		}
	}
	return 0;
}
