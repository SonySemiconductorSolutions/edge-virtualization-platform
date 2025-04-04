/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * This file aims to contain things which logically belong to
 * MQTT-C library itself.
 * That is, some logic to deal with internal details of the library.
 * Probably it makes sense to generalize these and contribute
 * to MQTT-C.
 * Thus, it's discouraged to make this tightly coupled with the rest
 * of the agent.
 */

#define MQTT_LOG_VERBOSE

#if defined(MQTT_LOG_VERBOSE)
#include <stdio.h>
#endif /* defined(MQTT_LOG_VERBOSE) */

#include <internal/util.h>

#include "main_loop.h"
#include "timeutil.h"
#include "xlog.h"
#include "xmqtt.h"

static void
mqtt_dump(struct mqtt_client *m)
{
#if defined(MQTT_LOG_VERBOSE)
	printf("error = %d (%s)\n", m->error, mqtt_error_str(m->error));
	long len = mqtt_mq_length(&m->mq);
	printf("mqtt_mq_length = %ld\n", len);
	printf("send_offset = %zu\n", m->send_offset);
	long i;
	for (i = 0; i < len; i++) {
		struct mqtt_queued_message *msg = mqtt_mq_get(&m->mq, i);
		printf("msg[%ld] state = %d\n", i, (int)msg->state);
		printf("msg[%ld] control_type = %d\n", i,
		       (int)msg->control_type);
		printf("msg[%ld] start = %p\n", i, msg->start);
		printf("msg[%ld] size = %zu\n", i, msg->size);
		printf("msg[%ld] packet_id = %d\n", i, (int)msg->packet_id);
		printf("msg[%ld] time_sent = %d\n", i, (int)msg->time_sent);
	}
#endif /* defined(MQTT_LOG_VERBOSE) */
}

#define MQTT_RETRY_INTERVAL_SEC 1

/*
 * Check the send queue and returns:
 *
 * - if something needs to be sent (mqtt_pal_sendall) right now
 *   via want_writep
 *
 * - otherwise, the next timeout, ie. when mqtt_sync() should be called,
 *   via the function return value.
 *
 * XXX this needs to be in sync with __mqtt_send() in the MQTT-C library.
 */
static mqtt_pal_time_t
mqtt_send_check(struct mqtt_client *client, bool *want_writep)
{
	if (client->keep_alive == 0) {
		return (mqtt_pal_time_t)-1;
	}

	mqtt_pal_time_t now = MQTT_PAL_TIME();
	mqtt_pal_time_t keep_alive_timeout =
		client->time_of_last_send +
		(mqtt_pal_time_t)client->keep_alive;
	mqtt_pal_time_t next_timeout = keep_alive_timeout;
	if (client->error != MQTT_OK) {
		xlog_error("%s: MQTT-C error: %s", __func__,
			   mqtt_error_str(client->error));
		mqtt_dump(client);
		return now + MQTT_RETRY_INTERVAL_SEC;
	}
	ssize_t len;
	int i;
	len = mqtt_mq_length(&client->mq);
	for (i = 0; i < len; ++i) {
		const struct mqtt_queued_message *msg =
			mqtt_mq_get(&client->mq, i);
		if (msg->state == MQTT_QUEUED_UNSENT) {
			*want_writep = true;
		} else if (msg->state == MQTT_QUEUED_AWAITING_ACK) {
			mqtt_pal_time_t msg_timeout =
				msg->time_sent + client->response_timeout;
			if (msg_timeout < now) {
				*want_writep = true;
			} else if (msg_timeout < next_timeout) {
				next_timeout = msg_timeout;
			}
		}
	}
	/*
	 * + 1 because we need to return the first MQTT_PAL_TIME() value
	 * which satisfies "MQTT_PAL_TIME() > next_timeout".
	 */
	return next_timeout + 1;
}

void
mqtt_prepare_poll(struct mqtt_client *client, bool *want_writep)
{
	bool want_write = false;
	if (client->error == MQTT_ERROR_SEND_BUFFER_IS_FULL) {
		/*
		 * Make want_write true to indicate we that want mqtt_sync()
		 * to be called whenever the underlying socket has a space.
		 */
		want_write = true;
	} else {
		time_t abs_timeout_sec = mqtt_send_check(client, &want_write);

		if (abs_timeout_sec != (time_t)-1) {
			/*
			 * Note: abs_timeout_sec is based on
			 * MQTT_PAL_TIME. We convert it to the value
			 * based on CLOCK_MONOTONIC here.
			 */
			const time_t now_sec = MQTT_PAL_TIME();
			const uint64_t now_ms = gettime_ms();
			uint64_t abs_timeout_ms;
			xlog_trace("%s: abs_timeout_sec=%ju, "
				   "now_sec=%ju\n",
				   __func__, (uintmax_t)abs_timeout_sec,
				   (uintmax_t)now_sec);
			if (abs_timeout_sec >= now_sec) {
				uint64_t delta_sec = abs_timeout_sec - now_sec;
				abs_timeout_ms = now_ms + delta_sec * 1000;
			} else {
				abs_timeout_ms = now_ms;
			}
			main_loop_add_abs_timeout_ms("MQTT", abs_timeout_ms);
		}
	}
	*want_writep = want_write;
}

bool
xmqtt_request_fits(struct mqtt_client *client, size_t len)
{
	bool ret = false;
	struct mqtt_message_queue *mq = &client->mq;

	MQTT_PAL_MUTEX_LOCK(&client->mutex);

	if (len > mq->curr_sz) {
		if (mq->queue_tail == NULL) {
			goto end;
		}

		/* Despite the name, this function does not clean the message
		 * queue. Instead, it removes acknowledged messages from the
		 * queue, so that mq->curr_sz reflects the actual number of
		 * available bytes inside the outgoing buffer. */
		mqtt_mq_clean(mq);

		if (len > mq->curr_sz) {
			goto end;
		}
	}

	ret = true;

end:
	MQTT_PAL_MUTEX_UNLOCK(&client->mutex);
	return ret;
}
