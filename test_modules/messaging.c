/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE /* asprintf */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "evp/sdk.h"
#include "log.h"

static unsigned int nmessages = 1000;

static char *g_salute;
static char *g_publish_to;
static char *g_subscribe_to;

static int g_step;

static const char *module_name = "MESSAGING";

struct send_message_cb_data {
	char *topic;
	char *payload;
};

struct state_cb_data {
	char *blob;
};

static void
config_cb(const char *topic, const void *config, size_t configlen,
	  void *userData)
{
	log_module(module_name,
		   "Received Configuration (topic=%s, size=%zu)\n", topic,
		   configlen);

	char **varp;

	if (!strcmp(topic, "salute")) {
		varp = &g_salute;
	} else if (!strcmp(topic, "publish_to")) {
		varp = &g_publish_to;
	} else if (!strcmp(topic, "subscribe_to")) {
		varp = &g_subscribe_to;
	} else {
		log_module(module_name,
			   "Ignoring Configuration with unknown topic "
			   "(topic=%s, size=%zu)\n",
			   topic, configlen);
		return;
	}

	free(*varp);
	*varp = malloc(configlen + 1);
	assert(*varp != NULL);
	memcpy(*varp, config, configlen);
	(*varp)[configlen] = 0;
}

static void
state_cb(EVP_STATE_CALLBACK_REASON reason, void *userData)
{
	assert(userData != NULL);
	struct state_cb_data *d = userData;
	assert(d->blob != NULL);
	free(d->blob);
	free(d);
}

static void
message_cb(const char *topic, const void *msgPayload, size_t msgPayloadLen,
	   void *userData)
{
	static int received_msg;
	log_module(module_name, "Received message number %d\n", received_msg);
	received_msg++;

	assert(topic != NULL);

	assert(!strcmp((const char *)topic, g_subscribe_to));
	assert(!strcmp((const char *)userData, "xyz"));

	char *msgStr = malloc(msgPayloadLen + 1);
	assert(msgStr != NULL);
	memcpy(msgStr, msgPayload, msgPayloadLen);
	msgStr[msgPayloadLen] = 0;

	assert(!strcmp((const char *)msgStr, g_salute));

	assert(g_step >= 10000);
	assert(g_step < 10000 + nmessages);
	g_step++;
	if (g_step == 10000 + nmessages) {
		g_step = 2;
	}
}

static void
send_message_cb(EVP_MESSAGE_SENT_CALLBACK_REASON reason, void *userData)
{
	static int send_msg;
	log_module(module_name, "Sent message number %d DONE. reason %d\n",
		   send_msg, reason);
	assert(reason == EVP_MESSAGE_SENT_CALLBACK_REASON_SENT);
	send_msg++;

	struct send_message_cb_data *d = userData;
	assert(d != NULL);
	assert(d->topic != NULL);
	assert(d->payload != NULL);
	free(d->topic);
	free(d->payload);
	free(d);

	assert(g_step >= 10000);
	assert(g_step < 10000 + nmessages);
	g_step++;
	if (g_step == 10000 + nmessages) {
		g_step = 3;
	}
}

int
main(void)
{
	g_salute = NULL;
	g_publish_to = NULL;
	g_subscribe_to = NULL;
	g_step = 0;
	int reported_step = -1;
	EVP_RESULT result;

	struct EVP_client *h = EVP_initialize();
	result = EVP_setConfigurationCallback(h, config_cb, (void *)0x1234);
	assert(result == EVP_OK);

	/*
	 * g_step = 0: wait for Configuration with:
	 *              - "publish_to" topic
	 *             or
	 *              - "subscribe_to" topic
	 *             also, wait for a Configuration with "salute" topic
	 * g_step = 10000: message sent or subscribed
	 * g_step = >10000: waiting for callback
	 * g_step = 2: all message received
	 * g_step = 3: EVP_sendMessage callback was called for all messages
	 * g_step = 999: error
	 * g_step = 1000: success
	 */

	unsigned int sender_msg_sent = 0;
	for (;;) {
		result = EVP_processEvent(h, 1000);
		if (result == EVP_SHOULDEXIT) {
			free(g_salute);
			free(g_publish_to);
			free(g_subscribe_to);
			break;
		}
		if (g_salute != NULL && g_publish_to != NULL && g_step == 0) {
			g_step = 10000;
		}

		if (g_salute != NULL && g_publish_to != NULL &&
		    g_step >= 10000 && sender_msg_sent < nmessages) {
			sender_msg_sent++;
			struct send_message_cb_data *d = malloc(sizeof(*d));
			assert(d != NULL);
			d->topic = strdup(g_publish_to);
			assert(d->topic != NULL);
			d->payload = strdup(g_salute);
			assert(d->payload != NULL);
			result = EVP_sendMessage(h, d->topic, d->payload,
						 strlen(d->payload),
						 send_message_cb, d);
			log_module(module_name,
				   "EVP_sendMessage message %d. Result is "
				   "%d \n",
				   sender_msg_sent, result);
			assert(result == EVP_OK);
		}
		if (g_salute != NULL && g_subscribe_to != NULL &&
		    g_step == 0) {
			result = EVP_setMessageCallback(h, message_cb, "xyz");
			assert(result == EVP_OK);
			g_step = 10000;
		}
		if (g_step == 2) {
			log_module(module_name, "RECEIVER SUCCESS!\n");
			g_step = 1000;
		}
		if (g_step == 3) {
			log_module(module_name, "SENDER SUCCESS!\n");
			g_step = 1000;
		}
		if (reported_step != g_step) {
			const char *topic = "status";
			struct state_cb_data *d = malloc(sizeof(*d));
			assert(d != NULL);
			int ret = asprintf(&d->blob, "g_step = %u", g_step);
			assert(ret != -1);
			size_t blob_len = ret;
			result = EVP_sendState(h, topic, d->blob, blob_len,
					       state_cb, d);
			if (EVP_OK != result) {
				log_module(module_name,
					   "Sent State (topic=%s, size=%zu) "
					   "fail with %d\n",
					   topic, blob_len, result);
			}
			assert(result == EVP_OK);
			reported_step = g_step;
		}
	}
	return 0;
}
