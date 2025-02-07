/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <internal/util.h>

#include "module_instance.h"
#include "sdk_agent.h"
#include "sdk_impl.h"
#include "sdk_msg.h"

static TAILQ_HEAD(, sdk_msg_publish_topic)
	g_publish_topics = TAILQ_HEAD_INITIALIZER(g_publish_topics);
static TAILQ_HEAD(, sdk_msg_subscribe_topic)
	g_subscribe_topics = TAILQ_HEAD_INITIALIZER(g_subscribe_topics);

/* forward declarations */
bool sdk_forward_local_to_topic(struct sdk_event_message_sent *msg,
				const char *topic_name);
bool sdk_forward_local_to_subscribe_topic(struct sdk_event_message_sent *msg,
					  const char *subscribe_topic_name);

void
sdk_set_publish_topics(struct TopicList *topics)
{
	struct sdk_msg_publish_topic *topic;
	size_t i;

	while ((topic = TAILQ_FIRST(&g_publish_topics)) != NULL) {
		TAILQ_REMOVE(&g_publish_topics, topic, q);
		/*
		 * The following unnatural assertion was added to suppress
		 * a clang ananlyzer warning.
		 * "warning: Use of memory after it is freed [unix.Malloc]"
		 */
		// TODO: Replace assert (programming error)
		assert(topic != TAILQ_FIRST(&g_publish_topics));
		free(__UNCONST(topic->name));
		free(__UNCONST(topic->topic));
		free(topic);
	}

	if (topics == NULL) {
		return;
	}

	for (i = 0; i < topics->n; i++) {
		topic = xmalloc(sizeof(struct sdk_msg_publish_topic));
		topic->name = xstrdup(topics->topics[i].name);
		topic->type =
			topic_type_string_to_enum(topics->topics[i].type);
		topic->topic = xstrdup(topics->topics[i].topic);
		TAILQ_INSERT_TAIL(&g_publish_topics, topic, q);
	}
}

void
sdk_set_subscribe_topics(struct TopicList *topics)
{
	struct sdk_msg_subscribe_topic *topic;
	size_t i;

	while ((topic = TAILQ_FIRST(&g_subscribe_topics)) != NULL) {
		TAILQ_REMOVE(&g_subscribe_topics, topic, q);
		/*
		 * The following unnatural assertion was added to suppress
		 * a clang ananlyzer warning.
		 * "warning: Use of memory after it is freed [unix.Malloc]"
		 */
		// TODO: Replace assert (programming error)
		assert(topic != TAILQ_FIRST(&g_subscribe_topics));
		free(__UNCONST(topic->name));
		free(__UNCONST(topic->topic));
		free(topic);
	}

	if (topics == NULL) {
		return;
	}

	for (i = 0; i < topics->n; i++) {
		topic = xmalloc(sizeof(struct sdk_msg_subscribe_topic));
		topic->name = xstrdup(topics->topics[i].name);
		topic->type =
			topic_type_string_to_enum(topics->topics[i].type);
		topic->topic = xstrdup(topics->topics[i].topic);
		TAILQ_INSERT_TAIL(&g_subscribe_topics, topic, q);
	}
}

bool
sdk_forward_local_to_publish_topic(struct sdk_event_message_sent *msg,
				   const char *publish_topic_name)
{
	struct sdk_msg_publish_topic *publish_topic;
	TAILQ_FOREACH (publish_topic, &g_publish_topics, q) {
		if (strcmp(publish_topic_name, publish_topic->name) == 0) {
			if (publish_topic->type == SDK_MSG_TOPIC_TYPE_LOCAL) {
				return sdk_forward_local_to_topic(
					msg, publish_topic->topic);
			} else {
				fprintf(stderr,
					"error: message not forwarded: "
					"'publish_topic' item '%s' found "
					"but type not implemented\n",
					publish_topic_name);
				return false;
			}
		}
	}
	fprintf(stderr,
		"error: message not forwarded: no 'publish_topic' items "
		"declared with name '%s'\n",
		publish_topic_name);
	return false;
}

bool
sdk_forward_local_to_topic(struct sdk_event_message_sent *msg,
			   const char *topic_name)
{
	// todo: check type is local?
	bool forwarded_to_someone = false;
	struct sdk_msg_subscribe_topic *subscribe_topic;
	TAILQ_FOREACH (subscribe_topic, &g_subscribe_topics, q) {
		if (strcmp(topic_name, subscribe_topic->topic) == 0) {
			if (subscribe_topic->type ==
			    SDK_MSG_TOPIC_TYPE_LOCAL) {
				forwarded_to_someone =
					forwarded_to_someone ||
					sdk_forward_local_to_subscribe_topic(
						msg, subscribe_topic->name);
			} else {
				fprintf(stderr,
					"error: message not forwarded: "
					"'subscribe_topic' item '%s' found "
					"with "
					"topic '%s'"
					"but type not implemented\n",
					subscribe_topic->name,
					subscribe_topic->topic);
				return false;
			}
		}
	}
	if (!forwarded_to_someone) {
		fprintf(stderr,
			"error: message not forwarded: no 'subscribe_topic' "
			"items declared with type 'local' and topic '%s'\n",
			topic_name);
	}
	return forwarded_to_someone;
}

bool
sdk_forward_local_to_subscribe_topic(struct sdk_event_message_sent *msg,
				     const char *subscribe_topic_name)
{
	bool forwarded_to_someone = false;
	const char *original_topic = msg->topic;
	msg->topic = subscribe_topic_name;
	module_instance_message_forward(msg);
	forwarded_to_someone =
		msg->reason == EVP_MESSAGE_SENT_CALLBACK_REASON_SENT;
	msg->topic = original_topic;

	if (!forwarded_to_someone) {
		fprintf(stdout,
			"warning: message not forwarded: no module instance "
			"declared a 'subscribe' item with topic '%s'\n",
			subscribe_topic_name);
	}
	return forwarded_to_someone;
}
