/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __SDK_MSG_H__
#define __SDK_MSG_H__

#include "event.h"
#include "manifest.h"

/* A message 'subscribe topic'
 *
 * It represent the device wide name that corresponds to the subscribe part of
 * a topic
 *
 * It should be mapping one attribute under .subscribe_topics of JSON manifest
 */
struct sdk_msg_subscribe_topic {
	TAILQ_ENTRY(sdk_msg_subscribe_topic) q;
	const char *name; /* from the JSON attribute key (the subscribe topic
			     name)*/
	enum sdk_msg_topic_type type; /* from the JSON sub attribute "type"
					 (usually "local" or "upstream") */
	const char *topic; /* from the JSON sub attribute "topic", representing
			      a local named queue or a upstream MQTT topic */
};

/* A message 'publish topic'
 *
 * It represent the device wide name that corresponds to the publish part of a
 * topic
 *
 * It should be mapping one attribute under .publish_topics of JSON manifest
 */
struct sdk_msg_publish_topic {
	TAILQ_ENTRY(sdk_msg_publish_topic) q;
	const char *
		name; /* from the JSON attribute key (the publish topic name)*/
	int type;     /* from the JSON sub attribute "type" (usually "local" or
			 "upstream") */
	const char *topic; /* from the JSON sub attribute "topic", representing
			      a local named queue or a upstream MQTT topic */
};

/* A message 'topic alias'
 *
 * It represent the module local name (alias) that corresponds to a device wide
 * 'subscribe topic' or 'publish topic'.
 *
 * It should be mapping one attribute under
 * .instanceSpecs.<instance>.{publish|subscribe} of JSON manifest
 */
struct sdk_msg_topic_alias {
	TAILQ_ENTRY(sdk_msg_topic_alias) q;
	const char *name;  /* from the JSON attribute key (the alias name)*/
	const char *topic; /* they the JSON attribute value (the 'subscribe
			      topic' or 'publish topic' is linked to)*/
};

void sdk_set_publish_topics(struct TopicList *topics);
void sdk_set_subscribe_topics(struct TopicList *topics);

#endif /* __SDK_MSG_H__ */
