/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <internal/queue.h>

#include "notification.h"

struct notification_entry {
	char *event;
	int (*cb)(const void *, void *);
	void *user_data;
	STAILQ_ENTRY(notification_entry) q;
};

int
notification_subscribe(struct notification *notif, const char *event,
		       int (*cb)(const void *, void *), void *user_data,
		       struct notification_entry **e)
{
	int ret = -1;
	int error = pthread_mutex_lock(&notif->mutex);
	char *eventdup = NULL;
	struct notification_entry *entry = NULL;

	if (error) {
		fprintf(stderr, "%s: pthread_mutex_lock: %s\n", __func__,
			strerror(error));
		goto unlocked;
	}

	eventdup = strdup(event);

	if (eventdup == NULL) {
		fprintf(stderr, "%s: strdup(3): %s\n", __func__,
			strerror(errno));
		goto locked;
	}

	entry = malloc(sizeof(*entry));

	if (entry == NULL) {
		fprintf(stderr, "%s: malloc(3): %s\n", __func__,
			strerror(errno));
		goto locked;
	}

	*entry = (struct notification_entry){
		.event = eventdup, .user_data = user_data, .cb = cb};
	STAILQ_INSERT_TAIL(&notif->list, entry, q);

	if (e) {
		*e = entry;
	}

	ret = 0;

locked:
	error = pthread_mutex_unlock(&notif->mutex);

	if (error) {
		fprintf(stderr, "%s: pthread_mutex_unlock: %s\n", __func__,
			strerror(error));
		ret = -1;
	}

unlocked:
	if (ret) {
		free(eventdup);
		free(entry);
	}

	return ret;
}

int
notification_publish(struct notification *notif, const char *event,
		     const void *args)
{
	int ret = 0;
	int error = pthread_mutex_lock(&notif->mutex);
	const struct notification_entry *entry;

	if (error) {
		fprintf(stderr, "%s: pthread_mutex_lock: %s\n", __func__,
			strerror(error));
		return -1;
	}

	STAILQ_FOREACH(entry, &notif->list, q)
	{
		if (!strcmp(event, entry->event)) {
			error = entry->cb(args, entry->user_data);

			if (error) {
				ret = error;
			}
		}
	}

	error = pthread_mutex_unlock(&notif->mutex);

	if (error) {
		fprintf(stderr, "%s: pthread_mutex_unlock: %s\n", __func__,
			strerror(error));
		return -1;
	}

	return ret;
}

void
notification_deinit(struct notification *notif)
{
	if (!notif)
		return;

	int error = pthread_mutex_lock(&notif->mutex);

	if (error) {
		fprintf(stderr, "%s: pthread_mutex_lock: %s\n", __func__,
			strerror(error));
		return;
	}

	struct notification_entry *entry, *next;

	STAILQ_FOREACH_SAFE(entry, &notif->list, q, next)
	{
		free(entry->event);
		STAILQ_REMOVE_HEAD(&notif->list, q);
		free(entry);
	}

	error = pthread_mutex_unlock(&notif->mutex);

	if (error) {
		fprintf(stderr, "%s: pthread_mutex_unlock: %s\n", __func__,
			strerror(error));
	}

	error = pthread_mutex_destroy(&notif->mutex);

	if (error) {
		fprintf(stderr, "%s: pthread_mutex_destroy: %s\n", __func__,
			strerror(error));
	}
}

void
notification_free(struct notification *notif)
{
	notification_deinit(notif);
	free(notif);
}

struct notification *
notification_alloc(void)
{
	struct notification *notif = malloc(sizeof(*notif));

	if (!notif) {
		fprintf(stderr, "%s: malloc(3): %s\n", __func__,
			strerror(errno));
		goto failure;
	}

	*notif = NOTIFICATION_INITIALIZER(notif);
	return notif;

failure:
	notification_free(notif);
	return NULL;
}

int
notification_unsubscribe(struct notification *notif,
			 struct notification_entry *e)
{
	int ret = 0;
	int error = pthread_mutex_lock(&notif->mutex);

	if (error) {
		fprintf(stderr, "%s: pthread_mutex_lock: %s\n", __func__,
			strerror(error));
		return -1;
	}

	STAILQ_REMOVE(&notif->list, e, notification_entry, q);
	free(e->event);
	free(e);
	error = pthread_mutex_unlock(&notif->mutex);

	if (error) {
		fprintf(stderr, "%s: pthread_mutex_unlock: %s\n", __func__,
			strerror(error));
		return -1;
	}

	return ret;
}
