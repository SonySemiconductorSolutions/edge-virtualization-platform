/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef NOTIFICATION_H
#define NOTIFICATION_H

#include <pthread.h>

#include <internal/queue.h>

#define NOTIFICATION_INITIALIZER(notif)                                       \
	(struct notification)                                                 \
	{                                                                     \
		.list = STAILQ_HEAD_INITIALIZER((notif)->list),               \
		.mutex = PTHREAD_MUTEX_INITIALIZER                            \
	}

struct notification {
	STAILQ_HEAD(, notification_entry) list;
	pthread_mutex_t mutex;
};

struct notification *notification_alloc(void);
int notification_publish(struct notification *notif, const char *event,
			 const void *args);
int notification_subscribe(struct notification *notif, const char *event,
			   int (*cb)(const void *args, void *user_data),
			   void *user_data, struct notification_entry **e);
int notification_unsubscribe(struct notification *notif,
			     struct notification_entry *e);
void notification_deinit(struct notification *notif);
void notification_free(struct notification *notif);

#endif
