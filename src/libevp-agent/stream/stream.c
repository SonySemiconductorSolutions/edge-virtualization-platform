/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _POSIX_C_SOURCE 200809L

#include <config.h>

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <evp/sdk.h>

#include <internal/queue.h>

#include "../cdefs.h"
#include "../event.h"
#include "../path.h"
#include "stream.h"

static const struct stream_ops *stream_ops[NR_STREAM_TYPE] = {
	[STREAM_TYPE_NULL] = &stream_null_ops,
	[STREAM_TYPE_POSIX] = &stream_posix_ops,
};

static struct notification notification =
	NOTIFICATION_INITIALIZER(&notification);

struct notification *
stream_notification(void)
{
	return &notification;
}

static struct stream_impl *
alloc_stream(const struct Stream *stream, const char *name)
{
	struct stream_impl *ret = NULL;
	static EVP_STREAM stream_cnt;

	ret = malloc(sizeof(*ret));
	if (ret == NULL) {
		goto failure;
	}

	*ret = (struct stream_impl){.stream = ++stream_cnt};

	if (stream_duplicate(stream, &ret->cfg)) {
		fprintf(stderr, "%s: stream_duplicate failed\n", __func__);
		goto failure;
	}
	return ret;

failure:
	if (ret != NULL) {
		stream_free(&ret->cfg);
	}
	free(ret);
	return NULL;
}

static int
close_stream(struct stream_impl *si)
{
	int ret = 0;

	if (si == NULL) {
		return 0;
	}

	if (si->in_thread_init) {
		int error = pthread_cancel(si->in_thread);

		if (error) {
			fprintf(stderr, "%s: pthread_cancel(3): %s\n",
				__func__, strerror(error));
			ret = -1;
		}

		error = pthread_join(si->in_thread, NULL);

		if (error) {
			fprintf(stderr, "%s: pthread_join(3): %s\n", __func__,
				strerror(error));
			ret = -1;
		}
	}

	if (si->ops != NULL) {
		ret = si->ops->close(si);
		if (ret != 0) {
			fprintf(stderr, "%s: stream close failed\n", __func__);
		}
	}

	stream_free(&si->cfg);
	return ret;
}

struct stream_impl *
stream_impl_from_stream(const struct stream_queue *queue, EVP_STREAM stream)
{
	struct stream_impl *s;
	TAILQ_FOREACH (s, queue, q) {
		if (s->stream == stream) {
			return s;
		}
	}
	return NULL;
}

struct stream_impl *
stream_impl_from_name(const struct stream_queue *queue, const char *name)
{
	struct stream_impl *stream;
	TAILQ_FOREACH (stream, queue, q) {
		if (!strcmp(stream->cfg.name, name)) {
			return stream;
		}
	}
	return NULL;
}

EVP_RESULT
stream_impl_insert(struct stream_queue *queue, struct stream_impl *si)
{
	TAILQ_INSERT_TAIL(queue, si, q);
	return EVP_OK;
}

EVP_RESULT
stream_impl_remove(struct stream_queue *queue, struct stream_impl *si)
{
	TAILQ_REMOVE(queue, si, q);
	return EVP_OK;
}

static EVP_RESULT
EVP_impl_streamOpen(struct EVP_client *h, const char *name, EVP_STREAM *out)
{
	EVP_RESULT ret;
	struct stream_impl *si = NULL;
	const struct Stream *stream;

	if (stream_from_name(h, name) != NULL) {
		ret = EVP_EXIST;
		goto end;
	}

	ret = stream_get_params(h, name, &stream);
	if (ret != EVP_OK) {
		goto end;
	}

	if (stream->type >= NR_STREAM_TYPE || stream->type < 0) {
		ret = EVP_NOTSUP;
		goto end;
	}

	si = alloc_stream(stream, name);
	if (si == NULL) {
		ret = EVP_NOMEM;
		goto end;
	}

	si->ops = stream_ops[stream->type];
	if (si->ops == NULL) {
		ret = EVP_NOTSUP;
		goto end;
	}

	ret = si->ops->init(si);
	if (ret != EVP_OK) {
		goto end;
	}

	ret = stream_insert(h, si);
	if (ret != EVP_OK) {
		goto end;
	}

	struct notification *n = stream_notification();
	if (n == NULL) {
		ret = EVP_ERROR;
		goto end;
	}

	if (notification_publish(n, "init/done", si)) {
		ret = EVP_ERROR;
		goto end;
	}

	*out = si->stream;
end:
	if (ret != EVP_OK) {
		close_stream(si);
		*out = -1;
	}

	return ret;
}

static const char *
direction_tostr(enum StreamDirection direction)
{
	static const char *const directions[] = {
		[STREAM_DIRECTION_IN] = "STREAM_DIRECTION_IN",
		[STREAM_DIRECTION_OUT] = "STREAM_DIRECTION_OUT",
	};

	return directions[direction];
}

static int
write_stream(const struct stream_impl *si, const void *buf, size_t n)
{
	return si->ops->write(si, buf, n);
}

EVP_RESULT
EVP_impl_streamWrite(struct EVP_client *h, EVP_STREAM stream, const void *buf,
		     size_t n)
{
	EVP_RESULT ret = EVP_OK;

	const struct stream_impl *si = stream_from_stream(h, stream);
	if (si == NULL) {
		ret = EVP_INVAL;
		goto end;
	}

	if (si->cfg.direction != STREAM_DIRECTION_OUT) {
		fprintf(stderr, "%s: unexpected direction %s\n", __func__,
			direction_tostr(si->cfg.direction));
		ret = EVP_INVAL;
		goto end;
	}

	if (write_stream(si, buf, n) != 0) {
		fprintf(stderr, "%s: write_stream failed\n", __func__);
		ret = EVP_ERROR;
		goto end;
	}

	ret = EVP_OK;
end:
	return ret;
}

EVP_RESULT
EVP_impl_streamOutputOpen(struct EVP_client *h, const char *name,
			  EVP_STREAM *stream)
{
	struct stream_impl *si = NULL;
	EVP_RESULT ret = EVP_impl_streamOpen(h, name, stream);
	if (ret != EVP_OK) {
		fprintf(stderr, "EVP_impl_streamOpen failed with error %d\n",
			(int)ret);
		goto end;
	}

	si = stream_from_stream(h, *stream);
	if (si == NULL) {
		ret = EVP_ERROR;
		goto end;
	}

	enum StreamDirection direction = si->cfg.direction;
	if (direction != STREAM_DIRECTION_OUT) {
		fprintf(stderr, "expected STREAM_DIRECTION_OUT, got \"%s\"\n",
			direction_tostr(direction));
		ret = EVP_INVAL;
		goto end;
	}

	ret = EVP_OK;
end:
	if (ret != EVP_OK) {
		close_stream(si);
	}
	return ret;
}

EVP_RESULT
EVP_impl_streamClose(struct EVP_client *h, EVP_STREAM stream)
{
	EVP_RESULT ret = EVP_OK;

	struct stream_impl *si = stream_from_stream(h, stream);
	if (si == NULL) {
		ret = EVP_INVAL;
		goto end;
	}

	ret = stream_remove(h, si);

	int error = close_stream(si);
	if (error != 0) {
		ret = EVP_ERROR;
	}

	free(si);
end:
	return ret;
}

struct stream_event_free_args {
	const struct stream_impl *si;
	void *data;
};

static void
free_read_msg(const struct stream_impl *si, void *data)
{
	si->ops->free_msg(data);
}

static void
free_read_event(void *data)
{
	struct stream_event_free_args *args = data;
	free_read_msg(args->si, args->data);
	free(args);
}

static int
notify_read_available(struct EVP_client *h, const struct stream_impl *si,
		      const struct stream_read *sr)
{
	int ret = -1;
	struct sdk_event_stream_read_available *event = NULL;
	struct stream_event_free_args *args = NULL;

	args = malloc(sizeof(*args));
	if (args == NULL) {
		fprintf(stderr, "%s: malloc(3) args failed with errno %d",
			__func__, errno);
		goto end;
	}

	*args = (struct stream_event_free_args){.data = sr->free_args,
						.si = si};

	event = malloc(sizeof(*event));
	if (event == NULL) {
		fprintf(stderr, "%s: malloc(3) event failed with errno %d",
			__func__, errno);
		goto end;
	}

	*event = (struct sdk_event_stream_read_available){
		.buf = sr->buf,
		.n = sr->n,
		.id = sr->id,
		.free = free_read_event,
		.free_args = args,
		.cb_userdata = si->stream_cb_userdata,
		.event.type = SDK_EVENT_STREAM_READ_AVAILABLE,
		.cb = si->cb};

	ret = stream_insert_read_event(h, event);
end:
	if (ret != 0) {
		free_read_event(sr->free_args);
		free(args);
	}
	return ret;
}

static int
check_input(struct EVP_client *h, struct stream_impl *si)
{
	struct stream_read sr;
	int result = si->ops->read(si, &sr);

	if (result) {
		fprintf(stderr, "%s: stream_read failed\n", __func__);
		return -1;
	}

	if (notify_read_available(h, si, &sr)) {
		fprintf(stderr, "%s: notify_read_available failed\n",
			__func__);
		return -1;
	}

	return 0;
}

struct in_thread_args {
	struct EVP_client *h;
	struct stream_impl *si;
};

static void *
in_thread(void *args)
{
	struct in_thread_args *a = args;

	pthread_cleanup_push(free, a);

	for (;;) {
		if (check_input(a->h, a->si)) {
			fprintf(stderr, "%s: check_input failed\n", __func__);
			goto end;
		}
	}

end:
	pthread_cleanup_pop(1);
	return NULL;
}

EVP_RESULT
EVP_impl_streamInputOpen(struct EVP_client *h, const char *name,
			 EVP_STREAM_READ_CALLBACK cb, void *userData,
			 EVP_STREAM *stream)
{
	struct stream_impl *si = NULL;
	struct in_thread_args *args = NULL;
	EVP_RESULT ret = EVP_impl_streamOpen(h, name, stream);
	if (ret != EVP_OK) {
		fprintf(stderr, "EVP_impl_streamOpen failed with error %d\n",
			(int)ret);
		goto end;
	}

	si = stream_from_stream(h, *stream);
	if (si == NULL) {
		ret = EVP_ERROR;
		goto end;
	}

	enum StreamDirection direction = si->cfg.direction;
	if (direction != STREAM_DIRECTION_IN) {
		fprintf(stderr, "expected STREAM_DIRECTION_IN, got \"%s\"\n",
			direction_tostr(direction));
		ret = EVP_INVAL;
		goto end;
	}

	args = malloc(sizeof(*args));
	if (args == NULL) {
		fprintf(stderr, "%s: malloc(3): %s\n", __func__,
			strerror(errno));
		ret = EVP_NOMEM;
		goto end;
	}

	*args = (struct in_thread_args){.si = si, .h = h};

	si->cb = cb;
	si->stream_cb_userdata = userData;

	int error = pthread_create(&si->in_thread, NULL, in_thread, args);

	if (error) {
		fprintf(stderr, "%s: pthread_create(3): %s\n", __func__,
			strerror(error));
		ret = EVP_ERROR;
		goto end;
	}

	si->in_thread_init = true;
	ret = EVP_OK;
end:
	if (ret != EVP_OK) {
		close_stream(si);
		free(args);
	}
	return ret;
}

int
stream_duplicate(const struct Stream *src, struct Stream *dst)
{
	int ret = 0;
	char *namedup = strdup(src->name), *connectiondup = NULL,
	     *hostnamedup = NULL;
	union StreamParams params = {0};

	if (namedup == NULL) {
		fprintf(stderr, "strdup(3) failed with errno %d\n", errno);
		ret = errno;
		goto end;
	}

	/* TODO: Create virtual function instead of switch */
	switch (src->type) {
	case STREAM_TYPE_NULL:
		break;
	case STREAM_TYPE_POSIX:
		{
			const struct StreamPosix *posix = &src->params.posix;

			hostnamedup = strdup(posix->hostname);
			if (hostnamedup == NULL) {
				fprintf(stderr,
					"strdup(3) failed with errno %d\n",
					errno);
				ret = errno;
				goto end;
			}

			params.posix =
				(struct StreamPosix){.domain = posix->domain,
						     .port = posix->port,
						     .type = posix->type,
						     .hostname = hostnamedup};
		}
		break;
	case NR_STREAM_TYPE:
		/* dummy case to avoid -Wswitch warnings */
		break;
	}

	*dst = (struct Stream){
		.direction = src->direction,
		.type = src->type,
		.name = namedup,
		.params = params,
	};

end:
	if (ret != 0) {
		free(connectiondup);
		free(namedup);
		free(hostnamedup);
	}
	return ret;
}

void
stream_free(struct Stream *s)
{
	if (!s)
		return;

	free(s->name);

	/* TODO: Create virtual function instead of switch */
	switch (s->type) {
	case STREAM_TYPE_NULL:
		break;
	case STREAM_TYPE_POSIX:
		free(s->params.posix.hostname);
		break;
	case NR_STREAM_TYPE:
		/* dummy case to avoid -Wswitch warnings */
		break;
	}
}

static void
close_singleton(void)
{
	struct notification *n = stream_notification();

	notification_deinit(n);
}

int
stream_atexit(void)
{
	int r;
	const struct stream_ops *ops, **p;

	r = 0;
	for (p = stream_ops; p < &stream_ops[NR_STREAM_TYPE]; ++p) {
		ops = *p;
		if (!ops || !ops->atexit)
			continue;
		r |= (*ops->atexit)();
	}

	r |= atexit(close_singleton);
	return r;
}
