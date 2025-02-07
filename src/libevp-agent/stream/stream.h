/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef STREAM_H
#define STREAM_H

#include <pthread.h>

#include <evp/sdk.h>

#include <internal/queue.h>

#include "../event.h"
#include "../notification.h"

struct Stream {
	char *name;
	enum StreamType {
		STREAM_TYPE_NULL,
		STREAM_TYPE_NNG,
		STREAM_TYPE_POSIX,
		NR_STREAM_TYPE
	} type;
	enum StreamDirection {
		STREAM_DIRECTION_IN,
		STREAM_DIRECTION_OUT
	} direction;
	union StreamParams {
		struct StreamNng {
			enum {
				STREAM_NNG_MODE_DIAL,
				STREAM_NNG_MODE_LISTEN
			} mode;
			enum {
				STREAM_NNG_PROTOCOL_PUSH,
				STREAM_NNG_PROTOCOL_PULL
			} protocol;
			char *connection;
		} nng;
		struct StreamPosix {
			enum { STREAM_POSIX_TYPE_TCP } type;
			enum {
				STREAM_POSIX_DOMAIN_IPV4,
				STREAM_POSIX_DOMAIN_IPV6
			} domain;
			char *hostname;
			unsigned short port;
		} posix;
	} params;
};

struct stream_impl;
struct stream_read;

struct stream_ops {
	EVP_RESULT (*init)(struct stream_impl *);
	int (*close)(struct stream_impl *);
	int (*write)(const struct stream_impl *, const void *, size_t);
	int (*read)(struct stream_impl *, struct stream_read *sr);
	void (*free_msg)(void *);
	int (*atexit)(void);
};

struct stream_impl {
	TAILQ_ENTRY(stream_impl) q;
	EVP_STREAM stream;
	EVP_STREAM_READ_CALLBACK cb;
	void *stream_cb_userdata;
	struct Stream cfg;
	const struct stream_ops *ops;
	struct stream_impl_params *params;
	pthread_t in_thread;
	bool in_thread_init;
};

struct stream_read {
	EVP_STREAM_PEER_ID id;
	const void *buf;
	size_t n;
	void *free_args;
};

struct stream_port {
	struct stream_impl *si;
	unsigned short port;
};

/* SDK implementation-specific symbols. */
struct stream_impl *stream_from_stream(struct EVP_client *h,
				       EVP_STREAM stream);

struct stream_impl *stream_from_name(struct EVP_client *h, const char *name);

EVP_RESULT
stream_insert(struct EVP_client *h, struct stream_impl *si);

EVP_RESULT
stream_remove(struct EVP_client *h, struct stream_impl *si);

int stream_insert_read_event(struct EVP_client *h,
			     struct sdk_event_stream_read_available *ev);

/* SDK implementation-agnostic symbols. */
TAILQ_HEAD(stream_queue, stream_impl);

struct stream_impl *stream_impl_from_stream(const struct stream_queue *queue,
					    EVP_STREAM stream);

struct stream_impl *stream_impl_from_name(const struct stream_queue *queue,
					  const char *name);

EVP_RESULT stream_impl_insert(struct stream_queue *queue,
			      struct stream_impl *si);

EVP_RESULT stream_impl_remove(struct stream_queue *queue,
			      struct stream_impl *si);

EVP_RESULT
stream_get_params(struct EVP_client *h, const char *name,
		  const struct Stream **out);

int stream_duplicate(const struct Stream *src, struct Stream *dst);

void stream_free(struct Stream *s);

int stream_atexit(void);

struct notification *stream_notification(void);

EVP_RESULT EVP_impl_streamInputOpen(struct EVP_client *h, const char *name,
				    EVP_STREAM_READ_CALLBACK cb,
				    void *userData, EVP_STREAM *stream);
EVP_RESULT EVP_impl_streamOutputOpen(struct EVP_client *h, const char *name,
				     EVP_STREAM *stream);
EVP_RESULT EVP_impl_streamClose(struct EVP_client *h, EVP_STREAM stream);
EVP_RESULT EVP_impl_streamWrite(struct EVP_client *h, EVP_STREAM stream,
				const void *buf, size_t n);

extern const struct stream_ops stream_null_ops;
extern const struct stream_ops stream_nng_ops;
extern const struct stream_ops stream_posix_ops;

#endif /* STREAM_H */
