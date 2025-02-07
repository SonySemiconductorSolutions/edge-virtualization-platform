/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __EVENT_H__
#define __EVENT_H__

#include <semaphore.h>
#include <stdbool.h>

#include <evp/sdk.h>

#include <internal/queue.h>

struct blob_work;

enum sdk_event_type {
	SDK_EVENT_CONFIG = 1,
	SDK_EVENT_STATE = 2,
	SDK_EVENT_BLOB = 4,
	SDK_EVENT_MESSAGE_SENT = 5,
	SDK_EVENT_MESSAGE_RECEIVED = 6,
	SDK_EVENT_TELEMETRY = 7,
	SDK_EVENT_RPC_REQUEST = 8,
	SDK_EVENT_RPC_RESPONSE = 9,
	SDK_EVENT_STREAM_READ_AVAILABLE = 10,
	SDK_EVENT_BLOB_GET_UPLOAD_URL = 11,
	SDK_EVENT_BLOB_IO_READ = 12,
	SDK_EVENT_BLOB_IO_WRITE = 13,
};

struct sdk_event {
	TAILQ_ENTRY(sdk_event) q;
	enum sdk_event_type type;
	const void *buffer;
	void *extra_alloc;
};

/*
 * "output" / "input" in the comments below documents the directions
 * for sdkrpc.
 * the "output" means the info which the agent passes to the
 * module instance. and vice versa.
 *
 *    output: the agent -> the module instance
 *    input : the agent <- the module instance
 */

/* SDK_EVENT_CONFIG */
struct sdk_event_config {
	struct sdk_event event;
	const char *topic; /* output */
	const void *blob;  /* output */
	size_t bloblen;    /* output */
};

/* SDK_EVENT_STATE */
struct sdk_event_state {
	struct sdk_event event;
	const char *topic; /* input */
	const void *blob;  /* input */
	size_t bloblen;    /* input */

	EVP_STATE_CALLBACK cb;            /* input/output */
	EVP_STATE_CALLBACK_REASON reason; /* output */
	void *cb_userdata;                /* input/output */

#if !defined(EVPMODULESDK)
	bool collected;
#endif
};

/* SDK_EVENT_BLOB */
struct sdk_event_blob_callback_closure {
	EVP_BLOB_CALLBACK cb; /* input/output */
	void *cb_data;        /* input/output */
};

struct sdk_event_blob_io_callback_closure {
	EVP_BLOB_IO_CALLBACK cb; /* input/output */
	void *cb_data;           /* input/output */
	struct EVP_client *h;
};

struct sdk_event_blob {
	struct sdk_event event;
#if defined(EVPMODULESDK)
	void *result;
#else
	struct blob_work *work; /* input/output */
#endif /* defined(EVPMODULESDK) */

	struct sdk_event_blob_callback_closure user_cb; /* input/output */

	struct sdk_event_blob_io_callback_closure io_cb; /* input/output */
	EVP_BLOB_CALLBACK_REASON reason;                 /* output */

	/* temporary use */
	struct EVP_client *owner;
};

/* SDK_EVENT_MESSAGE_SENT */
struct sdk_event_message_sent {
	struct sdk_event event;
	const char *topic; /* input */
	const void *blob;  /* input */
	size_t bloblen;    /* input */

	EVP_MESSAGE_SENT_CALLBACK cb;            /* input/output */
	EVP_MESSAGE_SENT_CALLBACK_REASON reason; /* output */
	void *cb_userdata;                       /* input/output */

	/* temporary use in sdk_process_outbox_messages */
	struct EVP_client *from;
	bool mqtt_published;
};

/* SDK_EVENT_MESSAGE_RECEIVED */
struct sdk_event_message_received {
	struct sdk_event event;
	const char *topic; /* output */
	const void *blob;  /* output */
	size_t bloblen;    /* output */
};

/* SDK_EVENT_TELEMETRY */
struct sdk_event_telemetry {
	struct sdk_event event;
	const struct EVP_telemetry_entry *entries; /* input */
	size_t nentries;                           /* input */
	EVP_TELEMETRY_CALLBACK cb;                 /* input/output */
	EVP_TELEMETRY_CALLBACK_REASON reason;      /* output */
	void *cb_userdata;                         /* input/output */

	/* Owner handle */
	struct EVP_client *owner;

#if !defined(EVPMODULESDK)
	bool collected;
#endif
};

/* SDK_EVENT_RPC_REQUEST */
struct sdk_event_rpc_request {
	struct sdk_event event;
	EVP_RPC_ID id;      /* output */
	const char *method; /* output */
	const char *params; /* output */
};

/* SDK_EVENT_RPC_RESPONSE */
struct sdk_event_rpc_response {
	struct sdk_event event;
	EVP_RPC_ID id;                           /* input */
	const char *response;                    /* input */
	EVP_RPC_RESPONSE_STATUS status;          /* input */
	EVP_RPC_RESPONSE_CALLBACK cb;            /* input/output */
	EVP_RPC_RESPONSE_CALLBACK_REASON reason; /* output */
	void *cb_userdata;                       /* input/output */
};

/* SDK_EVENT_STREAM_READ_AVAILABLE */
struct sdk_event_stream_read_available {
	struct sdk_event event;
	EVP_STREAM_PEER_ID id;
	EVP_STREAM_READ_CALLBACK cb;
	void *free_args;
	void (*free)(void *);
	void *cb_userdata;
	const void *buf;
	size_t n;
};

struct sdk_event_blob_io {
	struct sdk_event event;
	struct EVP_client *h;
	EVP_BLOB_IO_CALLBACK cb;
	void *cb_data;
	size_t n;
	int *out_errno;
	sem_t *sem;

	union sdk_event_blob_io_buf {
		void *rw;
		const void *ro;
	} buf;
};

#endif /* __EVENT_H__ */
