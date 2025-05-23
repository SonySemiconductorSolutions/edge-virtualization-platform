/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef BLOB_H
#define BLOB_H

#if defined(__NuttX__)
#include <nuttx/compiler.h>
#else
#if !defined(FAR)
#define FAR
#endif
#endif

#include <config.h>

#include <stdbool.h>
#include <unistd.h>

#include "work.h"

struct evp_agent_context;

enum blob_work_type {
	BLOB_TYPE_AZURE_BLOB = 0,
	deprecated_BLOB_TYPE_EVP = 1, /* not used */
	BLOB_TYPE_HTTP = 2,
	BLOB_TYPE_EVP_EXT = 3,
	BLOB_TYPE_HTTP_EXT = 4,

};

enum blob_work_op {
	BLOB_OP_GET = 0,
	BLOB_OP_PUT = 1,
	BLOB_OP_GET_BLOB_URL = 2,
};

enum blob_work_result {
	BLOB_RESULT_SUCCESS = 0,
	BLOB_RESULT_ERROR = 1,
	BLOB_RESULT_ERROR_HTTP = 2,
	BLOB_RESULT_DENIED = 3,
	BLOB_RESULT_INVALID = 4, /* Invalid parameters, not supported */
};

struct blob_work {
	struct work wk;
	enum blob_work_type type;
	enum blob_work_op op;

	union {
		const char *url;
		char *url_rw;
	};
	const char *filename;
	const char *tmpname_template;
	char *buffer;
	int buffer_size;

	/*
	 * proxy settings
	 */

	const char *proxy;
	const char *proxy_user;

	/*
	 * Webclient sink callback. It's used only when `filename` is NULL.
	 */
	int (*webclient_sink_callback)(unsigned http_status, FAR char **buffer,
				       int offset, int datend, FAR int *buflen,
				       FAR void *arg);
	void *webclient_sink_callback_arg;

	/*
	 * Webclient body callback. It's used only when `filename` is NULL.
	 */
	int (*webclient_body_callback)(FAR void *buffer, FAR size_t *sizep,
				       FAR const void *FAR *datap,
				       size_t reqsize, FAR void *ctx);

	void *webclient_body_callback_arg;

	/*
	 * The length of the blob to upload
	 * Note: ignored if filename != NULL
	 */
	size_t blob_len;

	/* for BLOB_TYPE_EVP_EXT */
	const char *remote_name;
	union {
		const char *const *headers;
		char **headers_rw;
	};
	unsigned int nheaders;
	const char *cert_id;
	struct cert *cert;
	TAILQ_ENTRY(blob_work) rpcq EVP_GUARDED(g_sdk_lock);
	const char *module_instance_name;
	const char *storage_name;

	/* for SDK */
	void *user;

	/* for BLOB_STATUS_DONE */
	enum blob_work_result result;

	/* for BLOB_RESULT_ERROR */
	int error; /* errno value */

	/* for BLOB_RESULT_ERROR_HTTP */
	unsigned int http_status;

	struct evp_agent_context *agent;
};

struct blob_worker {
	struct worker worker;
	struct evp_agent_context *agent;
	void *buffer;
};

struct EVP_BlobRequestHttpExt {
	/**
	 * URL for the blob.
	 */
	char *url;

	/**
	 * Pointer array of extra headers.
	 */
	const char *const *headers;

	/**
	 * Number of extra headers in array.
	 */
	unsigned int nheaders;
};

#define BLOB_WORKER_BUFFER_SIZE (2048 + 128)

/** @brief Initialize the blob handler to perform the different blob operations
 *         supported
 *
 * @Note: This method must be called only once. Calling it more than once could
 *        result in unexpected behavior.
 */
void start_blob_worker_manager(struct evp_agent_context *agent);

/** @brief Clean the blob handler up, cancelling any threads it may have
 * spawned.
 */
void stop_blob_worker_manager(void);

void process_blob_rpcs(struct evp_agent_context *agent);

struct blob_work *blob_work_alloc(void);
void blob_work_free(struct blob_work *wk);

void blob_work_set_defaults(struct blob_work *wk);
void blob_work_set_proxy(struct blob_work *wk);
void blob_work_enqueue(struct blob_work *wk);
int blob_work_cancel(struct blob_work *wk);
char *blob_strerror(struct blob_work *wk);

int blob_noop_write_func(unsigned http_status, char **bufp, int offset,
			 int datend, int *buflen, void *vp);
int blob_file_write_func(unsigned http_status, char **bufp, int offset,
			 int datend, int *buflen, void *vp);
int blob_memory_write_func(char **bufp, int offset, int datend, int *buflen,
			   void *vp);

unsigned int blob_get(struct blob_work *wk,
		      unsigned int (*do_get)(struct blob_work *, int));
int blob_file_read_func(void *buffer, size_t *sizep, const void **datap,
			size_t reqsize, void *ctx);
unsigned int blob_put(struct blob_work *wk,
		      unsigned int (*do_put)(struct blob_work *, int));

#endif // BLOB_H
