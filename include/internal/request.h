/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if !defined(__REQUEST_H__)
#define __REQUEST_H__

#include <stddef.h>
#include <stdint.h>

#include "queue.h"

typedef uint64_t sdk_xid_t;

struct sdk_response {
	/* serialized response */
	void *buf;
	size_t buflen;
	void (*buf_free)(void *);
};

struct sdk_request {
	TAILQ_ENTRY(sdk_request) q;
	TAILQ_ENTRY(sdk_request) wq;
	void *resp;
	size_t resplen;
	void (*done)(struct sdk_request *);
	void *user;

	sdk_xid_t xid;

	/* serialized request */
	void *buf;
	size_t buflen;
	void (*buf_free)(void *);
};

struct sdk_request *sdk_request_alloc(void);
void sdk_request_free(struct sdk_request *);

struct sdk_response *sdk_response_alloc(void);
void sdk_response_free(struct sdk_response *);

#endif /* !defined(__REQUEST_H__) */
