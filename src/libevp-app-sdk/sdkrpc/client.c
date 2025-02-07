/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sys/socket.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <internal/queue.h>
#include <internal/request.h>

#include "../sdkutil.h"
#include "client.h"

static TAILQ_HEAD(, sdk_request) sdk_reqq = TAILQ_HEAD_INITIALIZER(sdk_reqq);
static TAILQ_HEAD(,
		  sdk_request) sdk_writeq = TAILQ_HEAD_INITIALIZER(sdk_writeq);
static sdk_xid_t next_xid = 1000;

void
sdk_clnt_enqueue(struct sdk_client *clnt, struct sdk_request *req)
{
	TAILQ_INSERT_TAIL(&sdk_reqq, req, q);
	TAILQ_INSERT_TAIL(&sdk_writeq, req, wq);
}

static bool
has_next(void *user)
{
	struct sdk_request *req;
	req = TAILQ_FIRST(&sdk_writeq);
	return req != NULL;
}

static void *
get_next(uint32_t *sizep, sdk_xid_t *xidp, void *user)
{
	struct sdk_request *req;
	req = TAILQ_FIRST(&sdk_writeq);
	if (req != NULL) {
		TAILQ_REMOVE(&sdk_writeq, req, wq);
	}
	if (req == NULL) {
		return NULL;
	}
	*xidp = req->xid;
	*sizep = req->buflen;
	return req->buf;
}

void
free_buf(void *p)
{
	// TODO: Replace assert (programming error)
	assert(p != NULL);

	/*
	 * nothing to do.
	 *
	 * the buffer will be freed by sdk_request_free.
	 */
}

static void dispatch(void *buf, size_t size, sdk_xid_t xid, void *user);

void
sdk_clnt_setup(struct sdk_client *clnt, int fd)
{
	int flags;
	int ret;
	flags = fcntl(fd, F_GETFL, 0);
	ret = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	// TODO: Replace assert (runtime error)
	assert(ret != -1);

	memset(clnt, 0, sizeof(*clnt));
	struct sdk_transport *t = &clnt->transport;
	t->fd = fd;
	struct record_writer *w = &clnt->writer;
	w->has_next = has_next;
	w->get_next = get_next;
	w->free_buf = free_buf;
	struct record_reader *r = &clnt->reader;
	r->dispatch = dispatch;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, t->fds)) {
		fprintf(stderr, "%s: socketpair(2): %s\n", __func__,
			strerror(errno));
	}
}

#undef ns
#define ns(a) FLATBUFFERS_WRAP_NAMESPACE(EVP_SDK, a)

static void
rpc_clnt_resp_dispatch(void *resp, size_t size, sdk_xid_t xid)
{
	struct sdk_request *req;
	TAILQ_FOREACH (req, &sdk_reqq, q) {
		if (req->xid == xid) {
			TAILQ_REMOVE(&sdk_reqq, req, q);
			break;
		}
	}
	if (req != NULL) {
		req->resp = resp;
		req->resplen = size;
		req->done(req);
	} else {
		free(resp);
	}
}

static void
dispatch(void *buf, size_t size, sdk_xid_t xid, void *user)
{
	if (size > SDKRPC_MAX_RESPONSE_SIZE) {
		free(buf);
		return;
	}

	rpc_clnt_resp_dispatch(buf, size, xid);
}

struct sdk_request *
sdk_request_alloc(void)
{
	struct sdk_request *req = xmalloc(sizeof(*req));
	*req = (struct sdk_request){
		.resp = NULL,
		.buf = NULL,
		.xid = next_xid++,
	};
	return req;
}

void
sdk_request_free(struct sdk_request *req)
{
	// TODO: Replace assert (programming error)
	assert(req != NULL);
	free(req->resp);
	if (req->buf != NULL && req->buf_free != NULL) {
		req->buf_free(req->buf);
	}
	free(req);
}
