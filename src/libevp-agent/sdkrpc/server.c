/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <internal/record_hdr.h>
#include <internal/request.h>
#include <internal/util.h>

#include "../ioutil.h"
#include "../sdk_agent.h"
#include "../sdkenc/sdk_builder.h"
#include "server.h"

void
sdk_svr_setup(struct sdk_server *svr, int fd)
{
	svr->fd = fd;
}

static void
resp_free(void *arg)
{
	sdk_response_free(arg);
}

int
sdk_svr_process(struct sdk_server *svr,
		int (*fn)(const void *, size_t, struct sdk_response **respp,
			  void *),
		void *ctx)
{
	struct sdk_response *resp = NULL;
	void *buf = NULL;
	int fd = svr->fd;
	ssize_t ssz;
	int error;

	struct record_hdr hdr;
	ssz = readall(fd, &hdr, sizeof(hdr));
	if (ssz < 0) {
		goto fail;
	}
	if ((size_t)ssz < sizeof(hdr)) {
		error = ECONNRESET; /* EOF in the middle of a record */
		goto fail_with_error;
	}
	if (hdr.zero != 0) {
		error = EINVAL;
		goto fail_with_error;
	}
	sdk_xid_t xid = hdr.xid;
	size_t sz = hdr.size;
	if (sz == 0) {
		error = EINVAL;
		goto fail_with_error;
	}

	if (sz > SDKRPC_MAX_REQUEST_SIZE) {
		if (discardall(fd, sz) != 0) {
			error = EIO;
			goto fail_with_error;
		}
		resp = sdk_response_alloc();
		void *buf;
		size_t buflen;
		buf = sdk_build_simple_response(&buflen, EVP_TOOBIG);
		*resp = (struct sdk_response){
			.buf = buf,
			.buflen = buflen,
			.buf_free = flatcc_builder_aligned_free,
		};
	} else {
		buf = xcalloc(1, sz);
		ssz = readall(fd, buf, sz);
		if (ssz < 0) {
			goto fail;
		}
		if ((size_t)ssz < sz) {
			error = ECONNRESET; /* EOF in the middle of a record */
			goto fail_with_error;
		}

		/* XXX todo: consider to process a few concurrent requests */

		error = fn(buf, sz, &resp, ctx);
		buf = NULL;
		if (error != 0) {
			goto fail_with_error;
		}
	}

	// TODO: Replace assert (runtime error)
	assert(resp != NULL);
	const void *resp_buf = resp->buf;
	uint32_t resp_sz = resp->buflen;
	// TODO: Replace assert (programming error)
	assert(resp_buf != NULL);
	// TODO: Replace assert (programming error)
	assert(resp_sz > 0);
	struct record_hdr resp_hdr;
	memset(&resp_hdr, 0, sizeof(resp_hdr));
	resp_hdr.xid = xid;
	resp_hdr.size = resp_sz;
	pthread_cleanup_push(resp_free, resp);
	ssz = write(fd, &resp_hdr, sizeof(resp_hdr));
	pthread_cleanup_pop(0);
	if (ssz < 0) {
		goto fail;
	}
	if ((size_t)ssz < sizeof(resp_hdr)) {
		error = EIO; /* probably the peer closed the transport */
		goto fail_with_error;
	}
	pthread_cleanup_push(resp_free, resp);
	ssz = write(fd, resp_buf, resp_sz);
	pthread_cleanup_pop(0);
	if (ssz == -1) {
		goto fail;
	}
	if (ssz < resp_sz) {
		error = EIO; /* probably the peer closed the transport */
		goto fail_with_error;
	}
	sdk_response_free(resp);
	return 0;
fail:;
	error = errno;
fail_with_error:
	// TODO: Replace assert (programming error)
	assert(error != 0);
	free(buf);
	sdk_response_free(resp);
	return error;
}

struct sdk_response *
sdk_response_alloc(void)
{
	struct sdk_response *resp = xcalloc(1, sizeof(*resp));
	return resp;
}

void
sdk_response_free(struct sdk_response *resp)
{
	if (resp == NULL) {
		return;
	}
	if (resp->buf != NULL && resp->buf_free != NULL) {
		resp->buf_free(resp->buf);
	}
	free(resp);
}
