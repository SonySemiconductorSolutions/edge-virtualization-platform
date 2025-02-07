/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../sdkutil.h"
#include "client.h"

int
record_read(struct record_reader *r, struct sdk_transport *trans)
{
	int fd = trans->fd;
	int ret;

	if (r->bytes_read < sizeof(r->hdr)) {
		size_t want = sizeof(r->hdr) - r->bytes_read;
		ret = read(fd, (char *)&r->hdr + r->bytes_read, want);
		if (ret == 0) {
			return EIO; /* EOF */
		}
		if (ret == -1) {
			goto fail;
		}
		// TODO: Replace assert (runtime error)
		assert(ret > 0);
		r->bytes_read += ret;
		return 0;
	}
	size_t offset = r->bytes_read - sizeof(r->hdr);
	if (r->buf == NULL) {
		// TODO: Replace assert (programming error)
		assert(offset == 0);
		r->buf = xcalloc(1, r->hdr.size);
	}
	if (offset < r->hdr.size) {
		size_t want = r->hdr.size - offset;
		ret = read(fd, r->buf + offset, want);
		if (ret == 0) {
			return EIO; /* EOF */
		}
		if (ret == -1) {
			goto fail;
		}
		// TODO: Replace assert (runtime error)
		assert(ret > 0);
		r->bytes_read += ret;
	}
	offset = r->bytes_read - sizeof(r->hdr);
	if (offset < r->hdr.size) {
		return 0;
	}
	// TODO: Replace assert (programming error)
	assert(offset == r->hdr.size);
	r->dispatch(r->buf, r->hdr.size, r->hdr.xid, r->user);
	r->buf = NULL;
	r->bytes_read = 0;
	return 0;
fail:
	if (errno == EAGAIN || errno == EINTR) {
		return 0;
	}
	// TODO: Replace assert (programming error)
	assert(errno != 0);
	return errno;
}

int
record_write(struct record_writer *w, struct sdk_transport *trans)
{
	int fd = trans->fd;
	int ret;

	if (w->buf == NULL) {
		memset(&w->hdr, 0, sizeof(w->hdr));
		w->buf = w->get_next(&w->hdr.size, &w->hdr.xid, w->user);
		if (w->buf == NULL) {
			return 0;
		}
		w->bytes_written = 0;
	}
	if (w->bytes_written < sizeof(w->hdr)) {
		size_t want = sizeof(w->hdr) - w->bytes_written;
		ret = write(fd, (const char *)&w->hdr + w->bytes_written,
			    want);
		// TODO: Replace assert (runtime error)
		assert(ret != 0);
		if (ret == -1) {
			goto fail;
		}
		// TODO: Replace assert (runtime error)
		assert(ret > 0);
		w->bytes_written += ret;
		return 0;
	}
	size_t offset = w->bytes_written - sizeof(w->hdr);
	if (offset < w->hdr.size) {
		size_t want = w->hdr.size - offset;
		ret = write(fd, w->buf + offset, want);
		// TODO: Replace assert (runtime error)
		assert(ret != 0);
		if (ret == -1) {
			goto fail;
		}
		// TODO: Replace assert (runtime error)
		assert(ret > 0);
		w->bytes_written += ret;
	}
	offset = w->bytes_written - sizeof(w->hdr);
	if (offset < w->hdr.size) {
		return 0;
	}
	// TODO: Replace assert (programming error)
	assert(offset == w->hdr.size);
	w->free_buf(w->buf);
	w->buf = NULL;
	return 0;
fail:
	if (errno == EAGAIN || errno == EINTR) {
		return 0;
	}
	// TODO: Replace assert (runtime error)
	assert(errno != 0);
	return errno;
}

int
sdk_clnt_sync_ts(struct sdk_client *clnt, const struct timespec *abstimeout)
{
	int timeout_ms = absts2relms_realtime_roundup(abstimeout);
	return sdk_clnt_sync(clnt, timeout_ms);
}

static int
process_agent_in(struct sdk_client *clnt, const struct pollfd *pfd)
{
	struct sdk_transport *trans = &clnt->transport;
	int ret = -1;

	if ((pfd->revents & POLLIN) != 0) {
		ret = record_read(&clnt->reader, trans);
		if (ret != 0) {
			return ret;
		}
	}
	if ((pfd->revents & POLLOUT) != 0) {
		ret = record_write(&clnt->writer, trans);
		if (ret != 0) {
			return ret;
		}
	}

	return ret;
}

static int
process_stream_in(struct sdk_client *clnt, const struct pollfd *pfd)
{
	void *buf, *p = &buf;
	size_t rem = sizeof(buf);

	while (rem) {
		ssize_t n = read(pfd->fd, p, rem);

		if (n < 0) {
			fprintf(stderr, "%s: read(2): %s\n", __func__,
				strerror(errno));
			return errno;
		}

		p = (char *)p + n;
		rem -= n;
	}

	return clnt->transport.on_stream_input(buf, clnt->transport.user);
}

int
sdk_clnt_sync(struct sdk_client *clnt, int timeout_ms)
{
	struct sdk_transport *trans = &clnt->transport;
	int fds[] = {trans->fd, trans->fds[0]};
	struct pollfd pfd[sizeof(fds) / sizeof(*fds)];
	static int (*const process[sizeof(fds) / sizeof(*fds)])(
		struct sdk_client *,
		const struct pollfd *) = {process_agent_in, process_stream_in};
	int ret;

	for (size_t i = 0; i < sizeof(pfd) / sizeof(*pfd); i++) {
		pfd[i] = (struct pollfd){
			.events = POLLIN,
			.fd = fds[i],
		};
	}

	if (clnt->writer.buf != NULL ||
	    clnt->writer.has_next(clnt->writer.user)) {
		pfd[0].events |= POLLOUT;
	}
	ret = poll(pfd, sizeof(pfd) / sizeof(*pfd), timeout_ms);
	if (ret == -1) {
		// TODO: Replace assert (runtime error)
		assert(errno != 0);
		return errno;
	}
	if (ret == 0) {
		return ETIMEDOUT;
	}

	for (size_t i = 0; i < sizeof(process) / sizeof(*process); i++) {
		if (pfd[i].revents) {
			ret = process[i](clnt, &pfd[i]);

			if (ret) {
				return ret;
			}
		}
	}

	return 0;
}
