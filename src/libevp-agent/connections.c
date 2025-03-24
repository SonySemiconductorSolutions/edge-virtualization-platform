/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <string.h>

#include "webclient/webclient.h"

#include "connections.h"
#include "timeutil.h"
#include "xlog.h"
#include "xpthread.h"

#define NO_DATA_TIMEOUT_S (10)

static struct {
	bool connected;
	unsigned int count;
	struct evp_lock lock;
} g_connections_state = {.lock = EVP_LOCK_INITIALIZER};

void
connections_set_status(bool is_connected)
{
	xpthread_mutex_lock(&g_connections_state.lock);
	g_connections_state.connected = is_connected;
	xpthread_mutex_unlock(&g_connections_state.lock);
}

/* we need to be able to stop the connections as soon as possible.
 * this is a simple way that uses the non-blocking API from webclient
 * to implement the original blocking api exported from this function
 */
struct connections_webclient_callback_arg {
	uint64_t last_data_time;

	int (*original_body_callback)(void *buffer, size_t *sizep,
				      const void **datap, size_t reqsize,
				      void *ctx);
	void *original_body_callback_arg;

	int (*original_header_callback)(unsigned http_status, const char *line,
					bool truncated, void *arg);
	void *original_header_callback_arg;

	int (*original_sink_callback)(unsigned http_status, char **buffer,
				      int offset, int datend, int *buflen,
				      void *arg);
	void *original_sink_callback_arg;
};

static int
connections_body_callback(void *buffer, size_t *sizep, const void **datap,
			  size_t reqsize, void *ctx)
{
	struct connections_webclient_callback_arg *conn = ctx;

	conn->last_data_time = gettime_ms();

	if (conn->original_body_callback) {
		return conn->original_body_callback(
			buffer, sizep, datap, reqsize,
			conn->original_body_callback_arg);
	}

	return 0;
}

static int
connections_header_callback(unsigned http_status, const char *line,
			    bool truncated, void *arg)
{
	struct connections_webclient_callback_arg *conn = arg;

	conn->last_data_time = gettime_ms();

	if (conn->original_header_callback) {
		return conn->original_header_callback(
			http_status, line, truncated,
			conn->original_header_callback_arg);
	}

	return 0;
}

static int
connections_sink_callback(unsigned http_status, char **buffer, int offset,
			  int datend, int *buflen, void *arg)
{
	struct connections_webclient_callback_arg *conn = arg;

	conn->last_data_time = gettime_ms();

	if (conn->original_sink_callback) {
		return conn->original_sink_callback(
			http_status, buffer, offset, datend, buflen,
			conn->original_sink_callback_arg);
	}

	return 0;
}

/* we need to be able to stop the connections as soon as possible.
 * this is a simple way that uses the non-blocking API from webclient
 * to implement the original blocking api exported from this function
 */
int
connections_webclient_perform(struct webclient_context *ctx)
{
	int ret;

	/* Do not use callback. Use sink_callback instead */
	// TODO: Replace assert (programming error)
	assert(ctx->callback == NULL);

	xpthread_mutex_lock(&g_connections_state.lock);
	if (!g_connections_state.connected) {
		xpthread_mutex_unlock(&g_connections_state.lock);
		xlog_info("dropping http request because we are offline");
		return -ENETDOWN;
	}

	g_connections_state.count++;
	xpthread_mutex_unlock(&g_connections_state.lock);

	/* Override the callbacks to the activity functions */
	struct connections_webclient_callback_arg arg = {
		.original_body_callback = ctx->body_callback,
		.original_body_callback_arg = ctx->body_callback_arg,
		.original_header_callback = ctx->header_callback,
		.original_header_callback_arg = ctx->header_callback_arg,
		.original_sink_callback = ctx->sink_callback,
		.original_sink_callback_arg = ctx->sink_callback_arg,
		.last_data_time = gettime_ms()

	};

	ctx->body_callback = connections_body_callback;
	ctx->body_callback_arg = &arg;
	ctx->header_callback = connections_header_callback;
	ctx->header_callback_arg = &arg;
	ctx->sink_callback = connections_sink_callback;
	ctx->sink_callback_arg = &arg;

	ctx->flags |= WEBCLIENT_FLAG_NON_BLOCKING;

	if (ctx->timeout_sec == 0) {
		ctx->timeout_sec = NO_DATA_TIMEOUT_S;
	}

perform_again:
	ret = webclient_perform(ctx);

	if (ret)
		xlog_debug("webclient_perform returned %d", ret);

	if (ret == -EAGAIN || ret == -EINPROGRESS) {
		struct webclient_poll_info info;
		struct pollfd pfd;

		/* Set up poll */
		ret = webclient_get_poll_info(ctx, &info);
		if (ret != 0) {
			xlog_info("webclient_get_poll_info returned %d", ret);
			ret = -EAGAIN;
			goto abort;
		}

		memset(&pfd, 0, sizeof(pfd));
		pfd.fd = info.fd;
		if ((info.flags & WEBCLIENT_POLL_INFO_WANT_READ) != 0) {
			pfd.events |= POLLIN;
		}

		if ((info.flags & WEBCLIENT_POLL_INFO_WANT_WRITE) != 0) {
			pfd.events |= POLLOUT;
		}

		/* Abort the connection if we just timed out */
		xpthread_mutex_lock(&g_connections_state.lock);
		bool connected = g_connections_state.connected;
		xpthread_mutex_unlock(&g_connections_state.lock);

		if (!connected) {
			xlog_info("connections_webclient_perform aborted due "
				  "to network down");
			ret = -ENETDOWN;
			goto abort;
		}

		if (gettime_ms() >
		    arg.last_data_time + ctx->timeout_sec * 1000) {
			xlog_info("connections_webclient_perform aborted due "
				  "to %u seconds timeout",
				  ctx->timeout_sec);
			ret = -ETIMEDOUT;
			goto abort;
		}

		ret = poll(&pfd, 1, 1000); /* 1 second timeout should be ok */
		if (ret == -1) {
			goto abort;
		} else {
			goto perform_again;
		}
	} else {
		goto finish;
	}

abort:
	webclient_abort(ctx);

finish:
	xpthread_mutex_lock(&g_connections_state.lock);
	g_connections_state.count--;
	xpthread_mutex_unlock(&g_connections_state.lock);
	return ret;
}

unsigned int
connections_get_count(void)
{
	unsigned int ret;
	xpthread_mutex_lock(&g_connections_state.lock);
	ret = g_connections_state.count;
	xpthread_mutex_unlock(&g_connections_state.lock);
	return ret;
}
