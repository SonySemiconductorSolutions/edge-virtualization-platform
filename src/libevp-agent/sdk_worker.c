/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sys/socket.h>

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#include "sdk_agent.h"
#include "sdk_impl.h"
#include "sdk_worker.h"
#include "sdkrpc/server.h"
#include "xlog.h"

static int
sdk_socket_accept(struct sdk_socket_context *ctx)
{
	int lfd = ctx->listen_fd;
	int fd;
	int ret;
	fd = accept(lfd, NULL, 0);
	if (fd == -1) {
		return errno;
	}
	/*
	 * for now, don't bother to fork for each clients.
	 */
	struct sdk_server svr0;
	struct sdk_server *svr = &svr0;
	sdk_svr_setup(svr, fd);
	while ((ret = sdk_svr_process(svr, sdk_process_request,
				      ctx->sdk_handle)) == 0) {
		/* nothing */
#if defined(SDK_LOG_VERBOSE)
		xlog_debug("sdk_svr_process succeed");
#endif
	}
	xlog_warning("sdk_svr_process failed with %d", ret);
	close(fd);
	sdk_clear_events(ctx->sdk_handle);
	return 0;
}

void *
sdk_socket_thread(void *vp)
{
	struct sdk_socket_context *ctx = vp;
	int ret;

	while ((ret = sdk_socket_accept(ctx)) == 0) {
		/* nothing */
	}
	xlog_error("sdk_socket_accept failed with %d", ret);
	/* XXX what to do? */
	return NULL;
}
