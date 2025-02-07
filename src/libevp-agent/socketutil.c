/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sys/socket.h>

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>

#include "socketutil.h"
#include "xlog.h"

static int
format_address(const struct sockaddr *sa, socklen_t slen, char *dest)
{
	char host[NI_MAXHOST];
	char serv[NI_MAXSERV];
	int ret;

	ret = getnameinfo(sa, slen, host, sizeof(host), serv, sizeof(serv),
			  NI_NUMERICHOST | NI_NUMERICSERV);
	if (ret != 0) {
		xlog_error("getnameinfo failed: %s", gai_strerror(ret));
		goto bail;
	}
	snprintf(dest, NI_MAXHOST + NI_MAXSERV, "%s:%s", host, serv);
	return 0;
bail:
	return EINVAL;
}

void
xlog_socket_address(int fd)
{
	struct sockaddr_storage ss;
	struct sockaddr *sa = (void *)&ss;
	socklen_t slen;
	int ret;
	char *local = NULL;
	char *peer = NULL;

	local = malloc(NI_MAXHOST + NI_MAXSERV);
	if (local == NULL) {
		xlog_error("malloc failed with %d in xlog_socket_address",
			   errno);
		goto bail;
	}

	peer = malloc(NI_MAXHOST + NI_MAXSERV);
	if (peer == NULL) {
		xlog_error("malloc failed with %d in xlog_socket_address",
			   errno);
		goto bail;
	}

	slen = sizeof(ss);
	ret = getsockname(fd, sa, &slen);
	if (ret == -1) {
		xlog_error("getsockname on fd %d failed with %d", fd, errno);
		goto bail;
	}
	ret = format_address(sa, slen, local);
	if (ret != 0) {
		goto bail;
	}
	slen = sizeof(ss);
	ret = getpeername(fd, sa, &slen);
	if (ret == -1) {
		xlog_error("getpeername on fd %d failed with %d", fd, errno);
		goto bail;
	}
	ret = format_address(sa, slen, peer);
	if (ret != 0) {
		goto bail;
	}

	xlog_info("socket %d: peer %s local %s", fd, peer, local);

bail:
	free(local);
	free(peer);
}
