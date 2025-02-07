/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sys/socket.h>
#include <sys/types.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "main_loop.h"
#include "socketutil.h"
#include "tcp.h"
#include "xlog.h"

#if !defined(TCP_DEBUG_ADDR_INFO_DISABLE)
#include <arpa/inet.h>
#include <stdio.h>

void
tcp_debug_addr_info_ipv4(char *preamble, const struct sockaddr_in *sin)
{
	char buf[INET_ADDRSTRLEN];
	const char *addr =
		inet_ntop(AF_INET, &sin->sin_addr, buf, INET_ADDRSTRLEN);
	if (!addr) {
		xlog_error("%serror converting IPv4 address: errno=%d",
			   preamble, errno);
		return;
	}
	uint16_t addr_port = ntohs(sin->sin_port);
	xlog_info("%sconnecting to IPv4 %s address, port %hu", preamble, addr,
		  addr_port);
}

void
tcp_debug_addr_info_ipv6(char *preamble, const struct sockaddr_in6 *sin6)
{
	char buf[INET6_ADDRSTRLEN];
	const char *addr =
		inet_ntop(AF_INET6, &sin6->sin6_addr, buf, INET6_ADDRSTRLEN);
	if (!addr) {
		xlog_error("%serror converting IPv6 address: errno=%d",
			   preamble, errno);
		return;
	}
	uint16_t addr_port = ntohs(sin6->sin6_port);
	xlog_info("%sconnecting to IPv6 %s address, port %hu", preamble, addr,
		  addr_port);
}

void
tcp_debug_addr_info(int index, const struct addrinfo *ai)
{
	char preamble[32];

	snprintf(preamble, sizeof(preamble), "address #%i: ", index);

	switch (ai->ai_family) {
	case AF_INET:
		if (ai->ai_addrlen != sizeof(struct sockaddr_in)) {
			xlog_error("%ssocket address length mismatch (IPv4)",
				   preamble);
			return;
		}
		const void *sin = ai->ai_addr;
		tcp_debug_addr_info_ipv4(preamble, sin);
		break;
	case AF_INET6:
		if (ai->ai_addrlen != sizeof(struct sockaddr_in6)) {
			xlog_error("%ssocket address length mismatch (IPv6)",
				   preamble);
			return;
		}
		const void *sin6 = ai->ai_addr;
		tcp_debug_addr_info_ipv6(preamble, sin6);
		break;
	default:
		xlog_error("%sunknown socket address family: %i", preamble,
			   ai->ai_family);
	}
}
#else
inline void
tcp_debug_addr_info(int index, const struct addrinfo *ai)
{
	/* disabled */
}
#endif

int
tcp_connect_socket(int *socketfd, const char *host, const char *port,
		   unsigned int flags)
{
	/* Adapted from client program example in `getaddrinfo` manual */

	struct addrinfo hints;
	struct addrinfo *result;
	const struct addrinfo *ai;
	int sfd = -1;
	int ret;

	/* Obtain address(es) matching host/port */

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_flags =
		AI_ADDRCONFIG; /* Only results for configured IP versions */
	hints.ai_family = AF_UNSPEC;     /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_STREAM; /* Stream socket (~TCP) */
	hints.ai_protocol = 0;           /* Any protocol */
	/* REVISIT: restrict to TCP? (`hints.ai_protocol = 6;`) */

	ret = getaddrinfo(host, port, &hints, &result);
	if (ret != 0) {
		xlog_error("getaddrinfo failed with 0x%x: %s",
			   (unsigned int)ret, gai_strerror(ret));
		return -1;
	}

	/* getaddrinfo() returns a list of address structures.
	   Try each address until we successfully connect(2).
	   If socket(2) (or connect(2)) fails, we (close the socket
	   and) try the next address. */
	int i = 0;
	for (ai = result; ai != NULL; ai = ai->ai_next, i++) {
		tcp_debug_addr_info(i, ai);
		sfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (sfd == -1) {
			xlog_error("socket call for address #%i failed "
				   "(domain=%i, type=%i, protocol=%i): "
				   "errno=%i, strerror='%s'",
				   i, ai->ai_family, ai->ai_socktype,
				   ai->ai_protocol, errno, strerror(errno));
			continue;
		}
		ret = connect(sfd, ai->ai_addr, ai->ai_addrlen);
		if (ret == 0) {
			break; /* Success */
		}
		xlog_warning(
			"connect attempt for address #%i failed (family=%i, "
			"type=%i, protocol=%i): errno=%i: strerror='%s'",
			i, ai->ai_family, ai->ai_socktype, ai->ai_protocol,
			errno, strerror(errno));
		close(sfd);
	}

	freeaddrinfo(result); /* No longer needed */

	if (ai == NULL) { /* No address succeeded */
		xlog_error("could not connect");
		return -1;
	}

	xlog_socket_address(sfd);
	if ((flags & TCP_BLOCKING) == 0) {
		ret = fcntl(sfd, F_SETFL, fcntl(sfd, F_GETFL) | O_NONBLOCK);
		if (ret != 0) {
			xlog_error("failed to set non-blocking mode: %s",
				   strerror(errno));
			close(sfd);
			return -1;
		}
	}

	*socketfd = sfd;
	return 0;
}

void
tcp_socket_init(int *socketfd)
{
	// TODO: Replace assert (programming error)
	assert(socketfd);

	*socketfd = -1;
}

void
tcp_socket_free(int *socketfd)
{
	// TODO: Replace assert (programming error)
	assert(socketfd);

	if (*socketfd == -1) {
		return;
	}

	int ret;

	ret = shutdown(*socketfd, SHUT_RDWR);
	if (ret != 0) {
		xlog_error("error on shutdown: errno=%i: strerror='%s'", errno,
			   strerror(errno));
	}

	ret = close(*socketfd);
	if (ret != 0) {
		xlog_error("error on close: errno=%i: strerror='%s'", errno,
			   strerror(errno));
	}
	*socketfd = -1;
}

int
tcp_prepare_poll(int socketfd, bool want_write)
{
	return main_loop_add_fd(socketfd, want_write);
}
