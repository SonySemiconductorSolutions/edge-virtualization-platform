/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "pal.h"
#include "xlog.h"

int
pal_connect(struct pal_socket *socket, const char *host, const char *port,
	    unsigned int flags, void *conf)
{
	switch (socket->type) {
	case PAL_TYPE_MBEDTLS:
		return tls_connect(&socket->socket.tls, conf, host, port,
				   flags);
	case PAL_TYPE_TCP:
		return tcp_connect_socket(&socket->socket.tcp, host, port,
					  flags);
	default:
		// TODO: Review exit (xlog_abort)
		//       programming error
		xlog_abort("Invalid state %d", socket->type);
	}
}

int
pal_connect_on_fd(struct pal_socket *socket, const char *host,
		  unsigned int flags, void *conf, int fd)
{
	int ret;
	switch (socket->type) {
	case PAL_TYPE_MBEDTLS:
		socket->socket.tls.net_ctx.fd = fd;
		ret = tls_init_connection(&socket->socket.tls, conf, host,
					  flags);
		if (ret != 0) {
			socket->socket.tls.net_ctx.fd = -1;
		}
		return ret;
	case PAL_TYPE_TCP:
		socket->socket.tcp = fd;
		return 0;
	default:
		// TODO: Review exit (xlog_abort)
		//       programming error
		xlog_abort("Invalid state %d", socket->type);
	}
}

int
pal_prepare_poll(struct pal_socket *socket, bool want_write)
{
	switch (socket->type) {
	case PAL_TYPE_MBEDTLS:
		return tls_prepare_poll(&socket->socket.tls, want_write);
	case PAL_TYPE_TCP:
		return tcp_prepare_poll(socket->socket.tcp, want_write);
	default:
		// TODO: Review exit (xlog_abort)
		//       programming error
		xlog_abort("Invalid state %d", socket->type);
	}
}

void
pal_socket_init(struct pal_socket *socket, void *conf)
{
	int type;

	if (conf == NULL) {
		type = PAL_TYPE_TCP;
	} else {
		type = PAL_TYPE_MBEDTLS;
	}

	socket->type = type;
	switch (type) {
	case PAL_TYPE_MBEDTLS:
		tls_connection_context_init(&socket->socket.tls);
		break;
	case PAL_TYPE_TCP:
		tcp_socket_init(&socket->socket.tcp);
		break;
	default:
		// TODO: Review exit (xlog_abort)
		//       programming error
		xlog_abort("Invalid state %d", type);
	}
}

void
pal_socket_free(struct pal_socket *socket)
{
	switch (socket->type) {
	case PAL_TYPE_MBEDTLS:
		tls_connection_context_free(&socket->socket.tls);
		return;
	case PAL_TYPE_TCP:
		tcp_socket_free(&socket->socket.tcp);
		return;
	default:
		// TODO: Review exit (xlog_abort)
		//       programming error
		xlog_abort("Invalid state %d", socket->type);
	}
}
