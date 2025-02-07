/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sys/types.h>

#include <stdbool.h>

#include "mqtt_custom.h"
#include "mqtt_pal/mbedtls.h"
#include "mqtt_pal/tcp.h"
#include "pal.h"
#include "xlog.h"

ssize_t
mqtt_pal_sendall(mqtt_pal_socket_handle h, const void *buf, size_t len,
		 int flags)
{
	switch (h->type) {
	case PAL_TYPE_MBEDTLS:
		return mqtt_pal_mbedtls_sendall(&h->socket.tls.ssl_ctx, buf,
						len, flags);
	case PAL_TYPE_TCP:
		return mqtt_pal_tcp_sendall(h->socket.tcp, buf, len, flags);
	default:
		// TODO: Review exit (xlog_abort)
		//       programming error
		xlog_abort("Invalid state %d", h->type);
	}
}

ssize_t
mqtt_pal_recvall(mqtt_pal_socket_handle h, void *buf, size_t bufsz, int flags)
{
	switch (h->type) {
	case PAL_TYPE_MBEDTLS:
		return mqtt_pal_mbedtls_recvall(&h->socket.tls.ssl_ctx, buf,
						bufsz, flags);
	case PAL_TYPE_TCP:
		return mqtt_pal_tcp_recvall(h->socket.tcp, buf, bufsz, flags);
	default:
		// TODO: Review exit (xlog_abort)
		//       programming error
		xlog_abort("Invalid state %d", h->type);
	}
}
