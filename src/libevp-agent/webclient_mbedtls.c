/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <evp/agent.h>

#include "webclient/webclient.h"

#include "mbedtls/version.h"
#include "tls.h"
#include "webclient_mbedtls.h"
#include "xlog.h"

#define AZURE_BLOB_WORKAROUND

struct webclient_tls_connection {
	struct tls_connection_context ctx;
	unsigned int flags;

	/*
	 * REVISIT: Probably these _GOT_CLOSE_NOTIFY/_GOT_FATAL_ERROR stuff
	 * is better to be done in a lower layer, probably in mbedtls itself.
	 * That way other (non-webclient) TLS users can get it freely. (good or
	 * bad)
	 */

#define _GOT_CLOSE_NOTIFY 1U
#define _GOT_FATAL_ERROR  2U
#define _WANT_READ        4U
#define _WANT_WRITE       8U
#define _CLOSED_BY_PEER   16U
};

static bool
mbedtls_fatal_error(int rv)
{
	/*
	 * https://github.com/Mbed-TLS/mbedtls/blob/main/include/mbedtls/ssl.h#L5053-L5064
	 *
	 * Note: MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY is not listed in the above
	 * mbedtls doc. But the agent keeps sending data
	 * after receiving a close_notify. It doesn't matter much for our
	 * application (that is, https client) anyway.
	 */

	if (rv >= 0) {
		return false;
	}
	switch (rv) {
	case MBEDTLS_ERR_SSL_WANT_READ:
	case MBEDTLS_ERR_SSL_WANT_WRITE:
#if defined(MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS)
	case MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS:
#endif
#if defined(MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS)
	case MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS:
#endif
	case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
#if defined(MBEDTLS_SSL_SESSION_TICKETS) && MBEDTLS_VERSION_MAJOR == 3
	case MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET:
#endif
		return false;
	default:
		break;
	}
	return true;
}

static void
mbedtls_record_async(struct webclient_tls_connection *conn, int rv)
{
	switch (rv) {
	case MBEDTLS_ERR_SSL_WANT_READ:
		conn->flags |= _WANT_READ;
		break;
	case MBEDTLS_ERR_SSL_WANT_WRITE:
		conn->flags |= _WANT_WRITE;
		break;
	default:
		break;
	}
}

static int
_tls_connect_common(FAR void *ctx, FAR const char *hostname,
		    FAR const char *port, int fd, unsigned int timeout_second,
		    FAR struct webclient_tls_connection **connp)
{
	struct webclient_tls_connection *conn = malloc(sizeof(*conn));
	struct webclient_mbedtls_param *param = ctx;
	int rv;

	if (conn == NULL) {
		return -errno;
	}
	memset(conn, 0, sizeof(*conn));

	tls_connection_context_init(&conn->ctx);

	unsigned int flags = 0;
	if (param->insecure) {
		flags |= TLS_INSECURE;
	}
	if (!param->nonblocking) {
		flags |= TLS_BLOCKING;
	}
	if (fd == -1) {
		rv = tls_connect(&conn->ctx, param->ssl_config, hostname, port,
				 flags);
	} else {
		conn->ctx.net_ctx.fd = fd;
		rv = tls_init_connection(&conn->ctx, param->ssl_config,
					 hostname, flags);
		if (rv != 0) {
			conn->ctx.net_ctx.fd = -1;
		}
	}
	if (rv != 0) {
		tls_connection_context_free(&conn->ctx);
		free(conn);
		return -mbedtls2errno(rv);
	}
	*connp = conn;
	return 0;
}

static int
_tls_connect(FAR void *ctx, FAR const char *hostname, FAR const char *port,
	     unsigned int timeout_second,
	     FAR struct webclient_tls_connection **connp)
{
	return _tls_connect_common(ctx, hostname, port, -1, timeout_second,
				   connp);
}

static ssize_t
_tls_send(FAR void *ctx, FAR struct webclient_tls_connection *conn,
	  FAR const void *buf, size_t len)
{
	ssize_t written_bytes = 0;
	int rv = 0;
	const unsigned char *buf_cpy = buf;

	while (len > 0) {
		if ((conn->flags & _GOT_FATAL_ERROR) != 0) {
			rv = MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
		} else {
			rv = mbedtls_ssl_write(&conn->ctx.ssl_ctx, buf_cpy,
					       len);
			if (mbedtls_fatal_error(rv)) {
				conn->flags |= _GOT_FATAL_ERROR;
			}
			mbedtls_record_async(conn, rv);
		}
		if (rv >= 0) {
			written_bytes += rv;
			buf_cpy += rv;
			len -= rv;
		} else {
			break;
		}
	}
	if (written_bytes > 0) {
		return written_bytes;
	}
	if (rv == MBEDTLS_ERR_SSL_WANT_WRITE) {
		xlog_debug("_tls_send failed with %d, flags=%x", rv,
			   conn->flags);
		return -mbedtls2errno(rv);
	} else if (rv < 0) {
		xlog_error("_tls_send failed with %d, flags=%x", rv,
			   conn->flags);
		if (rv == MBEDTLS_ERR_SSL_TIMEOUT) {
			struct webclient_mbedtls_param *param = ctx;
			if (param->agent) {
				evp_agent_notification_publish(param->agent,
							       "network/error",
							       "ssl_timeout");
			}
		}
		return -mbedtls2errno(rv);
	}
	return rv;
}

static ssize_t
_tls_recv(FAR void *ctx, FAR struct webclient_tls_connection *conn,
	  FAR void *buf, size_t len)
{
	ssize_t read_bytes = 0;
	int rv = 0;
	unsigned char *buf_cpy = buf;

	while (len > 0) {
		if ((conn->flags & _GOT_FATAL_ERROR) != 0) {
			rv = MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
		} else {
			rv = mbedtls_ssl_read(&conn->ctx.ssl_ctx, buf_cpy,
					      len);
#if defined(MBEDTLS_SSL_SESSION_TICKETS) && MBEDTLS_VERSION_MAJOR == 3
			if (rv ==
			    MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) {
				xlog_info("Ignoring new session ticket");
				continue;
			}
#endif
			if (mbedtls_fatal_error(rv)) {
				conn->flags |= _GOT_FATAL_ERROR;
			}
			mbedtls_record_async(conn, rv);
		}
		if (rv > 0) {
			if ((conn->flags & _GOT_CLOSE_NOTIFY) != 0) {
				xlog_warning("user data after a close notify");
				return -EINVAL;
			}
			read_bytes += rv;
			buf_cpy += rv;
			len -= rv;
		} else if (rv == 0) {
			conn->flags |= _CLOSED_BY_PEER;
			if ((conn->flags & _GOT_CLOSE_NOTIFY) == 0) {
				/*
				 * It seems that the peer closed the connection
				 * without sending a close notify.
				 */
				xlog_warning("EOF without a close notify");

				/*
				 * Azure Blob
				 * (https://xxx.blob.core.windows.net)
				 * seems to close TCP without sending us
				 * a close notify.
				 */
#if !defined(AZURE_BLOB_WORKAROUND)
				return -ECONNRESET;
#else
				rv = 0;
#endif
			}
			break;
		} else {
			if (rv == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
				if ((conn->flags & _GOT_CLOSE_NOTIFY) != 0) {
					xlog_warning("Ignoring multiple close "
						     "notify");
				} else {
					xlog_debug("Got a close notify");
					conn->flags |= _GOT_CLOSE_NOTIFY;
				}
				rv = 0;
			}
			break;
		}
	}
	if (read_bytes > 0) {
		return read_bytes;
	}
	if (rv < 0) {
		if (rv == MBEDTLS_ERR_SSL_TIMEOUT) {
			struct webclient_mbedtls_param *param = ctx;
			if (param->agent) {
				evp_agent_notification_publish(param->agent,
							       "network/error",
							       "ssl_timeout");
			}
		}
		return -mbedtls2errno(rv);
	}
	return rv;
}

static int
_tls_close(FAR void *ctx, FAR struct webclient_tls_connection *conn)
{
	if ((conn->flags & _GOT_FATAL_ERROR) == 0
#if defined(__NuttX__)
	    /* Note: NuttX TCP doesn't have half close */
	    && (conn->flags & _CLOSED_BY_PEER) == 0
#endif
	) {
		int rv = mbedtls_ssl_close_notify(&conn->ctx.ssl_ctx);
		if (rv != 0) {
			xlog_warning("failed to send a close notify");
		}
	}
	tls_connection_context_free(&conn->ctx);
	free(conn);
	return 0;
}

static int
_tls_get_poll_info(FAR void *ctx, FAR struct webclient_tls_connection *conn,
		   FAR struct webclient_poll_info *info)
{
	unsigned int flags = conn->flags;
	conn->flags &= ~(_WANT_READ | _WANT_WRITE);
	info->fd = conn->ctx.net_ctx.fd;
	info->flags = 0;
	if ((flags & _WANT_READ) != 0) {
		info->flags |= WEBCLIENT_POLL_INFO_WANT_READ;
	}
	if ((flags & _WANT_WRITE) != 0) {
		info->flags |= WEBCLIENT_POLL_INFO_WANT_WRITE;
	}
	return 0;
}

static int
_tls_init_connection(void *ctx, struct webclient_conn_s *tunnel,
		     const char *hostname, unsigned int timeout_second,
		     FAR struct webclient_tls_connection **connp)
{
	int rv;

	if (tunnel->tls) {
		return -ENOTSUP;
	}
	rv = _tls_connect_common(ctx, hostname, NULL, tunnel->sockfd,
				 timeout_second, connp);
	if (rv == 0) {
		free(tunnel);
	}
	return rv;
}

const struct webclient_tls_ops mbedtls_tls_ops = {
	_tls_connect, _tls_send,          _tls_recv,
	_tls_close,   _tls_get_poll_info, _tls_init_connection,
};
