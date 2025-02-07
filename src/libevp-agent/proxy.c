/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Tunnel through web proxy server
 *
 * https://datatracker.ietf.org/doc/html/draft-luotonen-web-proxy-tunneling-01
 */

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <internal/util.h>

#include "webclient/webclient.h"

#include "base64.h"
#include "connections.h"
#include "proxy.h"
#include "xlog.h"

int
compose_proxy_auth_header(char **header, const char *user)
{
	char *proxy_auth_header;
	char *proxy_user_base64;
	size_t proxy_user_base64_len;
	int ret;

	ret = base64_encode(user, strlen(user), &proxy_user_base64,
			    &proxy_user_base64_len);
	if (ret != 0) {
		return ret;
	}
	xasprintf(&proxy_auth_header, "Proxy-Authorization: Basic %s",
		  proxy_user_base64);
	free(proxy_user_base64);
	*header = proxy_auth_header;
	return 0;
}

int
tunnel_over_proxy(const char *proxy, const char *proxy_user,
		  const char *target_host, const char *target_port, int *fdp)
{
	struct webclient_context ctx0;
	struct webclient_context *ctx = &ctx0;
	struct webclient_conn_s *conn;
	char *proxy_auth_header = NULL;
	intmax_t target_port_int;
	const size_t buflen = 1024;
	int ret;

	ret = string_to_int(target_port, &target_port_int);
	if (ret == 0) {
		if (target_port_int > 65535 || target_port_int < 0) {
			ret = E2BIG;
		}
	}
	if (ret != 0) {
		xlog_error("target port '%s' is not a valid port number",
			   target_port);
		return ret;
	}

	webclient_set_defaults(ctx);
	ctx->method = "CONNECT";
	ctx->flags = WEBCLIENT_FLAG_TUNNEL;
	ctx->proxy = proxy;
	if (proxy_user != NULL) {
		ret = compose_proxy_auth_header(&proxy_auth_header,
						proxy_user);
		if (ret != 0) {
			return ret;
		}
		ctx->proxy_headers = (const char **)&proxy_auth_header;
		ctx->proxy_nheaders = 1;
	}
	ctx->tunnel_target_host = target_host;
	ctx->tunnel_target_port = (uint16_t)target_port_int;
	ctx->buffer = xmalloc(buflen);
	ctx->buflen = buflen;
	ret = connections_webclient_perform(ctx);
	free(ctx->buffer);
	free(proxy_auth_header);
	if (ret != 0) {
		xlog_error("tunnelling failed with errno %d", -ret);
		return -ret;
	}
	if (ctx->http_status / 100 != 2) {
		xlog_error("tunnelling failed with HTTP status %u",
			   ctx->http_status);
		return EIO;
	}
	webclient_get_tunnel(ctx, &conn);
	// TODO: Replace assert (runtime error)
	assert(!conn->tls);
	*fdp = conn->sockfd;
	webclient_conn_free(conn);
	return 0;
}
