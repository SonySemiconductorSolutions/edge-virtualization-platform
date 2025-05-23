/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sys/stat.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "webclient/webclient.h"

#include "blob.h"
#include "blob_http.h"
#include "connections.h"
#include "proxy.h"
#include "webclient_mbedtls.h"

unsigned int
blob_http_get(struct blob_work *wk, int fd, const char *const *headers,
	      unsigned int nheaders, struct mbedtls_ssl_config *ssl_conf)
{
	struct webclient_context ctx;
	char *proxy_auth_header = NULL;
	char reason[256];
	int ret;

	struct webclient_mbedtls_param tls_param = {
		.agent = wk->agent,
		.nonblocking = true,
		.ssl_config = ssl_conf,
	};

	if (wk->buffer == NULL || wk->buffer_size == 0) {
		ret = EINVAL;
		goto fail_with_errno;
	}

	webclient_set_defaults(&ctx);
	ctx.protocol_version = WEBCLIENT_PROTOCOL_VERSION_HTTP_1_1;
	ctx.url = wk->url;
	ctx.headers = headers;
	ctx.nheaders = nheaders;
	ctx.buffer = wk->buffer;
	ctx.buflen = wk->buffer_size;
	if (fd != -1) {
		ctx.sink_callback = blob_file_write_func;
		ctx.sink_callback_arg = &fd;
	} else if (wk->webclient_sink_callback != NULL) {
		ctx.sink_callback = wk->webclient_sink_callback;
		ctx.sink_callback_arg = wk->webclient_sink_callback_arg;
	} else {
		ret = EINVAL;
		goto fail_with_errno;
	}
	ctx.tls_ops = &mbedtls_tls_ops;
	ctx.tls_ctx = &tls_param;
	ctx.http_reason = reason;
	ctx.http_reason_len = sizeof(reason);
	ctx.proxy = wk->proxy;
	if (wk->proxy_user != NULL) {
		ret = compose_proxy_auth_header(&proxy_auth_header,
						wk->proxy_user);
		if (ret != 0) {
			goto fail_with_errno;
		}
		ctx.proxy_headers = (const char **)&proxy_auth_header;
		ctx.proxy_nheaders = 1;
	}
	ret = connections_webclient_perform(&ctx);
	free(proxy_auth_header);
	if (ret != 0) {
		goto fail_with_negative_errno;
	}
	wk->http_status = ctx.http_status;
	if ((ctx.http_status / 100) != 2) {
		goto fail_with_http;
	}
	return BLOB_RESULT_SUCCESS;
fail_with_negative_errno:
	ret = -ret;
fail_with_errno:
	wk->error = ret;
	return BLOB_RESULT_ERROR;
fail_with_http:
	/* XXX return ctx.http_reason as well */
	return BLOB_RESULT_ERROR_HTTP;
}

unsigned int
blob_http_put(struct blob_work *wk, int fd, const char *const *headers,
	      unsigned int nheaders, struct mbedtls_ssl_config *ssl_conf)
{
	struct webclient_context ctx;
	char *proxy_auth_header = NULL;
	char reason[100];
	int ret;

	struct webclient_mbedtls_param tls_param = {
		.agent = wk->agent,
		.nonblocking = true,
		.ssl_config = ssl_conf,
	};

	if (wk->buffer == NULL || wk->buffer_size == 0) {
		ret = EINVAL;
		goto fail_with_errno;
	}

	webclient_set_defaults(&ctx);
	ctx.protocol_version = WEBCLIENT_PROTOCOL_VERSION_HTTP_1_1;
	ctx.method = "PUT";
	ctx.url = wk->url;
	ctx.headers = headers;
	ctx.nheaders = nheaders;
	ctx.buffer = wk->buffer;
	ctx.buflen = wk->buffer_size;

	if (fd != -1) {
		struct stat st;
		ret = fstat(fd, &st);
		if (ret == -1) {
			ret = errno;
			goto fail_with_errno;
		}
		ctx.body_callback = blob_file_read_func;
		ctx.body_callback_arg = &fd;
		ctx.bodylen = st.st_size;
	} else if (wk->webclient_body_callback != NULL) {
		ctx.body_callback = wk->webclient_body_callback;
		ctx.body_callback_arg = wk->webclient_body_callback_arg;
		ctx.bodylen = wk->blob_len;
	} else {
		ret = EINVAL;
		goto fail_with_errno;
	}

	ctx.sink_callback = blob_noop_write_func;
	ctx.tls_ops = &mbedtls_tls_ops;
	ctx.tls_ctx = &tls_param;
	ctx.http_reason = reason;
	ctx.http_reason_len = sizeof(reason);
	ctx.proxy = wk->proxy;
	if (wk->proxy_user != NULL) {
		ret = compose_proxy_auth_header(&proxy_auth_header,
						wk->proxy_user);
		if (ret != 0) {
			goto fail_with_errno;
		}
		ctx.proxy_headers = (const char **)&proxy_auth_header;
		ctx.proxy_nheaders = 1;
	}
	ret = connections_webclient_perform(&ctx);
	free(proxy_auth_header);
	if (ret != 0) {
		goto fail_with_negative_errno;
	}
	wk->http_status = ctx.http_status;
	if ((ctx.http_status / 100) != 2) {
		goto fail_with_http;
	}
	return BLOB_RESULT_SUCCESS;
fail_with_negative_errno:
	ret = -ret;
fail_with_errno:
	wk->error = ret;
	return BLOB_RESULT_ERROR;
fail_with_http:
	/* XXX return ctx.http_reason as well */
	return BLOB_RESULT_ERROR_HTTP;
}
