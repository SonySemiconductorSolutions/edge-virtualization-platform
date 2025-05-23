/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <malloc.h>

#include <internal/util.h>

#include "webclient/webclient.h"

#include "agent_test.h"
#include "hub.h"
#include "xlog.h"

#define HTTP_STATUS_OK 200

__attribute__((weak)) int
__wrap_webclient_perform(FAR struct webclient_context *ctx)
{
	char *str;
	xasprintf(&str, "%s %s", ctx->method, ctx->url);
	agent_write_to_pipe(str);
	free(str);
	for (size_t i = 0; i < ctx->nheaders; ++i) {
		agent_write_to_pipe(ctx->headers[i]);
	}
	ctx->http_status = HTTP_STATUS_OK;
	return 0;
}
