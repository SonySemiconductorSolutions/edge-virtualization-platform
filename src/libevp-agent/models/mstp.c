/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stdlib.h>

#include <parson.h>

#include <internal/util.h>

#include "../hub.h"
#include "../models/mstp.h"

void
storagetoken_response_ctor(struct storagetoken_response *data, int status,
			   const char *error, const char *url,
			   uint64_t expiration_ms,
			   enum storagetoken_response_type resp_type)
{
	*data = (struct storagetoken_response){
		.status = status,
		.error = error ? xstrdup(error) : NULL,
		.url = url ? xstrdup(url) : NULL,
		.headers = xmalloc(sizeof(char *) * 4),
		.expiration_ms = expiration_ms,
		.resp_type = resp_type,
	};
}

void
storagetoken_response_dtor(struct storagetoken_response *data)
{
	free(data->url);
	for (unsigned int i = 0; i < data->headers_len; i++) {
		free(data->headers[i]);
	}
	free(data->headers);
	free(data->error);
}

int
storagetoken_response_add_header(struct storagetoken_response *data,
				 const char *name, const char *value)
{
	char **headers = xrealloc(data->headers,
				  sizeof(char *) * (data->headers_len + 1));
	if (!headers)
		return -ENOMEM;

	data->headers = headers;

	char *header;
	xasprintf(&header, "%s: %s", name, value);
	data->headers[data->headers_len++] = header;
	return 0;
}
