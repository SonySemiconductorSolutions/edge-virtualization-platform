/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stdlib.h>

#include "blob.h"
#include "blob_http.h"
#include "blob_type_http.h"
#include "https_ssl_config.h"

static unsigned int
http_get(struct blob_work *wk, int fd)
{
	return blob_http_get(wk, fd, wk->headers, wk->nheaders,
			     https_ssl_config());
}

unsigned int
blob_type_http_get(struct blob_work *wk)
{
	return blob_get(wk, http_get);
}

static unsigned int
http_put(struct blob_work *wk, int fd)
{
	return blob_http_put(wk, fd, wk->headers, wk->nheaders,
			     https_ssl_config());
}

unsigned int
blob_type_http_put(struct blob_work *wk)
{
	return blob_put(wk, http_put);
}
