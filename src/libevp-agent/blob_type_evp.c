/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>

#include "blob.h"
#include "blob_http.h"
#include "blob_type_evp.h"
#include "https_ssl_config.h"

#if 0
/* Not supported yet for mSTP */
static unsigned int
blob_type_evp_http_get(struct blob_work *wk, int fd)
{
	return blob_http_get(wk, fd, wk->headers, wk->nheaders,
			     https_ssl_config());
}
#endif

static unsigned int
blob_type_evp_http_put(struct blob_work *wk, int fd)
{
	unsigned int resp;
	resp = blob_http_put(wk, fd, wk->headers, wk->nheaders,
			     https_ssl_config());
	return resp;
}

unsigned int
blob_type_evp_get(struct blob_work *wk)
{
#if 0 /* notyet */
	return blob_get(wk, blob_type_evp_http_get);
#else
	/* TODO For now, GET is not supported by EVP */
	wk->error = ENOTSUP;
	return BLOB_RESULT_ERROR;
#endif
}

unsigned int
blob_type_evp_put(struct blob_work *wk)
{
	return blob_put(wk, blob_type_evp_http_put);
}
