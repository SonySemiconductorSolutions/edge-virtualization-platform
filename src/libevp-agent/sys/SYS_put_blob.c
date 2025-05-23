/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <string.h>

#include <evp/sdk.h>
#include <evp/sdk_sys.h>

#include <internal/chan.h>

#include "../sdk_impl.h"
#include "../xlog.h"
#include "evp/sdk_blob.h"
#include "sys.h"
#include "sys_common.h"

struct blob_cb {
	struct SYS_client *c;
	SYS_blob_cb cb;
	void *user;
	char *url;
	void *req;
};

static void *
create_request(const char *url, const struct SYS_http_header *headers)
{
	struct EVP_BlobRequestHttpExt *ret;

	if ((ret = EVP_BlobRequestHttpExt_initialize()) == NULL) {
		return NULL;
	}

	if (sys_add_headers(ret, headers)) {
		goto failure;
	}

	if (EVP_BlobRequestHttpExt_setUrl(ret, (char *)url) != EVP_OK) {
		goto failure;
	}

	return ret;

failure:
	EVP_BlobRequestHttpExt_free(ret);
	return NULL;
}

static void
blob_cb(EVP_BLOB_CALLBACK_REASON reason, const void *result, void *userData)
{
	const struct EVP_BlobResultHttpExt *http = result;
	struct blob_cb *d = userData;
	struct SYS_blob_data bd = {
		.method = "PUT",
		.error = http->error,
		.status_code = http->http_status,
		.url = d->url,
	};

	enum SYS_result r = d->cb(d->c, &bd, SYS_REASON_FINISHED, d->user);

	if (r != SYS_RESULT_OK) {
		xlog_error("user blob callback failed with %s",
			   SYS_result_tostr(r));
	}

	EVP_BlobRequestHttpExt_free(d->req);
	free(d->url);
	free(d);
}

static EVP_BLOB_IO_RESULT
io_cb(void *buf, size_t buflen, void *userData)
{
	enum SYS_result result;
	struct blob_cb *d = userData;
	struct SYS_blob_data bd = {
		.blob_buffer = buf,
		.len = buflen,
		.method = "PUT",
		.url = d->url,
	};

	result = d->cb(d->c, &bd, SYS_REASON_MORE_DATA, d->user);

	return result == SYS_RESULT_OK ? EVP_BLOB_IO_RESULT_SUCCESS
				       : EVP_BLOB_IO_RESULT_ERROR;
}

enum SYS_result
SYS_put_blob(struct SYS_client *c, const char *url,
	     const struct SYS_http_header *headers, unsigned long long datalen,
	     SYS_blob_cb cb, void *user)
{
	enum SYS_result ret;
	void *req = NULL;
	char *urldup = NULL;
	struct blob_cb *data = NULL;

	if (!strncmp(url, "http://", strlen("http://")) ||
	    !strncmp(url, "https://", strlen("https://"))) {
		if ((req = create_request(url, headers)) == NULL) {
			ret = SYS_RESULT_ERROR_NO_MEM;
			goto err;
		}

	} else {
		ret = SYS_RESULT_ERROR_BAD_PARAMS;
		goto err;
	}

	if ((urldup = strdup(url)) == NULL) {
		ret = SYS_RESULT_ERROR_NO_MEM;
		goto err;
	}

	if ((data = malloc(sizeof(*data))) == NULL) {
		ret = SYS_RESULT_ERROR_NO_MEM;
		goto err;
	}

	*data = (struct blob_cb){
		.c = c,
		.cb = cb,
		.user = user,
		.url = urldup,
		.req = req,
	};

	struct EVP_BlobLocalStore store = {
		.io_cb = io_cb,
		.blob_len = datalen,
	};

	EVP_RESULT result = EVP_impl_blobOperation(
		c->h, NULL, EVP_BLOB_TYPE_HTTP_EXT, EVP_BLOB_OP_PUT, req,
		&store, blob_cb, data);

	if (result == EVP_OK) {
		return SYS_RESULT_OK;
	}

	ret = sys_to_sys_result(result);

err:
	if (req)
		EVP_BlobRequestHttpExt_free(req);

	free(urldup);
	free(data);
	return ret;
}
