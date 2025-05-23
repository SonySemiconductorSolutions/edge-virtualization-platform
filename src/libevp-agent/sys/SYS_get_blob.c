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
#include "sys.h"
#include "sys_common.h"

struct blob_cb {
	struct SYS_client *c;
	SYS_blob_cb cb;
	void *user;
	char *url;
	EVP_BLOB_TYPE type;
	void *req;
};

static void *
create_http_request(const char *url, const struct SYS_http_header *headers)
{
	struct EVP_BlobRequestHttpExt *ret;

	if ((ret = EVP_BlobRequestHttpExt_initialize()) == NULL) {
		return NULL;
	}

	if (sys_add_headers(ret, headers)) {
		goto failure;
	}

	/* EVP_BlobRequestHttpExt_setUrl is not const-correct. */
	if (EVP_BlobRequestHttpExt_setUrl(ret, (char *)url) != EVP_OK) {
		goto failure;
	}

	return ret;

failure:
	EVP_BlobRequestHttpExt_free(ret);
	return NULL;
}

static int
set_blob_data(struct SYS_blob_data *bd, const struct blob_cb *data,
	      const void *result)
{
	switch (data->type) {
	case EVP_BLOB_TYPE_HTTP_EXT:
		{
			const struct EVP_BlobResultHttpExt *http = result;

			*bd = (struct SYS_blob_data){
				.method = "GET",
				.error = http->error,
				.status_code = http->http_status,
				.url = data->url,
				/* .response_headers? */
			};
		}
		break;

	default:
		/* Unexpected data type. */
		return -1;
	}

	return 0;
}

static void
free_request(void *req, EVP_BLOB_TYPE type)
{
	switch (type) {
	case EVP_BLOB_TYPE_HTTP_EXT:
		EVP_BlobRequestHttpExt_free(req);
		break;

	default:
		break;
	}
}

static void
blob_cb(EVP_BLOB_CALLBACK_REASON reason, const void *result, void *userData)
{
	struct blob_cb *d = userData;
	struct SYS_blob_data bd;

	if (set_blob_data(&bd, d, result)) {
		xlog_error("failed to set blob data");
		return;
	}

	enum SYS_result r = d->cb(d->c, &bd, SYS_REASON_FINISHED, d->user);

	if (r != SYS_RESULT_OK) {
		xlog_error("user blob callback failed with %s",
			   SYS_result_tostr(r));
	}

	free_request(d->req, d->type);
	free(d->url);
	free(d);
}

static EVP_BLOB_IO_RESULT
to_io_result(enum SYS_result result)
{
	return result == SYS_RESULT_OK ? EVP_BLOB_IO_RESULT_SUCCESS
				       : EVP_BLOB_IO_RESULT_ERROR;
}

static EVP_BLOB_IO_RESULT
io_cb(void *buf, size_t buflen, void *userData)
{
	enum SYS_result result;
	struct blob_cb *d = userData;
	struct SYS_blob_data bd = {
		.blob_buffer = buf,
		.len = buflen,
		.method = "GET",
		.url = d->url,
		/* response_headers and status_code cannot be retrieved here.
		 */
	};

	result = d->cb(d->c, &bd, SYS_REASON_MORE_DATA, d->user);
	return to_io_result(result);
}

enum SYS_result
SYS_get_blob(struct SYS_client *c, const char *url,
	     const struct SYS_http_header *headers, SYS_blob_cb cb, void *user)
{
	enum SYS_result ret;
	char *urldup = NULL;
	void *req = NULL;
	EVP_BLOB_TYPE type;
	struct blob_cb *data = NULL;

	if (!strncmp(url, "http://", strlen("http://")) ||
	    !strncmp(url, "https://", strlen("https://"))) {
		if ((req = create_http_request(url, headers)) == NULL) {
			ret = SYS_RESULT_ERROR_NO_MEM;
			goto failure;
		}

		type = EVP_BLOB_TYPE_HTTP_EXT;
	} else {
		ret = SYS_RESULT_ERROR_BAD_PARAMS;
		goto failure;
	}

	if ((urldup = strdup(url)) == NULL) {
		ret = SYS_RESULT_ERROR_NO_MEM;
		goto failure;
	}

	if ((data = malloc(sizeof(*data))) == NULL) {
		ret = SYS_RESULT_ERROR_NO_MEM;
		goto failure;
	}

	*data = (struct blob_cb){
		.c = c,
		.cb = cb,
		.type = type,
		.user = user,
		.url = urldup,
		.req = req,
	};

	struct EVP_BlobLocalStore store = {
		.io_cb = io_cb,
	};

	EVP_RESULT result = EVP_impl_blobOperation(
		c->h, NULL, type, EVP_BLOB_OP_GET, req, &store, blob_cb, data);

	if (result != EVP_OK) {
		ret = sys_to_sys_result(result);
		goto failure;
	}

	return SYS_RESULT_OK;

failure:
	if (req)
		free_request(req, type);

	free(urldup);
	free(data);
	return ret;
}
