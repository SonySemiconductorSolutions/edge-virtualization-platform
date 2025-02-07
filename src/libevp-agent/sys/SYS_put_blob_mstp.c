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
#include "evp/sdk_blob_evp.h"
#include "sys.h"
#include "sys_common.h"

struct blob_cb {
	struct SYS_client *c;
	SYS_blob_cb cb;
	void *user;
	struct EVP_BlobRequestEvpExt *req;
	char *filename, *storage_name;
};

static void
blob_cb(EVP_BLOB_CALLBACK_REASON reason, const void *result, void *userData)
{
	const struct EVP_BlobResultEvp *evp = result;
	struct blob_cb *d = userData;
	struct SYS_blob_data bd = {
		.method = "PUT",
		.error = evp->error,
		.status_code = evp->http_status
		/* url is intentionally left as null. */
	};

	enum SYS_result r = d->cb(d->c, &bd, SYS_REASON_FINISHED, d->user);

	if (r != SYS_RESULT_OK) {
		xlog_error("user blob callback failed with %s",
			   SYS_result_tostr(r));
	}

	free(d->filename);
	free(d->storage_name);
	free(d->req);
	free(d);
}

static EVP_BLOB_IO_RESULT
io_cb(void *buf, size_t buflen, void *userData)
{
	enum SYS_result result;
	struct blob_cb *d = userData;
	struct SYS_blob_data bd = {
		.blob_buffer = buf, .len = buflen, .method = "PUT",
		/* url is intentionally left as null. */
	};

	result = d->cb(d->c, &bd, SYS_REASON_MORE_DATA, d->user);

	return result == SYS_RESULT_OK ? EVP_BLOB_IO_RESULT_SUCCESS
				       : EVP_BLOB_IO_RESULT_ERROR;
}

enum SYS_result
SYS_put_blob_mstp(struct SYS_client *c, const char *storage_name,
		  const char *filename, unsigned long long datalen,
		  SYS_blob_cb cb, void *user)
{
	enum SYS_result ret;
	struct blob_cb *data = NULL;
	char *filenamedup = NULL;
	char *storagenamedup = NULL;
	struct EVP_BlobRequestEvpExt *req = malloc(sizeof(*req));

	if (!req) {
		ret = SYS_RESULT_ERROR_NO_MEM;
		goto err;
	}

	if ((filenamedup = strdup(filename)) == NULL) {
		ret = SYS_RESULT_ERROR_NO_MEM;
		goto err;
	}

	if ((storagenamedup = strdup(storage_name)) == NULL) {
		ret = SYS_RESULT_ERROR_NO_MEM;
		goto err;
	}

	*req = (struct EVP_BlobRequestEvpExt){
		.remote_name = filenamedup,
		.storage_name = storagenamedup,
	};

	if ((data = malloc(sizeof(*data))) == NULL) {
		ret = SYS_RESULT_ERROR_NO_MEM;
		goto err;
	}

	*data = (struct blob_cb){
		.c = c,
		.cb = cb,
		.user = user,
		.req = req,
		.filename = filenamedup,
		.storage_name = storagenamedup,
	};

	struct EVP_BlobLocalStore store = {
		.io_cb = io_cb,
		.blob_len = datalen,
	};

	EVP_RESULT result = EVP_impl_blobOperation(
		c->h, NULL, EVP_BLOB_TYPE_EVP_EXT, EVP_BLOB_OP_PUT, req,
		&store, blob_cb, data);

	if (result == EVP_OK) {
		return SYS_RESULT_OK;
	}

	ret = sys_to_sys_result(result);

err:
	free(filenamedup);
	free(storagenamedup);
	free(req);
	free(data);
	return ret;
}
