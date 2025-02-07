/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE
#include <config.h>

#include <assert.h>
#include <errno.h>
#include <semaphore.h>
#include <stdlib.h>
#include <string.h>

#include "blob.h"
#include "evp/sdk.h"
#include "evp/sdk_blob_http_ext.h"
#include "sdk_callback_impl_ops.h"
#include "sdk_common.h"
#include "sdk_impl.h"
#include "xlog.h"

EVP_RESULT
sdk_execute_get_upload_url(struct sdk_event_blob *blob,
			   const struct sdk_callback_impl_ops *ops, void *ctx)
{
	struct blob_work *wk = blob->work;
	assert(blob->owner == NULL);
	if (blob->reason == EVP_BLOB_CALLBACK_REASON_DONE) {
		assert(wk != NULL);
		assert(wk->user == blob);
		assert(wk->type == BLOB_TYPE_EVP_EXT);
		ops->invoke_blob_get_upload_url_callback(
			ctx, blob->user_cb.cb, blob->reason, wk->url,
			blob->user_cb.cb_data);
	} else {
		ops->invoke_blob_get_upload_url_callback(
			ctx, blob->user_cb.cb, blob->reason, NULL,
			blob->user_cb.cb_data);
	}
	return EVP_OK;
}

EVP_RESULT
sdk_execute_event_blob(struct sdk_event_blob *blob,
		       const struct sdk_callback_impl_ops *ops, void *ctx)
{

	struct blob_work *wk = blob->work;
	// TODO: Replace assert (programming error)
	assert(blob->owner == NULL);
	if (blob->reason == EVP_BLOB_CALLBACK_REASON_DONE ||
	    blob->reason == EVP_BLOB_CALLBACK_REASON_DENIED) {
		// TODO: Replace assert (programming error)
		assert(wk != NULL);
		// TODO: Replace assert (programming error)
		assert(wk->user == blob);
		assert(wk->type == BLOB_TYPE_AZURE_BLOB ||
		       wk->type == BLOB_TYPE_HTTP ||
		       wk->type == BLOB_TYPE_EVP_EXT ||
		       wk->type == BLOB_TYPE_HTTP_EXT);
		struct EVP_BlobResultAzureBlob result;
		memset(&result, 0, sizeof(result));
		result.result = (EVP_BLOB_RESULT)wk->result;
		result.error = wk->error;
		result.http_status = wk->http_status;
		ops->invoke_blob_callback(ctx, blob->user_cb.cb, blob->reason,
					  &result, blob->user_cb.cb_data);
	} else {
		assert(blob->reason == EVP_BLOB_CALLBACK_REASON_EXIT);
		// TODO: Replace assert (programming error)
		assert(wk == NULL);
		ops->invoke_blob_callback(ctx, blob->user_cb.cb, blob->reason,
					  NULL, blob->user_cb.cb_data);
	}
	return EVP_OK;
}

EVP_RESULT
sdk_execute_blob_io_read(struct sdk_event_blob_io *io,
			 const struct sdk_callback_impl_ops *ops, void *ctx)
{
	int out_errno;
	EVP_BLOB_IO_RESULT result = ops->invoke_blob_io_read_callback(
		ctx, io->cb, io->buf.rw, io->n, io->cb_data, &out_errno);

	*io->out_errno = result != EVP_BLOB_IO_RESULT_SUCCESS ? out_errno : 0;

	if (sem_post(io->sem)) {
		xlog_error("sem_post failed with errno %d", errno);
		return EVP_ERROR;
	}

	return EVP_OK;
}

EVP_RESULT
sdk_execute_blob_io_write(struct sdk_event_blob_io *io,
			  const struct sdk_callback_impl_ops *ops, void *ctx)
{
	int out_errno;
	EVP_BLOB_IO_RESULT result = ops->invoke_blob_io_write_callback(
		ctx, io->cb, io->buf.ro, io->n, io->cb_data, &out_errno);

	*io->out_errno = result != EVP_BLOB_IO_RESULT_SUCCESS ? out_errno : 0;

	if (sem_post(io->sem)) {
		xlog_error("sem_post failed with errno %d", errno);
		return EVP_ERROR;
	}

	return EVP_OK;
}
