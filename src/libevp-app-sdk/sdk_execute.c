/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE
#include <config.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "blob.h"
#include "evp/sdk.h"
#include "evp/sdk_blob_http_ext.h"
#include "sdk_callback_impl_ops.h"
#include "sdk_common.h"

EVP_RESULT
sdk_execute_get_upload_url(struct sdk_event_blob *event,
			   const struct sdk_callback_impl_ops *ops, void *ctx)
{
	return EVP_NOTSUP;
}

EVP_RESULT
sdk_execute_event_blob(struct sdk_event_blob *blob,
		       const struct sdk_callback_impl_ops *ops, void *ctx)
{

	blob->user_cb.cb(blob->reason, blob->result, blob->user_cb.cb_data);
	return EVP_OK;
}

EVP_RESULT
sdk_execute_blob_io_read(struct sdk_event_blob_io *io,
			 const struct sdk_callback_impl_ops *ops, void *ctx)
{
	return EVP_NOTSUP;
}

EVP_RESULT
sdk_execute_blob_io_write(struct sdk_event_blob_io *io,
			  const struct sdk_callback_impl_ops *ops, void *ctx)
{
	return EVP_NOTSUP;
}
