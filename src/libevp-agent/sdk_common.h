/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if !defined(__SDK_COMMON_H__)
#define __SDK_COMMON_H__

#include "event.h"

struct sdk_common_callbacks {
	EVP_CONFIGURATION_CALLBACK config_cb;
	void *config_cb_userdata;
	EVP_MESSAGE_RECEIVED_CALLBACK in_msg_cb;
	void *in_msg_cb_userdata;
	EVP_RPC_REQUEST_CALLBACK rpc_cb;
	void *rpc_cb_userdata;
};

struct sdk_callback_impl_ops;

EVP_RESULT sdk_common_execute_event(const struct sdk_callback_impl_ops *ops,
				    const struct sdk_common_callbacks *cb,
				    struct sdk_event *event, void *ctx);

EVP_RESULT sdk_execute_get_upload_url(struct sdk_event_blob *blob,
				      const struct sdk_callback_impl_ops *ops,
				      void *ctx);

EVP_RESULT
sdk_execute_event_blob(struct sdk_event_blob *blob,
		       const struct sdk_callback_impl_ops *ops, void *ctx);

EVP_RESULT
sdk_execute_blob_io_read(struct sdk_event_blob_io *io,
			 const struct sdk_callback_impl_ops *ops, void *ctx);

EVP_RESULT
sdk_execute_blob_io_write(struct sdk_event_blob_io *io,
			  const struct sdk_callback_impl_ops *ops, void *ctx);

#endif /* !defined(__SDK_COMMON_H__) */
