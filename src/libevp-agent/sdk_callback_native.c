/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <config.h>

#include <errno.h>

#include "sdk_callback_impl_ops.h"

SDK_CALLBACK_IMPL_OPS_DECLARE_FUNCTIONS(native);
SDK_CALLBACK_IMPL_OPS_DEFINE(native);

void
sdk_callback_impl_native_invoke_config_callback(void *ctx,
						EVP_CONFIGURATION_CALLBACK cb,
						const char *topic,
						const void *blob,
						size_t bloblen, void *userdata)
{
	cb(topic, blob, bloblen, userdata);
}

void
sdk_callback_impl_native_invoke_state_callback(
	void *ctx, EVP_STATE_CALLBACK cb, EVP_STATE_CALLBACK_REASON reason,
	void *userdata)
{
	cb(reason, userdata);
}

void
sdk_callback_impl_native_invoke_blob_callback(void *ctx, EVP_BLOB_CALLBACK cb,
					      EVP_BLOB_CALLBACK_REASON reason,
					      const void *result,
					      void *userdata)
{
	cb(reason, result, userdata);
}

void
sdk_callback_impl_native_invoke_message_sent_callback(
	void *ctx, EVP_MESSAGE_SENT_CALLBACK cb,
	EVP_MESSAGE_SENT_CALLBACK_REASON reason, void *userdata)
{
	cb(reason, userdata);
}

void
sdk_callback_impl_native_invoke_message_received_callback(
	void *ctx, EVP_MESSAGE_RECEIVED_CALLBACK cb, const char *topic,
	const void *msg_payload, size_t msg_payload_len, void *userdata)
{
	cb(topic, msg_payload, msg_payload_len, userdata);
}

void
sdk_callback_impl_native_invoke_telemetry_callback(
	void *ctx, EVP_TELEMETRY_CALLBACK cb,
	EVP_TELEMETRY_CALLBACK_REASON reason, void *userdata)
{
	cb(reason, userdata);
}

void
sdk_callback_impl_native_invoke_rpc_request_callback(
	void *ctx, EVP_RPC_REQUEST_CALLBACK cb, EVP_RPC_ID id,
	const char *method_name, const char *params, void *userdata)
{
	cb(id, method_name, params, userdata);
}

void
sdk_callback_impl_native_invoke_rpc_response_callback(
	void *ctx, EVP_RPC_RESPONSE_CALLBACK cb,
	EVP_RPC_RESPONSE_CALLBACK_REASON reason, void *userdata)
{
	cb(reason, userdata);
}

void
sdk_callback_impl_native_invoke_stream_read_available_callback(
	void *ctx, EVP_STREAM_READ_CALLBACK cb, EVP_STREAM_PEER_ID id,
	const void *buf, size_t n, void *userdata)
{
	cb(id, buf, n, userdata);
}

void
sdk_callback_impl_native_invoke_blob_get_upload_url_callback(
	void *ctx, EVP_BLOB_CALLBACK cb, EVP_BLOB_CALLBACK_REASON reason,
	const char *uploadUrl, void *userdata)
{
	cb(reason, uploadUrl, userdata);
}

EVP_BLOB_IO_RESULT
sdk_callback_impl_native_invoke_blob_io_read_callback(void *ctx,
						      EVP_BLOB_IO_CALLBACK cb,
						      void *buf, size_t buflen,
						      void *userData,
						      int *out_errno)
{
	EVP_BLOB_IO_RESULT error = cb(buf, buflen, userData);

	if (error) {
		*out_errno = ECANCELED;
	}

	return error;
}

EVP_BLOB_IO_RESULT
sdk_callback_impl_native_invoke_blob_io_write_callback(
	void *ctx, EVP_BLOB_IO_CALLBACK cb, const void *buf, size_t buflen,
	void *userData, int *out_errno)
{
	/* TODO: EVP_BLOB_IO_CALLBACK is not const-correct. */
	EVP_BLOB_IO_RESULT error = cb((void *)buf, buflen, userData);

	if (error) {
		*out_errno = ECANCELED;
	}

	return error;
}
