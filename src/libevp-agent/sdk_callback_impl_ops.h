/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if !defined(__SDK_CALLBACK_H__)
#define __SDK_CALLBACK_H__

#include "evp/sdk.h"

struct sdk_callback_impl_ops {

	void (*invoke_config_callback)(void *ctx,
				       EVP_CONFIGURATION_CALLBACK cb,
				       const char *topic, const void *blob,
				       size_t bloblen, void *userdata);

	void (*invoke_state_callback)(void *ctx, EVP_STATE_CALLBACK cb,
				      EVP_STATE_CALLBACK_REASON reason,
				      void *userdata);

	void (*invoke_blob_callback)(void *ctx, EVP_BLOB_CALLBACK cb,
				     EVP_BLOB_CALLBACK_REASON reason,
				     const void *result, void *userdata);

	void (*invoke_message_sent_callback)(
		void *ctx, EVP_MESSAGE_SENT_CALLBACK cb,
		EVP_MESSAGE_SENT_CALLBACK_REASON reason, void *userdata);

	void (*invoke_message_received_callback)(
		void *ctx, EVP_MESSAGE_RECEIVED_CALLBACK cb, const char *topic,
		const void *msg_payload, size_t msg_payload_len,
		void *userdata);

	void (*invoke_telemetry_callback)(void *ctx, EVP_TELEMETRY_CALLBACK cb,
					  EVP_TELEMETRY_CALLBACK_REASON reason,
					  void *userdata);

	void (*invoke_rpc_request_callback)(
		void *ctx, EVP_RPC_REQUEST_CALLBACK cb, EVP_RPC_ID id,
		const char *method_name, const char *params, void *userdata);

	void (*invoke_rpc_response_callback)(
		void *ctx, EVP_RPC_RESPONSE_CALLBACK cb,
		EVP_RPC_RESPONSE_CALLBACK_REASON reason, void *userdata);

	void (*invoke_stream_read_available_callback)(
		void *ctx, EVP_STREAM_READ_CALLBACK cb, EVP_STREAM_PEER_ID id,
		const void *buf, size_t n, void *userdata);

	void (*invoke_blob_get_upload_url_callback)(
		void *ctx, EVP_BLOB_CALLBACK cb,
		EVP_BLOB_CALLBACK_REASON reason, const char *uploadUrl,
		void *userdata);

	EVP_BLOB_IO_RESULT(*invoke_blob_io_read_callback)
	(void *ctx, EVP_BLOB_IO_CALLBACK cb, void *buf, size_t buflen,
	 void *userData, int *out_errno);

	EVP_BLOB_IO_RESULT(*invoke_blob_io_write_callback)
	(void *ctx, EVP_BLOB_IO_CALLBACK cb, const void *buf, size_t buflen,
	 void *userData, int *out_errno);
};

#define SDK_CALLBACK_IMPL_OPS_DECLARE(name)                                   \
	extern const struct sdk_callback_impl_ops sdk_callback_impl_ops_##name

#define SDK_CALLBACK_IMPL_OPS_DECLARE_FUNCTIONS(name)                          \
	void sdk_callback_impl_##name##_invoke_config_callback(                \
		void *ctx, EVP_CONFIGURATION_CALLBACK cb, const char *topic,   \
		const void *blob, size_t bloblen, void *userdata);             \
	void sdk_callback_impl_##name##_invoke_state_callback(                 \
		void *ctx, EVP_STATE_CALLBACK cb,                              \
		EVP_STATE_CALLBACK_REASON reason, void *userdata);             \
	void sdk_callback_impl_##name##_invoke_blob_callback(                  \
		void *ctx, EVP_BLOB_CALLBACK cb,                               \
		EVP_BLOB_CALLBACK_REASON reason, const void *result,           \
		void *userdata);                                               \
	void sdk_callback_impl_##name##_invoke_message_sent_callback(          \
		void *ctx, EVP_MESSAGE_SENT_CALLBACK cb,                       \
		EVP_MESSAGE_SENT_CALLBACK_REASON reason, void *userdata);      \
	void sdk_callback_impl_##name##_invoke_message_received_callback(      \
		void *ctx, EVP_MESSAGE_RECEIVED_CALLBACK cb,                   \
		const char *topic, const void *msg_payload,                    \
		size_t msg_payload_len, void *userdata);                       \
	void sdk_callback_impl_##name##_invoke_telemetry_callback(             \
		void *ctx, EVP_TELEMETRY_CALLBACK cb,                          \
		EVP_TELEMETRY_CALLBACK_REASON reason, void *userdata);         \
	void sdk_callback_impl_##name##_invoke_rpc_request_callback(           \
		void *ctx, EVP_RPC_REQUEST_CALLBACK cb, EVP_RPC_ID id,         \
		const char *method_name, const char *params, void *userdata);  \
	void sdk_callback_impl_##name##_invoke_rpc_response_callback(          \
		void *ctx, EVP_RPC_RESPONSE_CALLBACK cb,                       \
		EVP_RPC_RESPONSE_CALLBACK_REASON reason, void *userdata);      \
	void sdk_callback_impl_##name##_invoke_stream_read_available_callback( \
		void *ctx, EVP_STREAM_READ_CALLBACK cb,                        \
		EVP_STREAM_PEER_ID id, const void *buf, size_t n,              \
		void *userdata);                                               \
	void sdk_callback_impl_##name##_invoke_blob_get_upload_url_callback(   \
		void *ctx, EVP_BLOB_CALLBACK cb,                               \
		EVP_BLOB_CALLBACK_REASON reason, const char *uploadUrl,        \
		void *userdata);                                               \
	EVP_BLOB_IO_RESULT                                                     \
	sdk_callback_impl_##name##_invoke_blob_io_read_callback(               \
		void *ctx, EVP_BLOB_IO_CALLBACK cb, void *buf, size_t buflen,  \
		void *userData, int *out_errno);                               \
	EVP_BLOB_IO_RESULT                                                     \
	sdk_callback_impl_##name##_invoke_blob_io_write_callback(              \
		void *ctx, EVP_BLOB_IO_CALLBACK cb, const void *buf,           \
		size_t buflen, void *userData, int *out_errno);

#define SDK_CALLBACK_IMPL_OP(op, name)                                        \
	.invoke_##op##_callback =                                             \
		sdk_callback_impl_##name##_invoke_##op##_callback

#define SDK_CALLBACK_IMPL_OPS_DEFINE(name)                                    \
	const struct sdk_callback_impl_ops sdk_callback_impl_ops_##name = {   \
		SDK_CALLBACK_IMPL_OP(config, name),                           \
		SDK_CALLBACK_IMPL_OP(state, name),                            \
		SDK_CALLBACK_IMPL_OP(blob, name),                             \
		SDK_CALLBACK_IMPL_OP(message_sent, name),                     \
		SDK_CALLBACK_IMPL_OP(message_received, name),                 \
		SDK_CALLBACK_IMPL_OP(telemetry, name),                        \
		SDK_CALLBACK_IMPL_OP(rpc_request, name),                      \
		SDK_CALLBACK_IMPL_OP(rpc_response, name),                     \
		SDK_CALLBACK_IMPL_OP(stream_read_available, name),            \
		SDK_CALLBACK_IMPL_OP(blob_get_upload_url, name),              \
		SDK_CALLBACK_IMPL_OP(blob_io_read, name),                     \
		SDK_CALLBACK_IMPL_OP(blob_io_write, name),                    \
	}

#endif /* !defined(__SDK_CALLBACK_H__) */
