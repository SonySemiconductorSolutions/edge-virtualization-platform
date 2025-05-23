/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Overview:
 *
 * This file contains the logic to call functions, which is in
 * a wasm module.
 *
 * EVP module C SDK has APIs which takes a pointer to a user-provided
 * callback function. This logic is used to invoke those callback
 * functions.
 *
 * Because the callback functions don't have a direct access to
 * native memory, we need to copy necessary data into the wasm memory.
 * We use wasm_runtime_module_malloc to temporarily allocate memory
 * region within the wasm module, copy necessary data to the memory
 * region, and invoke the callback function. Usually, we free the
 * temporary memory region immediately after the callback function returns.
 *
 * Note: wasm_runtime_module_malloc/free basically calls the malloc
 * implementation inside the wasm module. Yes, they themselves are calls
 * into the wasm module. They can even involve memory.grow. Be careful
 * especially when calling wasm_runtime_module_malloc multiple times.
 * The latter call can invalidate the "host" address from the previous
 * calls. We actually had subtle bugs involving memory.grow in the past.
 * See commit 299d279bfd761f38efff61d1c5364b2dafa655b0 for an example.
 * The "Overview" comment in sdk_local_wasm.c has some notes about
 * memory.grow as well.
 *
 * Note: in the convention for C on wasm we are using, a pointer to
 * a function is basically an index for a function table within
 * the wasm module. The table contains the description about the type of
 * functions (the type of arguments and return value, ...), which need to
 * match when invoking the functions. That is, there is not much freedom
 * to call functions using arbitrary address as you might expect in
 * traditional C runtime environments.
 *
 * Note: Because all SDK callbacks are called within the context of
 * EVP_processEvent, we always have a valid wasm execution context to
 * use to invoke a callback.
 * (While blob memory callback is an exception, we don't have a plan
 * to provide the hack for wasm-based modules.)
 */

#include <config.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <wasm_export.h>

#include "cdefs.h"
#include "platform.h"
#include "sdk_callback_impl_ops.h"
#include "xlog.h"

SDK_CALLBACK_IMPL_OPS_DECLARE_FUNCTIONS(wasm);
SDK_CALLBACK_IMPL_OPS_DEFINE(wasm);

static void
sdk_invoke_callback_ii(void *ctx, uint32_t func, uint32_t a1, uint32_t a2)
{
	wasm_exec_env_t exec_env = ctx;
	uint32_t args[] = {
		a1,
		a2,
	};
	if (!wasm_runtime_call_indirect(exec_env, func, __arraycount(args),
					args)) {
		xlog_error("wasm_runtime_call_indirect failed");
	}
}

void
sdk_callback_impl_wasm_invoke_config_callback(void *ctx,
					      EVP_CONFIGURATION_CALLBACK cb,
					      const char *topic,
					      const void *blob, size_t bloblen,
					      void *userdata)
{
	wasm_exec_env_t exec_env = ctx;
	wasm_module_inst_t module_inst =
		wasm_runtime_get_module_inst(exec_env);
	size_t topic_size = strlen(topic) + 1;
	void *topic_host;
	uint32_t topic_wasm = wasm_runtime_module_malloc(
		module_inst, topic_size, &topic_host);
	if (topic_wasm != 0) {
		plat_wasm_mem_write(module_inst, topic, topic_size,
				    topic_host);
		topic_host = NULL;
	}
	void *blob_host;
	uint32_t blob_wasm =
		wasm_runtime_module_malloc(module_inst, bloblen, &blob_host);
	if (blob_wasm != 0) {
		plat_wasm_mem_write(module_inst, blob, bloblen, blob_host);
		blob_host = NULL;
	}
	if (topic_wasm != 0 && blob_wasm != 0) {
		uint32_t func = (uint32_t)(uintptr_t)cb;
		uint32_t args[] = {
			topic_wasm,
			blob_wasm,
			(uint32_t)bloblen,
			(uint32_t)(uintptr_t)userdata,
		};
		if (!wasm_runtime_call_indirect(exec_env, func,
						__arraycount(args), args)) {
			xlog_error("wasm_runtime_call_indirect failed: %s",
				   topic);
		}
	} else {
		xlog_error("failed to allocate wasm module memory: %zu bytes",
			   topic_size + bloblen);
	}
	wasm_runtime_module_free(module_inst, topic_wasm);
	wasm_runtime_module_free(module_inst, blob_wasm);
}

void
sdk_callback_impl_wasm_invoke_state_callback(void *ctx, EVP_STATE_CALLBACK cb,
					     EVP_STATE_CALLBACK_REASON reason,
					     void *userdata)
{
	sdk_invoke_callback_ii(ctx, (uint32_t)(uintptr_t)cb, reason,
			       (uint32_t)(uintptr_t)userdata);
}

void
sdk_callback_impl_wasm_invoke_blob_callback(void *ctx, EVP_BLOB_CALLBACK cb,
					    EVP_BLOB_CALLBACK_REASON reason,
					    const void *result_vp,
					    void *userdata)
{
	/*
	 * struct EVP_BlobResultAzureBlob {
	 *     EVP_BLOB_RESULT result;
	 *     unsigned int http_status;
	 *     int error;
	 * };
	 *
	 * struct EVP_BlobResultEvp {
	 *     EVP_BLOB_RESULT result;
	 *     unsigned int http_status;
	 *     int error;
	 * };
	 *
	 * struct EVP_BlobResultHttp {
	 *     EVP_BLOB_RESULT result;
	 *     unsigned int http_status;
	 *     int error;
	 * };
	 */

	struct EVP_BlobResult_wasm { /* REVISIT: This should be per-type */
		uint32_t result;
		uint32_t http_status;
		int32_t error;
	};

	const struct EVP_BlobResultAzureBlob *result = result_vp;

	wasm_exec_env_t exec_env = ctx;
	wasm_module_inst_t module_inst =
		wasm_runtime_get_module_inst(exec_env);

	uint32_t result_wasm;
	const size_t result_size = sizeof(struct EVP_BlobResult_wasm);
	if (result != NULL) {
		void *result_host;
		result_wasm = wasm_runtime_module_malloc(
			module_inst, result_size, &result_host);
		if (result_wasm != 0) {
			struct EVP_BlobResult_wasm *dest = result_host;

			dest->result = result->result;
			dest->http_status = result->http_status;
			dest->error = result->error;
		}
	} else {
		result_wasm = 0;
	}
	if (result == NULL || result_wasm != 0) {
		uint32_t func = (uint32_t)(uintptr_t)cb;
		uint32_t args[] = {
			reason,
			result_wasm,
			(uint32_t)(uintptr_t)userdata,
		};
		if (!wasm_runtime_call_indirect(exec_env, func,
						__arraycount(args), args)) {
			xlog_error("wasm_runtime_call_indirect failed");
		}
	} else {
		xlog_error("failed to allocate wasm module memory: %zu bytes",
			   result_size);
	}
	wasm_runtime_module_free(module_inst, result_wasm);
}

void
sdk_callback_impl_wasm_invoke_message_sent_callback(
	void *ctx, EVP_MESSAGE_SENT_CALLBACK cb,
	EVP_MESSAGE_SENT_CALLBACK_REASON reason, void *userdata)
{
	sdk_invoke_callback_ii(ctx, (uint32_t)(uintptr_t)cb, reason,
			       (uint32_t)(uintptr_t)userdata);
}

void
sdk_callback_impl_wasm_invoke_message_received_callback(
	void *ctx, EVP_MESSAGE_RECEIVED_CALLBACK cb, const char *topic,
	const void *msg_payload, size_t msg_payload_len, void *userdata)
{
	wasm_exec_env_t exec_env = ctx;
	wasm_module_inst_t module_inst =
		wasm_runtime_get_module_inst(exec_env);
	size_t topic_size = strlen(topic) + 1;
	void *topic_host;
	uint32_t topic_wasm = wasm_runtime_module_malloc(
		module_inst, topic_size, &topic_host);
	if (topic_wasm != 0) {
		memcpy(topic_host, topic, topic_size);
		topic_host = NULL;
	}
	size_t msg_payload_size = msg_payload_len;
	void *msg_payload_host;
	uint32_t msg_payload_wasm = wasm_runtime_module_malloc(
		module_inst, msg_payload_size, &msg_payload_host);
	if (msg_payload_wasm != 0) {
		memcpy(msg_payload_host, msg_payload, msg_payload_size);
		msg_payload_host = NULL;
	}
	if (topic_wasm != 0 && msg_payload_wasm != 0) {
		uint32_t func = (uint32_t)(uintptr_t)cb;
		uint32_t args[] = {
			topic_wasm,
			msg_payload_wasm,
			msg_payload_size,
			(uint32_t)(uintptr_t)userdata,
		};
		if (!wasm_runtime_call_indirect(exec_env, func,
						__arraycount(args), args)) {
			xlog_error("wasm_runtime_call_indirect failed: %s",
				   topic);
		}
	} else {
		xlog_error("failed to allocate wasm module memory: %zu bytes",
			   topic_size + msg_payload_len);
	}
	wasm_runtime_module_free(module_inst, topic_wasm);
	wasm_runtime_module_free(module_inst, msg_payload_wasm);
}

void
sdk_callback_impl_wasm_invoke_telemetry_callback(
	void *ctx, EVP_TELEMETRY_CALLBACK cb,
	EVP_TELEMETRY_CALLBACK_REASON reason, void *userdata)
{
	sdk_invoke_callback_ii(ctx, (uint32_t)(uintptr_t)cb, reason,
			       (uint32_t)(uintptr_t)userdata);
}

void
sdk_callback_impl_wasm_invoke_rpc_request_callback(
	void *ctx, EVP_RPC_REQUEST_CALLBACK cb, EVP_RPC_ID id,
	const char *method_name, const char *params, void *userdata)
{
	wasm_exec_env_t exec_env = ctx;
	wasm_module_inst_t module_inst =
		wasm_runtime_get_module_inst(exec_env);
	size_t method_name_size = strlen(method_name) + 1;
	void *method_name_host;
	uint32_t method_name_wasm = wasm_runtime_module_malloc(
		module_inst, method_name_size, &method_name_host);
	if (method_name_wasm != 0) {
		memcpy(method_name_host, method_name, method_name_size);
		method_name_host = NULL;
	}
	size_t params_size = strlen(params) + 1;
	void *params_host;
	uint32_t params_wasm = wasm_runtime_module_malloc(
		module_inst, params_size, &params_host);
	if (params_wasm != 0) {
		memcpy(params_host, params, params_size);
		params_host = NULL;
	}
	if (method_name_wasm != 0 && params_wasm != 0) {
		uint32_t func = (uint32_t)(uintptr_t)cb;
		uint32_t args[] = {
			0,
			0,
			method_name_wasm,
			params_wasm,
			(uint32_t)(uintptr_t)userdata,
		};
		memcpy(&args[0], &id, sizeof(id));
		if (!wasm_runtime_call_indirect(exec_env, func,
						__arraycount(args), args)) {
			xlog_error("wasm_runtime_call_indirect failed: %s",
				   method_name);
		}
	} else {
		xlog_error("failed to allocate wasm module memory: %zu bytes",
			   method_name_size + params_size);
	}
	wasm_runtime_module_free(module_inst, method_name_wasm);
	wasm_runtime_module_free(module_inst, params_wasm);
}

void
sdk_callback_impl_wasm_invoke_rpc_response_callback(
	void *ctx, EVP_RPC_RESPONSE_CALLBACK cb,
	EVP_RPC_RESPONSE_CALLBACK_REASON reason, void *userdata)
{
	sdk_invoke_callback_ii(ctx, (uint32_t)(uintptr_t)cb, reason,
			       (uint32_t)(uintptr_t)userdata);
}

void
sdk_callback_impl_wasm_invoke_stream_read_available_callback(
	void *ctx, EVP_STREAM_READ_CALLBACK cb, EVP_STREAM_PEER_ID id,
	const void *buf, size_t n, void *userdata)
{
	wasm_exec_env_t exec_env = ctx;
	wasm_module_inst_t module_inst =
		wasm_runtime_get_module_inst(exec_env);
	void *buf_host;
	uint32_t buf_wasm =
		wasm_runtime_module_malloc(module_inst, n, &buf_host);
	if (buf_wasm == 0) {
		xlog_error("wasm_runtime_module_malloc failed");
		return;
	}
	memcpy(buf_host, buf, n);
	uint32_t args[] = {id, buf_wasm, n, (uint32_t)(uintptr_t)userdata};
	if (!wasm_runtime_call_indirect(exec_env, (uint32_t)(uintptr_t)cb,
					__arraycount(args), args)) {
		xlog_error("wasm_runtime_call_indirect failed");
	}
	wasm_runtime_module_free(module_inst, buf_wasm);
}

void
sdk_callback_impl_wasm_invoke_blob_get_upload_url_callback(
	void *ctx, EVP_BLOB_CALLBACK cb, EVP_BLOB_CALLBACK_REASON reason,
	const char *uploadUrl, void *userdata)
{
	xlog_error("This API is only available from native and not available "
		   "for WASM module");
}

EVP_BLOB_IO_RESULT
sdk_callback_impl_wasm_invoke_blob_io_read_callback(void *ctx,
						    EVP_BLOB_IO_CALLBACK cb,
						    void *buf, size_t buflen,
						    void *userData,
						    int *out_errno)
{
	wasm_exec_env_t exec_env = ctx;
	wasm_module_inst_t module_inst =
		wasm_runtime_get_module_inst(exec_env);
	void *dup = NULL;
	uint32_t buf_wasm =
		wasm_runtime_module_malloc(module_inst, buflen, &dup);
	EVP_BLOB_IO_RESULT ret;

	if (!dup) {
		xlog_error("wasm_runtime_module_malloc failed");
		ret = EVP_BLOB_IO_RESULT_ERROR;
		*out_errno = ENOMEM;
		goto end;
	}

	uint32_t args[] = {buf_wasm, buflen, (uint32_t)(uintptr_t)userData};

	if (!wasm_runtime_call_indirect(exec_env, (uint32_t)(uintptr_t)cb,
					__arraycount(args), args)) {
		xlog_error("wasm_runtime_call_indirect failed");
		ret = EVP_BLOB_IO_RESULT_ERROR;
		*out_errno = ECANCELED;
		goto end;
	}

	plat_wasm_mem_read(module_inst, buf, buflen, dup);

	/* According to its documentation, wasm-micro-runtime stores the return
	 * value for the called functions inside args[0]. We assume the
	 * endianness of this value matches that of the host. */
	ret = args[0];

end:
	if (dup) {
		wasm_runtime_module_free(module_inst, buf_wasm);
	}

	return ret;
}

EVP_BLOB_IO_RESULT
sdk_callback_impl_wasm_invoke_blob_io_write_callback(
	void *ctx, EVP_BLOB_IO_CALLBACK cb, const void *buf, size_t buflen,
	void *userData, int *out_errno)
{
	wasm_exec_env_t exec_env = ctx;
	wasm_module_inst_t module_inst =
		wasm_runtime_get_module_inst(exec_env);
	void *dup = NULL;
	uint32_t buf_wasm =
		wasm_runtime_module_malloc(module_inst, buflen, &dup);
	EVP_BLOB_IO_RESULT ret;

	if (!dup) {
		xlog_error("wasm_runtime_module_malloc failed");
		ret = EVP_BLOB_IO_RESULT_ERROR;
		*out_errno = ENOMEM;
		goto end;
	}

	plat_wasm_mem_write(module_inst, buf, buflen, dup);

	uint32_t args[] = {buf_wasm, buflen, (uint32_t)(uintptr_t)userData};

	if (!wasm_runtime_call_indirect(exec_env, (uint32_t)(uintptr_t)cb,
					__arraycount(args), args)) {
		xlog_error("wasm_runtime_call_indirect failed");
		ret = EVP_BLOB_IO_RESULT_ERROR;
		*out_errno = ECANCELED;
		goto end;
	}

	/* According to its documentation, wasm-micro-runtime stores the return
	 * value for the called functions inside args[0]. We assume the
	 * endianness of this value matches that of the host. */
	ret = args[0];

end:
	if (dup) {
		wasm_runtime_module_free(module_inst, buf_wasm);
	}

	return ret;
}
