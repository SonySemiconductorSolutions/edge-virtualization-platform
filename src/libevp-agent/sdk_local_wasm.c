/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Overview:
 *
 * This file contains SDK entry points for wasm-based EVP module instances.
 *
 * See module_api_wasm.c for the precise mapping from symbols.
 *
 * These entry points are called directly within the context of
 * module instances.
 * That is, in the middle of wasm_application_execute_main.
 *
 * Entry points usually can access wasm memory directly using
 * the library functions like wasm_runtime_addr_app_to_native.
 * However, be careful, the native address to the wasm memory can
 * change on a memory growth.
 * (Basically, a memory growth is caused by memory allocation within
 * the wasm module. Conceptually, you can consider it as realloc(3) of
 * the whole wasm memory for the wasm module. Thus all native addresses
 * to the region will be invalid after a growth.)
 *
 * Notes about memory growth:
 * - Wasm has a dedicated instruction for the purpose, memory.grow. (0x40)
 *   https://webassembly.github.io/spec/core/syntax/instructions.html#syntax-instr-memory
 *   https://webassembly.github.io/spec/core/binary/instructions.html#memory-instructions
 * - Clang has a built-in to issue the instruction, __builtin_wasm_memory_grow.
 * - wasi-libc uses __builtin_wasm_memory_grow in its sbrk implementation.
 *
 * The "Overview" comment in sdk_callback_wasm.c has some notes about
 * memory.grow as well.
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <wasm_export.h>

#include "blob.h"
#include "evp/sdk.h"
#include "main_loop.h"
#include "platform.h"
#include "sdk_agent.h"
#include "sdk_callback_impl_ops.h"
#include "sdk_common.h"
#include "sdk_impl.h"
#include "sdk_local_wasm.h"
#include "transport.h"
#include "xmqtt.h"

/*
 * Note: Wasm uses little endian for its linear memory. This code base
 * assumes the host and wasm use the same endian.
 * It doesn't make much sense to fix it here unless we also fix
 * WAMR, which has the same assumption in many places.
 */
#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) &&            \
	__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error little endian is assumed
#endif

SDK_CALLBACK_IMPL_OPS_DECLARE(wasm);

static uint32_t dummy_handle = 0x1234;

static struct EVP_client *
sdk_handle(wasm_exec_env_t exec_env)
{
	wasm_module_inst_t module_inst =
		wasm_runtime_get_module_inst(exec_env);
	// TODO: Replace assert (runtime error)
	assert(module_inst != NULL);
	struct EVP_client *h = wasm_runtime_get_custom_data(module_inst);
	// TODO: Replace assert (runtime error)
	assert(h != NULL);
	return h;
}

uint32_t
EVP_initialize_wasm(wasm_exec_env_t exec_env)
{
	return dummy_handle;
}

uint32_t
EVP_getWorkspaceDirectory_wasm(wasm_exec_env_t exec_env, uint32_t dh,
			       uint32_t type)
{
	if (dh != dummy_handle) {
		return EVP_INVAL;
	}
	struct EVP_client *h = sdk_handle(exec_env);
	sdk_assert_unlocked();
	if (type != EVP_WORKSPACE_TYPE_DEFAULT) {
		return EVP_INVAL;
	}
	if (h->workspace_wasm == 0) {
		wasm_module_inst_t module_inst =
			wasm_runtime_get_module_inst(exec_env);
		/*
		 * Note: we don't free h->workspace_wasm explicitly.
		 * It's left to the wasm runtime to free it.
		 */

		void *workspace_host;
		size_t workspace_size = strlen(h->workspace) + 1;

		h->workspace_wasm = wasm_runtime_module_malloc(
			module_inst, workspace_size, &workspace_host);
		if (h->workspace_wasm == 0) {
			return EVP_NOMEM;
		}
		memcpy(workspace_host, h->workspace, workspace_size);
	}
	return h->workspace_wasm;
}

uint32_t
EVP_setConfigurationCallback_wasm(wasm_exec_env_t exec_env, uint32_t dh,
				  uint32_t cb, uint32_t userdata)
{
	if (dh != dummy_handle) {
		return EVP_INVAL;
	}
	struct EVP_client *h = sdk_handle(exec_env);
	sdk_assert_unlocked();
	if (h->cb.config_cb != NULL) {
		return EVP_ERROR;
	}
	sdk_lock();
	h->cb.config_cb = (void *)(uintptr_t)cb;
	h->cb.config_cb_userdata = (void *)(uintptr_t)userdata;
	g_resend_request = true;
	sdk_unlock();
	main_loop_wakeup("RESEND-REQUEST");
	return EVP_OK;
}

uint32_t
EVP_sendState_wasm(wasm_exec_env_t exec_env, uint32_t dh, const char *topic,
		   const void *blob, uint32_t bloblen, uint32_t cb,
		   uint32_t userdata)
{
	EVP_RESULT ret;

	if (dh != dummy_handle) {
		return EVP_INVAL;
	}
	wasm_module_inst_t inst;
	inst = wasm_runtime_get_module_inst(exec_env);
	struct EVP_client *h = sdk_handle(exec_env);
	size_t topiclen = plat_wasm_strlen(inst, topic) + 1;
	char *rawbuf = malloc(topiclen + bloblen);
	if (rawbuf == NULL) {
		return EVP_NOMEM;
	}
	char *topic_copy = rawbuf;
	void *blob_copy = rawbuf + topiclen;

	plat_wasm_mem_read(inst, topic_copy, topiclen, topic);
	plat_wasm_mem_read(inst, blob_copy, bloblen, blob);

	ret = EVP_impl_sendState(h, rawbuf, topic_copy, blob_copy, bloblen,
				 (void *)(uintptr_t)cb,
				 (void *)(uintptr_t)userdata);
	if (ret != EVP_OK) {
		free(rawbuf);
	}

	return ret;
}

uint32_t
EVP_setMessageCallback_wasm(wasm_exec_env_t exec_env, uint32_t dh,
			    uint32_t incoming_cb, uint32_t userdata)
{
	if (dh != dummy_handle) {
		return EVP_INVAL;
	}
	struct EVP_client *h = sdk_handle(exec_env);
	sdk_lock();
	// TODO: Replace assert (programming error)
	assert(h->cb.in_msg_cb == NULL);
	h->cb.in_msg_cb = (void *)(uintptr_t)incoming_cb;
	h->cb.in_msg_cb_userdata = (void *)(uintptr_t)userdata;
	sdk_unlock();

	return EVP_OK;
}

uint32_t
EVP_setRpcCallback_wasm(wasm_exec_env_t exec_env, uint32_t dh, uint32_t cb,
			uint32_t userdata)
{
	if (dh != dummy_handle) {
		return EVP_INVAL;
	}
	struct EVP_client *h = sdk_handle(exec_env);

	sdk_lock();
	if (cb == 0 || h->cb.rpc_cb != NULL) {
		sdk_unlock();
		return EVP_INVAL;
	}
	h->cb.rpc_cb = (void *)(uintptr_t)cb;
	h->cb.rpc_cb_userdata = (void *)(uintptr_t)userdata;
	sdk_unlock();
	return EVP_OK;
}

/* Used for HTTP, Azure and EVP blob types. These have the same format */
static EVP_RESULT
get_BlobRequestGeneric(void *request, wasm_module_inst_t module_inst,
		       uint32_t request_addr)
{
	/*
	 * struct EVP_BlobRequestAzureBlob {
	 *     const char *url;
	 * };
	 *
	 * struct EVP_BlobRequestEvp {
	 *     const char *remote_name;
	 * };
	 *
	 * struct EVP_BlobRequestHttp {
	 *     const char *url;
	 * };
	 */
	struct EVP_BlobRequest_wasm {
		uint32_t url;
	};

	size_t request_size;
	uint32_t url_wasm;
	const char *url;

	request_size = sizeof(struct EVP_BlobRequest_wasm);
	if (!wasm_runtime_validate_app_addr(module_inst, request_addr,
					    request_size)) {
		return EVP_FAULT;
	}
	const struct EVP_BlobRequest_wasm *request_wasm =
		wasm_runtime_addr_app_to_native(module_inst, request_addr);

	/* Check and get data from field name */
	url_wasm = request_wasm->url;
	if (!wasm_runtime_validate_app_str_addr(module_inst, url_wasm)) {
		return EVP_FAULT;
	}
	url = wasm_runtime_addr_app_to_native(module_inst, url_wasm);

	((struct EVP_BlobRequestHttp *)request)->url = url;
	return EVP_OK;
};

/* Used for EvpExt blob type */
static EVP_RESULT
get_BlobRequestEvpExt(struct EVP_BlobRequestEvpExt *request,
		      wasm_module_inst_t module_inst, uint32_t request_addr)
{
	struct EVP_BlobRequestEvpExt_wasm {
		uint32_t name;
		uint32_t storage_name;
	};

	size_t request_size;
	uint32_t name_wasm;
	const char *name;

	uint32_t storage_name_wasm;
	const char *storage_name;

	request_size = sizeof(struct EVP_BlobRequestEvpExt_wasm);
	if (!wasm_runtime_validate_app_addr(module_inst, request_addr,
					    request_size)) {
		return EVP_FAULT;
	}
	const struct EVP_BlobRequestEvpExt_wasm *request_wasm =
		wasm_runtime_addr_app_to_native(module_inst, request_addr);

	/* Check and get data from field name */
	name_wasm = request_wasm->name;
	if (!wasm_runtime_validate_app_str_addr(module_inst, name_wasm)) {
		return EVP_FAULT;
	}
	name = wasm_runtime_addr_app_to_native(module_inst, name_wasm);

	/* Check and get data from field storage_name */
	storage_name_wasm = request_wasm->storage_name;
	if (!wasm_runtime_validate_app_str_addr(module_inst,
						storage_name_wasm)) {
		return EVP_FAULT;
	}
	storage_name = wasm_runtime_addr_app_to_native(module_inst,
						       storage_name_wasm);

	request->remote_name = name;
	request->storage_name = storage_name;
	return EVP_OK;
};

/*
 * struct EVP_BlobRequestHttpExt {
 *     const char *url;
 *     const char * const headers;
 *     unsigned int nheaders;
 * };
 */
struct EVP_BlobRequestHttpExt_wasm {
	uint32_t url;
	uint32_t headers;
	uint32_t nheaders;
};

/* Used for HttpExt blob type */
static EVP_RESULT
get_BlobRequestHttpExt(struct EVP_BlobRequestHttpExt *request,
		       wasm_module_inst_t module_inst, uint32_t request_addr)
{
	const char **headers;
	unsigned int nheaders;

	// Request
	if (!wasm_runtime_validate_app_addr(
		    module_inst, request_addr,
		    sizeof(struct EVP_BlobRequestHttpExt_wasm))) {
		return EVP_FAULT;
	}
	const struct EVP_BlobRequestHttpExt_wasm *request_wasm =
		wasm_runtime_addr_app_to_native(module_inst, request_addr);

	// URL
	uint32_t url_wasm = request_wasm->url;
	if (!wasm_runtime_validate_app_str_addr(module_inst, url_wasm)) {
		return EVP_FAULT;
	}
	char *url = wasm_runtime_addr_app_to_native(module_inst, url_wasm);

	if (request_wasm->nheaders > UINT_MAX) {
		return EVP_FAULT;
	}

	// Headers
	nheaders = request_wasm->nheaders;
	uint32_t headers_addr = request_wasm->headers;
	if (!wasm_runtime_validate_app_addr(module_inst, headers_addr,
					    nheaders * sizeof(uint32_t))) {
		return EVP_FAULT;
	}
	uint32_t *headers_wasm_addrs =
		wasm_runtime_addr_app_to_native(module_inst, headers_addr);
	for (unsigned int i = 0; i < nheaders; i++) {
		if (!wasm_runtime_validate_app_str_addr(
			    module_inst, headers_wasm_addrs[i])) {
			return EVP_FAULT;
		}
	}

	// Create a native headers
	headers = calloc(nheaders, sizeof(*headers));
	if (!headers) {
		return EVP_NOMEM;
	}

	for (unsigned int i = 0; i < nheaders; i++) {
		headers[i] = wasm_runtime_addr_app_to_native(
			module_inst, headers_wasm_addrs[i]);
	}
	request->url = url;
	request->headers = headers;
	request->nheaders = nheaders;

	return EVP_OK;
}

static EVP_RESULT
get_LocalStore(struct EVP_BlobLocalStore *store,
	       wasm_module_inst_t module_inst, uint32_t local_store_addr)
{
	/*
	 * struct EVP_BlobLocalStore {
	 *     const char *filename;
	 *     EVP_BLOB_IO_CALLBACK io_cb;
	 *     size_t blob_len;
	 * };
	 */

	struct EVP_BlobLocalStore_wasm {
		uint32_t filename;
		uint32_t io_cb;
		uint32_t blob_len;
	};
	size_t local_store_size = sizeof(struct EVP_BlobLocalStore_wasm);

	if (!wasm_runtime_validate_app_addr(module_inst, local_store_addr,
					    local_store_size)) {
		return EVP_FAULT;
	}
	const struct EVP_BlobLocalStore_wasm *store_wasm =
		wasm_runtime_addr_app_to_native(module_inst, local_store_addr);
	uint32_t filename_wasm = store_wasm->filename;
	if (!wasm_runtime_validate_app_str_addr(module_inst, filename_wasm)) {
		return EVP_FAULT;
	}
	const char *filename =
		wasm_runtime_addr_app_to_native(module_inst, filename_wasm);

	// for some reason, if filename_wasm is 0, filename is valid and set to
	// '\0'
	if (filename_wasm) {
		store->filename = filename;
	} else {
		// If filename is NULL, we are doing memory operation
		store->filename = NULL;
		store->io_cb =
			(EVP_BLOB_IO_CALLBACK)(uintptr_t)store_wasm->io_cb;
		store->blob_len = store_wasm->blob_len;
		// If io_cb is NULL, we will continue download to null
	}

	return EVP_OK;
}

uint32_t
EVP_blobOperation_wasm(wasm_exec_env_t exec_env, uint32_t dh, uint32_t type,
		       uint32_t op, uint32_t request_addr,
		       uint32_t local_store_addr, uint32_t cb,
		       uint32_t userdata)
{
	EVP_RESULT result;

	if (dh != dummy_handle) {
		return EVP_INVAL;
	}
	struct EVP_client *h = sdk_handle(exec_env);
	wasm_module_inst_t module_inst =
		wasm_runtime_get_module_inst(exec_env);

	struct EVP_BlobLocalStore store;

	result = get_LocalStore(&store, module_inst, local_store_addr);
	if (result != EVP_OK) {
		return result;
	}

	struct EVP_BlobRequestHttp request_http;
	struct EVP_BlobRequestEvpExt request_evp_ext;
	struct EVP_BlobRequestHttpExt request_http_ext;
	const void *request;
	switch (type) {
	case EVP_BLOB_TYPE_AZURE_BLOB:
	case EVP_BLOB_TYPE_EVP:
	case EVP_BLOB_TYPE_HTTP:
		result = get_BlobRequestGeneric(&request_http, module_inst,
						request_addr);
		request = &request_http;
		break;
	case EVP_BLOB_TYPE_EVP_EXT:
		result = get_BlobRequestEvpExt(&request_evp_ext, module_inst,
					       request_addr);
		request = &request_evp_ext;
		break;
	case EVP_BLOB_TYPE_HTTP_EXT:
		result = get_BlobRequestHttpExt(&request_http_ext, module_inst,
						request_addr);
		request = &request_http_ext;
		break;
	default:
		return EVP_INVAL;
	}
	if (result != EVP_OK) {
		return result;
	}

	result = EVP_impl_blobOperation(h, NULL, type, op, request, &store,
					(void *)(uintptr_t)cb,
					(void *)(uintptr_t)userdata);

	if (type == EVP_BLOB_TYPE_HTTP_EXT) {
		free((void *)request_http_ext.headers);
	}

	return result;
}

uint32_t
EVP_BlobRequestHttpExt_initialize_wasm(wasm_exec_env_t exec_env)
{
	wasm_module_inst_t module_inst =
		wasm_runtime_get_module_inst(exec_env);

	struct EVP_BlobRequestHttpExt_wasm *request_wasm;
	uint32_t request_addr = wasm_runtime_module_malloc(
		module_inst, sizeof(*request_wasm), (void **)&request_wasm);

	if (request_addr) {
		request_wasm->url = 0;
		request_wasm->nheaders = 0;
		request_wasm->headers = 0;
	}

	return request_addr;
}

uint32_t
EVP_BlobRequestHttpExt_addHeader_wasm(wasm_exec_env_t exec_env,
				      uint32_t request_addr,
				      uint32_t name_addr, uint32_t value_addr)
{
	// Module instance
	wasm_module_inst_t module_inst =
		wasm_runtime_get_module_inst(exec_env);
	if (!wasm_runtime_validate_app_addr(
		    module_inst, request_addr,
		    sizeof(struct EVP_BlobRequestHttpExt_wasm))) {
		return EVP_FAULT;
	}

	// Name
	if (!wasm_runtime_validate_app_str_addr(module_inst, name_addr)) {
		return EVP_FAULT;
	}
	const char *name =
		wasm_runtime_addr_app_to_native(module_inst, name_addr);

	// Value
	if (!wasm_runtime_validate_app_str_addr(module_inst, value_addr)) {
		return EVP_FAULT;
	}
	const char *value =
		wasm_runtime_addr_app_to_native(module_inst, value_addr);

	// Request
	struct EVP_BlobRequestHttpExt_wasm *request_wasm =
		wasm_runtime_addr_app_to_native(module_inst, request_addr);

	if (request_wasm->nheaders > 100) {
		return EVP_TOOBIG;
	}

	// Headers
	uint32_t *headers_wasm_addrs;
	if (!wasm_runtime_validate_app_addr(
		    module_inst, request_wasm->headers,
		    request_wasm->nheaders * sizeof(*headers_wasm_addrs))) {
		return EVP_FAULT;
	}
	headers_wasm_addrs = wasm_runtime_addr_app_to_native(
		module_inst, request_wasm->headers);

	// Allocate new headers
	uint32_t *new_headers;
	uint32_t new_headers_addr = wasm_runtime_module_malloc(
		module_inst,
		(request_wasm->nheaders + 1) * sizeof(request_wasm->headers),
		(void **)&new_headers);
	if (!new_headers_addr) {
		return EVP_NOMEM;
	}

	if (request_wasm->nheaders > UINT_MAX) {
		return EVP_FAULT;
	}

	// Copy original headers
	for (unsigned int i = 0; i < request_wasm->nheaders; i++) {
		new_headers[i] = headers_wasm_addrs[i];
	}

	// Allocate and initialize the new header
	void *new_header;
	size_t new_header_len = strlen(name) + strlen(value) + sizeof(": ");
	uint32_t new_header_addr = wasm_runtime_module_malloc(
		module_inst, new_header_len, &new_header);
	if (!new_header_addr) {
		return EVP_NOMEM;
	}
	snprintf((char *)new_header, new_header_len, "%s: %s", name, value);

	// Add it to the headers
	new_headers[request_wasm->nheaders] = new_header_addr;
	request_wasm->nheaders++;

	// Free old headers pointer and set new one
	wasm_runtime_module_free(module_inst, request_wasm->headers);
	request_wasm->headers = new_headers_addr;

	return EVP_OK;
}

uint32_t
EVP_BlobRequestHttpExt_addAzureHeader_wasm(wasm_exec_env_t exec_env,
					   uint32_t request_addr)
{
	const char *const name = "x-ms-blob-type";
	const char *const value = "BlockBlob";

	wasm_module_inst_t module_inst =
		wasm_runtime_get_module_inst(exec_env);
	if (!wasm_runtime_validate_app_addr(
		    module_inst, request_addr,
		    sizeof(struct EVP_BlobRequestHttpExt_wasm))) {
		return EVP_FAULT;
	}

	// Allocate and initialize the new name
	void *new_name;
	size_t new_name_len = strlen(name) + 1;
	uint32_t new_name_addr = wasm_runtime_module_malloc(
		module_inst, new_name_len, &new_name);
	if (!new_name_addr) {
		return EVP_NOMEM;
	}
	memcpy(new_name, name, new_name_len);

	// Allocate and initialize the new value
	void *new_value;
	size_t new_value_len = strlen(value) + 1;
	uint32_t new_value_addr = wasm_runtime_module_malloc(
		module_inst, strlen(value) + 1, &new_value);
	if (!new_value_addr) {
		return EVP_NOMEM;
	}
	memcpy(new_value, value, new_value_len);

	uint32_t ret = EVP_BlobRequestHttpExt_addHeader_wasm(
		exec_env, request_addr, new_name_addr, new_value_addr);

	/* If addHeader failed, we just dealloc our allocated
	 * variables and propagate the error to the caller */

	wasm_runtime_module_free(module_inst, new_name_addr);
	wasm_runtime_module_free(module_inst, new_value_addr);
	return ret;
}

uint32_t
EVP_BlobRequestHttpExt_setUrl_wasm(wasm_exec_env_t exec_env,
				   uint32_t request_addr, uint32_t url_addr)
{
	// Module instance
	wasm_module_inst_t module_inst =
		wasm_runtime_get_module_inst(exec_env);
	if (!wasm_runtime_validate_app_addr(
		    module_inst, request_addr,
		    sizeof(struct EVP_BlobRequestHttpExt_wasm))) {
		return EVP_FAULT;
	}

	// Input Url to be set
	if (!wasm_runtime_validate_app_str_addr(module_inst, url_addr)) {
		return EVP_FAULT;
	}
	const char *in_url =
		wasm_runtime_addr_app_to_native(module_inst, url_addr);

	// Request
	struct EVP_BlobRequestHttpExt_wasm *request_wasm =
		wasm_runtime_addr_app_to_native(module_inst, request_addr);

	if (request_wasm->nheaders > 100) {
		return EVP_TOOBIG;
	}

	// Current Url in the request
	if (!wasm_runtime_validate_app_str_addr(module_inst,
						request_wasm->url)) {
		return EVP_FAULT;
	}

	// Allocate and initialize the new Url
	void *new_url;
	size_t new_url_len = strlen(in_url) + 1;
	uint32_t new_url_addr =
		wasm_runtime_module_malloc(module_inst, new_url_len, &new_url);
	if (!new_url_addr) {
		return EVP_NOMEM;
	}

	memcpy(new_url, in_url, new_url_len);

	// Free old url pointer and set new one
	wasm_runtime_module_free(module_inst, request_wasm->url);
	request_wasm->url = new_url_addr;

	return EVP_OK;
}

void
EVP_BlobRequestHttpExt_free_wasm(wasm_exec_env_t exec_env,
				 uint32_t request_addr)
{
	// Module instance
	wasm_module_inst_t module_inst =
		wasm_runtime_get_module_inst(exec_env);
	if (!wasm_runtime_validate_app_addr(
		    module_inst, request_addr,
		    sizeof(struct EVP_BlobRequestHttpExt_wasm))) {
		return;
	}

	// Request
	if (!wasm_runtime_validate_app_addr(
		    module_inst, request_addr,
		    sizeof(struct EVP_BlobRequestHttpExt_wasm))) {
		return;
	}

	struct EVP_BlobRequestHttpExt_wasm *request_wasm =
		wasm_runtime_addr_app_to_native(module_inst, request_addr);

	// Headers
	uint32_t *headers_wasm_addrs;
	if (!wasm_runtime_validate_app_addr(
		    module_inst, request_wasm->headers,
		    request_wasm->nheaders * sizeof(*headers_wasm_addrs))) {
		return;
	}
	headers_wasm_addrs = wasm_runtime_addr_app_to_native(
		module_inst, request_wasm->headers);

	if (request_wasm->nheaders > UINT_MAX) {
		return;
	}

	// Free headers contents
	for (unsigned int i = 0; i < request_wasm->nheaders; i++) {
		wasm_runtime_module_free(module_inst, headers_wasm_addrs[i]);
	}

	// Free headers
	wasm_runtime_module_free(module_inst, request_wasm->headers);

	// Free request
	wasm_runtime_module_free(module_inst, request_addr);
}

uint32_t
EVP_sendMessage_wasm(wasm_exec_env_t exec_env, uint32_t dh, const char *topic,
		     const void *blob, uint32_t bloblen, uint32_t cb,
		     uint32_t userdata)
{
	if (dh != dummy_handle) {
		return EVP_INVAL;
	}
	struct EVP_client *h = sdk_handle(exec_env);
	size_t topiclen = strlen(topic) + 1;
	char *rawbuf = malloc(topiclen + bloblen);
	if (rawbuf == NULL) {
		return EVP_NOMEM;
	}
	char *topic_copy = rawbuf;
	void *blob_copy = rawbuf + topiclen;
	memcpy(topic_copy, topic, topiclen);
	memcpy(blob_copy, blob, bloblen);
	return EVP_impl_sendMessage(h, rawbuf, topic_copy, blob_copy, bloblen,
				    (void *)(uintptr_t)cb,
				    (void *)(uintptr_t)userdata);
}

uint32_t
EVP_sendTelemetry_wasm(wasm_exec_env_t exec_env, uint32_t dh,
		       uint32_t entries_addr, uint32_t nentries, uint32_t cb,
		       uint32_t userdata)
{
	if (dh != dummy_handle) {
		return EVP_INVAL;
	}
	struct EVP_client *h = sdk_handle(exec_env);
	wasm_module_inst_t module_inst =
		wasm_runtime_get_module_inst(exec_env);

	/*
	 * struct EVP_telemetry_entry {
	 *    const char *key;
	 *    const char *value;
	 * };
	 */

	struct EVP_telemetry_entry_wasm {
		uint32_t key;
		uint32_t value;
	};

	if (nentries > 1000) { /* just a sanity check */
		return EVP_TOOBIG;
	}
	if (!wasm_runtime_validate_app_addr(
		    module_inst, entries_addr,
		    nentries * sizeof(struct EVP_telemetry_entry_wasm))) {
		return EVP_FAULT;
	}
	const struct EVP_telemetry_entry_wasm *entries_wasm =
		wasm_runtime_addr_app_to_native(module_inst, entries_addr);

	unsigned int i;
	size_t totalsz;

	totalsz = nentries * sizeof(struct EVP_telemetry_entry);
	for (i = 0; i < nentries; i++) {
		uint32_t addr;

		addr = entries_wasm[i].key;
		if (!wasm_runtime_validate_app_str_addr(module_inst, addr)) {
			return EVP_FAULT;
		}
		totalsz += strlen(wasm_runtime_addr_app_to_native(module_inst,
								  addr)) +
			   1;

		addr = entries_wasm[i].value;
		if (!wasm_runtime_validate_app_str_addr(module_inst, addr)) {
			return EVP_FAULT;
		}
		totalsz += strlen(wasm_runtime_addr_app_to_native(module_inst,
								  addr)) +
			   1;
	}
	/* Add json extra chars
	 * The worst case for telemetry is something like
	 * {"<module_instance_name>/<telemetry_key>":
	 * "<telemetry_value>",}
	 */
	size_t extra_headers = 0;
	extra_headers += nentries * strlen(h->name);
	extra_headers += nentries * strlen("\"/\": \"\",");
	/* Take into account the main Json brackets */
	extra_headers += strlen("{}");

	if (g_mqtt_client == NULL) {
		return EVP_ERROR;
	}

	if (!xmqtt_request_fits(g_mqtt_client, totalsz + extra_headers)) {
		return EVP_TOOBIG;
	}

	char *buf = malloc(totalsz);
	if (buf == NULL) {
		return EVP_NOMEM;
	}
	struct EVP_telemetry_entry *entries = (void *)buf;
	char *kv_buf = buf + sizeof(*entries) * nentries;
	for (i = 0; i < nentries; i++) {
		uint32_t addr;
		const void *p;
		size_t sz;

		addr = entries_wasm[i].key;
		p = wasm_runtime_addr_app_to_native(module_inst, addr);
		sz = strlen(p) + 1;
		memcpy(kv_buf, p, sz);
		entries[i].key = kv_buf;
		kv_buf += sz;

		addr = entries_wasm[i].value;
		p = wasm_runtime_addr_app_to_native(module_inst, addr);
		sz = strlen(p) + 1;
		memcpy(kv_buf, p, sz);
		entries[i].value = kv_buf;
		kv_buf += sz;
	}

	EVP_RESULT ret = EVP_impl_sendTelemetry(
		h, buf, NULL, entries, nentries, (void *)(uintptr_t)cb,
		(void *)(uintptr_t)userdata);

	if (EVP_OK != ret) {
		free(entries);
	}

	return ret;
}

uint32_t
EVP_sendRpcResponse_wasm(wasm_exec_env_t exec_env, uint32_t dh, uint64_t id,
			 const char *response, uint32_t status, uint32_t cb,
			 uint32_t userdata)
{
	char *response_copy;
	if (dh != dummy_handle) {
		return EVP_INVAL;
	}
	struct EVP_client *h = sdk_handle(exec_env);
	response_copy = strdup(response);
	if (response_copy == NULL) {
		return EVP_NOMEM;
	}

	EVP_RESULT result = EVP_impl_sendRpcResponse(
		h, response_copy, id, response_copy, status,
		(void *)(uintptr_t)cb, (void *)(uintptr_t)userdata);
	if (result != EVP_OK) {
		free(response_copy);
	}
	return result;
}

uint32_t
EVP_processEvent_wasm(wasm_exec_env_t exec_env, uint32_t dh, int timeout_ms)
{
	if (dh != dummy_handle) {
		return EVP_INVAL;
	}
	struct EVP_client *h = sdk_handle(exec_env);
	struct sdk_event *event;
	EVP_RESULT result;
	result = EVP_impl_getEvent(h, timeout_ms, &event);
	// TODO: Replace assert (runtime error)
	assert((result == EVP_OK) == (event != NULL));
	if (result == EVP_OK) {
		result = sdk_common_execute_event(&sdk_callback_impl_ops_wasm,
						  &h->cb, event, exec_env);
		sdk_free_event(event);
	}
	return result;
}

uint32_t
EVP_streamInputOpen_wasm(wasm_exec_env_t exec_env, uint32_t dh,
			 const char *name, uint32_t cb, uint32_t userdata,
			 uint32_t stream)
{
	if (dh != dummy_handle) {
		return EVP_INVAL;
	}
	wasm_module_inst_t module_inst =
		wasm_runtime_get_module_inst(exec_env);
	if (!wasm_runtime_validate_app_addr(module_inst, stream,
					    sizeof(EVP_STREAM))) {
		return EVP_FAULT;
	}
	EVP_STREAM *stream_native =
		wasm_runtime_addr_app_to_native(module_inst, stream);
	return EVP_impl_streamInputOpen_local(
		sdk_handle(exec_env), name, (void *)(uintptr_t)cb,
		(void *)(uintptr_t)userdata, stream_native);
}

uint32_t
EVP_streamOutputOpen_wasm(wasm_exec_env_t exec_env, uint32_t dh,
			  const char *name, uint32_t stream)
{
	if (dh != dummy_handle) {
		return EVP_INVAL;
	}
	wasm_module_inst_t module_inst =
		wasm_runtime_get_module_inst(exec_env);
	if (!wasm_runtime_validate_app_addr(module_inst, stream,
					    sizeof(EVP_STREAM))) {
		return EVP_FAULT;
	}
	EVP_STREAM *stream_native =
		wasm_runtime_addr_app_to_native(module_inst, stream);
	return EVP_impl_streamOutputOpen_local(sdk_handle(exec_env), name,
					       stream_native);
}

uint32_t
EVP_streamClose_wasm(wasm_exec_env_t exec_env, uint32_t dh, uint32_t stream)
{
	if (dh != dummy_handle) {
		return EVP_INVAL;
	}
	return EVP_impl_streamClose_local(sdk_handle(exec_env), stream);
}

uint32_t
EVP_streamWrite_wasm(wasm_exec_env_t exec_env, uint32_t dh, uint32_t stream,
		     const void *buf, uint32_t n)
{
	if (dh != dummy_handle) {
		return EVP_INVAL;
	}
	return EVP_impl_streamWrite_local(sdk_handle(exec_env), stream, buf,
					  n);
}
