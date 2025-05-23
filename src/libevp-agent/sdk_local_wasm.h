/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <wasm_export.h>

uint32_t EVP_initialize_wasm(wasm_exec_env_t exec_env);
uint32_t EVP_getWorkspaceDirectory_wasm(wasm_exec_env_t exec_env, uint32_t h,
					uint32_t type);
uint32_t EVP_setConfigurationCallback_wasm(wasm_exec_env_t exec_env,
					   uint32_t h, uint32_t cb,
					   uint32_t userdata);
uint32_t EVP_sendState_wasm(wasm_exec_env_t exec_env, uint32_t h,
			    const char *topic, const void *blob,
			    uint32_t bloblen, uint32_t cb, uint32_t userdata);
uint32_t EVP_setMessageCallback_wasm(wasm_exec_env_t exec_env, uint32_t dh,
				     uint32_t incoming_cb, uint32_t userdata);
uint32_t EVP_setRpcCallback_wasm(wasm_exec_env_t exec_env, uint32_t h,
				 uint32_t cb, uint32_t userdata);
uint32_t EVP_blobOperation_wasm(wasm_exec_env_t exec_env, uint32_t h,
				uint32_t type, uint32_t op,
				uint32_t request_addr,
				uint32_t local_store_addr, uint32_t cb,
				uint32_t userdata);
uint32_t EVP_BlobRequestHttpExt_initialize_wasm(wasm_exec_env_t exec_env);
uint32_t EVP_BlobRequestHttpExt_addHeader_wasm(wasm_exec_env_t exec_env,
					       uint32_t request_addr,
					       uint32_t name_addr,
					       uint32_t value_addr);
uint32_t EVP_BlobRequestHttpExt_addAzureHeader_wasm(wasm_exec_env_t exec_env,
						    uint32_t request_addr);
uint32_t EVP_BlobRequestHttpExt_setUrl_wasm(wasm_exec_env_t exec_env,
					    uint32_t request_addr,
					    uint32_t url_addr);
void EVP_BlobRequestHttpExt_free_wasm(wasm_exec_env_t exec_env,
				      uint32_t request_addr);
uint32_t EVP_sendMessage_wasm(wasm_exec_env_t exec_env, uint32_t dh,
			      const char *topic, const void *blob,
			      uint32_t bloblen, uint32_t cb,
			      uint32_t userdata);
uint32_t EVP_sendTelemetry_wasm(wasm_exec_env_t exec_env, uint32_t h,
				uint32_t entries, uint32_t nentries,
				uint32_t cb, uint32_t userdata);
uint32_t EVP_sendRpcResponse_wasm(wasm_exec_env_t exec_env, uint32_t h,
				  uint64_t id, const char *response,
				  uint32_t status, uint32_t cb,
				  uint32_t userdata);
uint32_t EVP_processEvent_wasm(wasm_exec_env_t exec_env, uint32_t h,
			       int timeout_ms);
uint32_t EVP_streamInputOpen_wasm(wasm_exec_env_t exec_env, uint32_t dh,
				  const char *name, uint32_t cb,
				  uint32_t userdata, uint32_t stream);
uint32_t EVP_streamOutputOpen_wasm(wasm_exec_env_t exec_env, uint32_t dh,
				   const char *name, uint32_t stream);
uint32_t EVP_streamClose_wasm(wasm_exec_env_t exec_env, uint32_t dh,
			      uint32_t stream);
uint32_t EVP_streamWrite_wasm(wasm_exec_env_t exec_env, uint32_t dh,
			      uint32_t stream, const void *buf, uint32_t n);
