/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE

#include <cdefs.h>
#include <inttypes.h>
#include <stdlib.h>

#include "agent_test.h"
#include "evp/sdk.h"
#include "req.h"

enum test_payloads {
	DEPLOYMENT_MANIFEST_WASM,
	DEPLOYMENT_MANIFEST_SPAWN,
	DEPLOYMENT_MANIFEST_EMPTY,

	STP_RESPONSE_FMT,

	STEP_READY,
	STEP_DONE,
	VERIFY_STP_REQUEST_JSON_DOT,
	VERIFY_PUT_1,
	VERIFY_PUT_2,
	VERIFY_PUT_3,
};

// X macro prototype: X(Symb, Name, Ext)
// Symb: impl enum symbol
// Name: impl name string
// Ext: extension string
#define MODULE_IMPLS(X)                                                       \
	X(WASM, "wasm", "wasm")                                               \
	X(SPAWN, "spawn", "elf")                                              \
	X(PYTHON, "python", "zip")                                            \
	/*                                                                    \
		// TODO: Add other implementations                            \
		X(DLFCN, "dlfcn", "so")                                       \
		X(DOCKER, "docker", "NA")                                     \
	*/

#define IMPL_ENUM(Symb, ...) TEST_IMPL_##Symb,
enum test_impl { MODULE_IMPLS(IMPL_ENUM) TEST_IMPL_END };

#ifndef TEST_N_INSTANCES
#define TEST_N_INSTANCES 5
#endif

#define TEST_WORKSPACE_TEMPLATE "/tmp/evp-test.XXXXXX"
struct test_blob_core_context {
	struct evp_agent_context *agent;
	struct agent_deployment deployment;
	const char *match_stp_prefix_fmt;
	struct test_st_req {
		EVP_RPC_ID reqid;
		char *remote_name;
	} stp_reqs[TEST_N_INSTANCES];
	char workspace[sizeof(TEST_WORKSPACE_TEMPLATE)];
	unsigned short port;
};

struct test_blob_core_param {
	const char *module;
	enum test_impl impl;
	size_t n_instances;
};

#define DEPLOYMENT_ID_EMPTY "4fa905ae-e103-46ab-a8b9-73be0759970A"
#define DEPLOYMENT_ID       "4fa905ae-e103-46ab-a8b9-73be07599708"
#define INSTANCE_ID_BASE    "b218f90b-9228-423f-8e02-"
#define INSTANCE_ID_FMT     INSTANCE_ID_BASE "%012d"
#define MODULE_ID           "b218f90b-9228-423f-8e02-a6d3527bc15d"

#define BLOB_NAME_BASE "data_blob_"
#define BLOB_NAME_FMT  BLOB_NAME_BASE "%zd"

#define MODULE_DIR      "../test_modules"
#define MODULE_URL_BASE "file://" MODULE_DIR
#define MODULE_NAME     "%s"

#define ASSETS_BLOB_FMT "%s/assets/" BLOB_NAME_FMT

#define TEST_HOST_NAME    "localhost"
#define TEST_BASE_URL     "https://" TEST_HOST_NAME
#define TEST_BASE_URL_FMT TEST_BASE_URL ":%u"
#define TEST_SAS_PARAMS   "token=298dfascvHSjak09iujjsNKD"

#define TEST_HTTP_SERVER_PORT    0
#define TEST_PROXY_FRONTEND_PORT 0

// This generates a 1MB file filled with random base64 chars
// 1MB * 3/4 out due to base64 overhead -> 786432 chars
#define FILE_BLOB_GEN_CMD "openssl rand -base64 786432"
#define FILE_UPLOAD_NAME  "my_file.txt"
#define FILE_UPLOAD_DIR   "default_workspace"
#define STORAGE_NAME_DEF  "storage_def"

#define EVP1_STP_RESPONSE_FMT                                                 \
	"{"                                                                   \
	"\"method\":\"StorageToken\","                                        \
	"\"params\":{"                                                        \
	"\"URL\":\"" TEST_BASE_URL_FMT "/%s?%s\","                            \
	"\"responseType\":\"%s\","                                            \
	"\"expiresAtMillis\":\"%d\","                                         \
	"\"headers\":{\"x-ms-blob-type\":"                                    \
	"\"BlockBlob\"},"                                                     \
	"\"cert\":\"56176780-9747-11ed-9bd5-"                                 \
	"5f138e81521e\""                                                      \
	"}"                                                                   \
	"}"

#define EVP2_STP_RESPONSE_FMT                                                 \
	"{"                                                                   \
	"\"storagetoken-response\":{"                                         \
	"\"status\":\"ok\","                                                  \
	"\"URL\":\"" TEST_BASE_URL_FMT "/%s?%s\","                            \
	"\"responseType\":\"%s\","                                            \
	"\"expiresAtMillis\":\"%d\","                                         \
	"\"reqid\":\"%s\","                                                   \
	"\"headers\":{\"x-ms-blob-type\":\"BlockBlob\"}"                      \
	"}"                                                                   \
	"}"
