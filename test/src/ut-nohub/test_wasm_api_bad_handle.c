/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sys/stat.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cmocka.h>

#include "evp/sdk.h"
#include "sdk_local_wasm.h"

static uint32_t bad_handle = 0x1337; // correct handle is 0x1234

static void
test_wasm_api_bad_handle_EVP_getWorkspaceDirectory(void **status)
{
	uint32_t error = EVP_getWorkspaceDirectory_wasm(NULL, bad_handle, 0);
	assert_true(error == EVP_INVAL);
}

static void
test_wasm_api_bad_handle_EVP_setConfigurationCallback(void **status)
{
	uint32_t error =
		EVP_setConfigurationCallback_wasm(NULL, bad_handle, 0, 0);
	assert_true(error == EVP_INVAL);
}

static void
test_wasm_api_bad_handle_EVP_sendState(void **status)
{
	uint32_t error =
		EVP_sendState_wasm(NULL, bad_handle, NULL, NULL, 0, 0, 0);
	assert_true(error == EVP_INVAL);
}

static void
test_wasm_api_bad_handle_EVP_setMessageCallback(void **status)
{
	uint32_t error = EVP_setMessageCallback_wasm(NULL, bad_handle, 0, 0);
	assert_true(error == EVP_INVAL);
}

static void
test_wasm_api_bad_handle_EVP_blobOperation(void **status)
{
	uint32_t error =
		EVP_blobOperation_wasm(NULL, bad_handle, 0, 0, 0, 0, 0, 0);
	assert_true(error == EVP_INVAL);
}

static void
test_wasm_api_bad_handle_EVP_sendMessage(void **status)
{
	uint32_t error =
		EVP_sendMessage_wasm(NULL, bad_handle, NULL, NULL, 0, 0, 0);
	assert_true(error == EVP_INVAL);
}

static void
test_wasm_api_bad_handle_EVP_sendTelemetry(void **status)
{
	uint32_t error = EVP_sendTelemetry_wasm(NULL, bad_handle, 0, 0, 0, 0);
	assert_true(error == EVP_INVAL);
}

static void
test_wasm_api_bad_handle_EVP_sendRpcResponse(void **status)
{
	uint32_t error =
		EVP_sendRpcResponse_wasm(NULL, bad_handle, 0, NULL, 0, 0, 0);
	assert_true(error == EVP_INVAL);
}

static void
test_wasm_api_bad_handle_EVP_processEvent(void **status)
{
	uint32_t error = EVP_processEvent_wasm(NULL, bad_handle, 0);
	assert_true(error == EVP_INVAL);
}

static void
test_wasm_api_bad_handle_EVP_streamInputOpen(void **status)
{
	uint32_t error =
		EVP_streamInputOpen_wasm(NULL, bad_handle, NULL, 0, 0, 0);
	assert_true(error == EVP_INVAL);
}

static void
test_wasm_api_bad_handle_EVP_streamOutputOpen(void **status)
{
	uint32_t error = EVP_streamOutputOpen_wasm(NULL, bad_handle, NULL, 0);
	assert_true(error == EVP_INVAL);
}

static void
test_wasm_api_bad_handle_EVP_streamClose(void **status)
{
	uint32_t error = EVP_streamClose_wasm(NULL, bad_handle, 0);
	assert_true(error == EVP_INVAL);
}

static void
test_wasm_api_bad_handle_EVP_streamWrite(void **status)
{
	uint32_t error = EVP_streamWrite_wasm(NULL, bad_handle, 0, NULL, 0);
	assert_true(error == EVP_INVAL);
}

int
main(void)
{

	const struct CMUnitTest tests[] = {
		cmocka_unit_test(
			test_wasm_api_bad_handle_EVP_getWorkspaceDirectory),
		cmocka_unit_test(
			test_wasm_api_bad_handle_EVP_setConfigurationCallback),
		cmocka_unit_test(test_wasm_api_bad_handle_EVP_sendState),
		cmocka_unit_test(
			test_wasm_api_bad_handle_EVP_setMessageCallback),
		cmocka_unit_test(test_wasm_api_bad_handle_EVP_blobOperation),
		cmocka_unit_test(test_wasm_api_bad_handle_EVP_sendMessage),
		cmocka_unit_test(test_wasm_api_bad_handle_EVP_sendTelemetry),
		cmocka_unit_test(test_wasm_api_bad_handle_EVP_sendRpcResponse),
		cmocka_unit_test(test_wasm_api_bad_handle_EVP_processEvent),
		cmocka_unit_test(test_wasm_api_bad_handle_EVP_streamInputOpen),
		cmocka_unit_test(
			test_wasm_api_bad_handle_EVP_streamOutputOpen),
		cmocka_unit_test(test_wasm_api_bad_handle_EVP_streamClose),
		cmocka_unit_test(test_wasm_api_bad_handle_EVP_streamWrite),
	};
	// test run
	return cmocka_run_group_tests(tests, NULL, NULL);
}
