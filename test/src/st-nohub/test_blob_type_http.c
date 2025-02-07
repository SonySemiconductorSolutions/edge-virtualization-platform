/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <internal/util.h>

#include "webclient/webclient.h"

#include "agent_test.h"
#include "evp/sdk.h"
#include "hub.h"
#include "path.h"
#include "xlog.h"

#define TEST_HTTP_GET_URL  "https://baz/boo"
#define TEST_HTTP_PUT_URL  "http://foobar"
#define TEST_HTTP_GET_FILE "foobar.txt"
#define TEST_HTTP_PUT_FILE "boofar.bin"

#define HTTP_STATUS_OK 200

static void
blob_cb(EVP_BLOB_CALLBACK_REASON reason, const void *vp, void *userData)
{
	const struct EVP_BlobResultAzureBlob *result = vp;
	check_expected(reason);
	check_expected(result->result);
	check_expected(result->http_status);
	check_expected(result->error);
}

void
blob_type_http_test(void **state)
{
	// start agent
	struct evp_agent_context *ctxt = agent_test_start();

	// create backdoor instance
	struct EVP_client *sdk_handle =
		evp_agent_add_instance(ctxt, "backdoor");
	assert_non_null(sdk_handle);

	// prepare tests
	EVP_RESULT result;
	static struct EVP_BlobRequestHttp request;
	static struct EVP_BlobLocalStore localstore;
	static char cb_data;
	localstore.io_cb = 0;
	localstore.blob_len = 0;
	localstore.filename = NULL;
	request.url = TEST_HTTP_GET_URL;

	// test HTTP GET to memory
	result = EVP_blobOperation(sdk_handle, EVP_BLOB_TYPE_HTTP,
				   EVP_BLOB_OP_GET, &request, &localstore,
				   blob_cb, &cb_data);
	assert_int_equal(result, EVP_OK);
	// Blob download to memory is allowed

	// Expect processed blob to succeed
	expect_value(blob_cb, reason, EVP_BLOB_CALLBACK_REASON_DONE);
	expect_value(blob_cb, result->result, EVP_BLOB_RESULT_SUCCESS);
	expect_value(blob_cb, result->http_status, HTTP_STATUS_OK);
	expect_value(blob_cb, result->error, 0);
	result = EVP_processEvent(sdk_handle, 1000);
	assert_int_equal(result, EVP_OK);

	// test HTTP GET to file
	request.url = TEST_HTTP_GET_URL;
	xasprintf((char **)&localstore.filename, "%s/%s",
		  path_get(MODULE_INSTANCE_PATH_ID), TEST_HTTP_GET_FILE);
	/* we can't use expect_string because webclient_perform will be called
	 * from a different thread */
	result = EVP_blobOperation(sdk_handle, EVP_BLOB_TYPE_HTTP,
				   EVP_BLOB_OP_GET, &request, &localstore,
				   blob_cb, &cb_data);
	free(__UNCONST(localstore.filename));
	assert_int_equal(result, EVP_OK);
	agent_poll(verify_equals, "GET " TEST_HTTP_GET_URL);

	// Expect processed blob to succeed
	expect_value(blob_cb, reason, EVP_BLOB_CALLBACK_REASON_DONE);
	expect_value(blob_cb, result->result, EVP_BLOB_RESULT_SUCCESS);
	expect_value(blob_cb, result->http_status, HTTP_STATUS_OK);
	expect_value(blob_cb, result->error, 0);
	result = EVP_processEvent(sdk_handle, 1000);
	assert_int_equal(result, EVP_OK);

	// test HTTP PUT to file
	request.url = TEST_HTTP_PUT_URL;
	xasprintf((char **)&localstore.filename, "%s/%s",
		  path_get(MODULE_INSTANCE_PATH_ID), TEST_HTTP_PUT_FILE);
	result = EVP_blobOperation(sdk_handle, EVP_BLOB_TYPE_HTTP,
				   EVP_BLOB_OP_PUT, &request, &localstore,
				   blob_cb, &cb_data);
	free(__UNCONST(localstore.filename));
	assert_int_equal(result, EVP_OK);
	agent_poll(verify_equals, "PUT " TEST_HTTP_PUT_URL);

	// Expect processed blob to succeed
	expect_value(blob_cb, reason, EVP_BLOB_CALLBACK_REASON_DONE);
	expect_value(blob_cb, result->result, EVP_BLOB_RESULT_SUCCESS);
	expect_value(blob_cb, result->http_status, HTTP_STATUS_OK);
	expect_value(blob_cb, result->error, 0);
	result = EVP_processEvent(sdk_handle, 1000);
	assert_int_equal(result, EVP_OK);
}

int
setup(void **state)
{
	agent_test_setup();
	assert_int_equal(
		systemf("mkdir -p %s", path_get(MODULE_INSTANCE_PATH_ID)), 0);
	assert_int_equal(0, systemf("touch %s/%s",
				    path_get(MODULE_INSTANCE_PATH_ID),
				    TEST_HTTP_PUT_FILE));
	return 0;
}

int
teardown(void **state)
{
	agent_test_exit();
	return 0;
}

int
main(void)
{
	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(blob_type_http_test),
	};
	// setup and run tests
	return cmocka_run_group_tests(tests, setup, teardown);
}
