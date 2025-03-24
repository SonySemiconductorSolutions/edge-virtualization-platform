/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <string.h>

#include <evp/sdk.h>

#include <internal/util.h>

#include "webclient/webclient.h"

#include "agent_test.h"
#include "hub.h"
#include "path.h"
#include "xlog.h"

#define TEST_HTTP_GET_URL   "https://baz/boo"
#define TEST_HTTP_PUT_URL   "http://foobar"
#define TEST_HTTP_GET_FILE  "foobar.txt"
#define TEST_HTTP_PUT_FILE  "boofar.bin"
#define TEST_HTTP_GET_RANGE "bytes=0-1023"

#define HTTP_STATUS_OK 200

struct test {
	struct evp_agent_context *agent;
	struct EVP_client *client;
};

static struct test test;

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
test_http_ext_get_memory(void **state)
{
	/* This should test the HttpExt blob type.
	 *
	 * First test that it works without any additional headers
	 * Then test that the range and azure headers work
	 * Finally we test the headers limit and the free function.
	 */

	// test HTTP GET to memory
	struct test *ctxt = *state;

	EVP_RESULT result;
	struct EVP_BlobLocalStore localstore = {0};
	char cb_data;

	struct EVP_BlobRequestHttpExt *request =
		EVP_BlobRequestHttpExt_initialize();
	EVP_BlobRequestHttpExt_setUrl(request, TEST_HTTP_GET_URL);

	result = EVP_blobOperation(ctxt->client, EVP_BLOB_TYPE_HTTP_EXT,
				   EVP_BLOB_OP_GET, request, &localstore,
				   blob_cb, &cb_data);
	assert_int_equal(result, EVP_OK);
	agent_poll(verify_equals, "GET " TEST_HTTP_GET_URL);
	// Blob download to memory is allowed

	// Expect processed blob to succeed
	expect_value(blob_cb, reason, EVP_BLOB_CALLBACK_REASON_DONE);
	expect_value(blob_cb, result->result, EVP_BLOB_RESULT_SUCCESS);
	expect_value(blob_cb, result->http_status, HTTP_STATUS_OK);
	expect_value(blob_cb, result->error, 0);
	result = EVP_processEvent(ctxt->client, 5000);
	assert_int_equal(result, EVP_OK);

	EVP_BlobRequestHttpExt_free(request);
}

void
test_http_ext_get_file(void **state)
{
	// test HTTP GET to file
	struct test *ctxt = *state;

	char *filename;
	xasprintf(&filename, "%s/%s", path_get(MODULE_INSTANCE_PATH_ID),
		  TEST_HTTP_GET_FILE);
	EVP_RESULT result;
	struct EVP_BlobLocalStore localstore = {.filename = filename};
	char cb_data;

	struct EVP_BlobRequestHttpExt *request =
		EVP_BlobRequestHttpExt_initialize();
	EVP_BlobRequestHttpExt_setUrl(request, TEST_HTTP_GET_URL);

	/* we can't use expect_string because webclient_perform will be called
	 * from a different thread */
	result = EVP_blobOperation(ctxt->client, EVP_BLOB_TYPE_HTTP_EXT,
				   EVP_BLOB_OP_GET, request, &localstore,
				   blob_cb, &cb_data);
	free(filename);
	assert_int_equal(result, EVP_OK);
	agent_poll(verify_equals, "GET " TEST_HTTP_GET_URL);

	// Expect processed blob to succeed
	expect_value(blob_cb, reason, EVP_BLOB_CALLBACK_REASON_DONE);
	expect_value(blob_cb, result->result, EVP_BLOB_RESULT_SUCCESS);
	expect_value(blob_cb, result->http_status, HTTP_STATUS_OK);
	expect_value(blob_cb, result->error, 0);
	result = EVP_processEvent(ctxt->client, 5000);
	assert_int_equal(result, EVP_OK);

	EVP_BlobRequestHttpExt_free(request);
}

void
test_http_ext_put_file(void **state)
{
	// test HTTP PUT file
	struct test *ctxt = *state;

	char *filename;
	xasprintf(&filename, "%s/%s", path_get(MODULE_INSTANCE_PATH_ID),
		  TEST_HTTP_GET_FILE);
	EVP_RESULT result;
	struct EVP_BlobLocalStore localstore = {.filename = filename};
	char cb_data;

	struct EVP_BlobRequestHttpExt *request =
		EVP_BlobRequestHttpExt_initialize();
	EVP_BlobRequestHttpExt_setUrl(request, TEST_HTTP_PUT_URL);

	result = EVP_blobOperation(ctxt->client, EVP_BLOB_TYPE_HTTP_EXT,
				   EVP_BLOB_OP_PUT, request, &localstore,
				   blob_cb, &cb_data);
	free(filename);
	assert_int_equal(result, EVP_OK);
	agent_poll(verify_equals, "PUT " TEST_HTTP_PUT_URL);

	// Expect processed blob to succeed
	expect_value(blob_cb, reason, EVP_BLOB_CALLBACK_REASON_DONE);
	expect_value(blob_cb, result->result, EVP_BLOB_RESULT_SUCCESS);
	expect_value(blob_cb, result->http_status, HTTP_STATUS_OK);
	expect_value(blob_cb, result->error, 0);
	result = EVP_processEvent(ctxt->client, 5000);
	assert_int_equal(result, EVP_OK);

	EVP_BlobRequestHttpExt_free(request);
}

void
test_http_ext_get_file_range(void **state)
{
	// test HTTP GET with RANGE
	struct test *ctxt = *state;

	char *filename;
	xasprintf(&filename, "%s/%s", path_get(MODULE_INSTANCE_PATH_ID),
		  TEST_HTTP_GET_FILE);
	EVP_RESULT result;
	struct EVP_BlobLocalStore localstore = {.filename = filename};
	char cb_data;

	struct EVP_BlobRequestHttpExt *request =
		EVP_BlobRequestHttpExt_initialize();
	EVP_BlobRequestHttpExt_setUrl(request, TEST_HTTP_GET_URL);
	EVP_BlobRequestHttpExt_addHeader(request, "Range",
					 TEST_HTTP_GET_RANGE);

	result = EVP_blobOperation(ctxt->client, EVP_BLOB_TYPE_HTTP_EXT,
				   EVP_BLOB_OP_GET, request, &localstore,
				   blob_cb, &cb_data);

	free(filename);
	assert_int_equal(result, EVP_OK);
	agent_poll(verify_equals, "GET " TEST_HTTP_GET_URL);
	// make sure range header is present
	agent_poll(verify_equals, "Range: " TEST_HTTP_GET_RANGE);

	// Expect processed blob to succeed
	expect_value(blob_cb, reason, EVP_BLOB_CALLBACK_REASON_DONE);
	expect_value(blob_cb, result->result, EVP_BLOB_RESULT_SUCCESS);
	expect_value(blob_cb, result->http_status, HTTP_STATUS_OK);
	expect_value(blob_cb, result->error, 0);
	result = EVP_processEvent(ctxt->client, 5000);
	assert_int_equal(result, EVP_OK);

	EVP_BlobRequestHttpExt_free(request);
}

void
test_http_ext_get_file_range_azure(void **state)
{
	// test HTTP GET with RANGE and Azure header
	struct test *ctxt = *state;

	char *filename;
	xasprintf(&filename, "%s/%s", path_get(MODULE_INSTANCE_PATH_ID),
		  TEST_HTTP_GET_FILE);
	EVP_RESULT result;
	struct EVP_BlobLocalStore localstore = {.filename = filename};
	char cb_data;

	struct EVP_BlobRequestHttpExt *request =
		EVP_BlobRequestHttpExt_initialize();
	EVP_BlobRequestHttpExt_setUrl(request, TEST_HTTP_GET_URL);
	EVP_BlobRequestHttpExt_addHeader(request, "Range",
					 TEST_HTTP_GET_RANGE);
	EVP_BlobRequestHttpExt_addAzureHeader(request);

	result = EVP_blobOperation(ctxt->client, EVP_BLOB_TYPE_HTTP_EXT,
				   EVP_BLOB_OP_GET, request, &localstore,
				   blob_cb, &cb_data);

	free(filename);
	assert_int_equal(result, EVP_OK);
	agent_poll(verify_equals, "GET " TEST_HTTP_GET_URL);
	// make sure range header is present
	agent_poll(verify_equals, "Range: " TEST_HTTP_GET_RANGE);
	// make sure Azure header is present
	agent_poll(verify_equals, "x-ms-blob-type: BlockBlob");

	// Expect processed blob to succeed
	expect_value(blob_cb, reason, EVP_BLOB_CALLBACK_REASON_DONE);
	expect_value(blob_cb, result->result, EVP_BLOB_RESULT_SUCCESS);
	expect_value(blob_cb, result->http_status, HTTP_STATUS_OK);
	expect_value(blob_cb, result->error, 0);
	result = EVP_processEvent(ctxt->client, 5000);
	assert_int_equal(result, EVP_OK);

	EVP_BlobRequestHttpExt_free(request);
}

void
test_http_ext_get_null_memory_range_azure(void **state)
{
	// Test download to null memory
	struct test *ctxt = *state;

	EVP_RESULT result;
	struct EVP_BlobLocalStore localstore = {0};
	char cb_data;

	struct EVP_BlobRequestHttpExt *request =
		EVP_BlobRequestHttpExt_initialize();
	EVP_BlobRequestHttpExt_setUrl(request, TEST_HTTP_GET_URL);
	EVP_BlobRequestHttpExt_addHeader(request, "Range",
					 TEST_HTTP_GET_RANGE);
	EVP_BlobRequestHttpExt_addAzureHeader(request);

	result = EVP_blobOperation(ctxt->client, EVP_BLOB_TYPE_HTTP_EXT,
				   EVP_BLOB_OP_GET, request, &localstore,
				   blob_cb, &cb_data);

	assert_int_equal(result, EVP_OK);
	agent_poll(verify_equals, "GET " TEST_HTTP_GET_URL);
	// make sure range header is present
	agent_poll(verify_equals, "Range: " TEST_HTTP_GET_RANGE);
	// make sure Azure header is present
	agent_poll(verify_equals, "x-ms-blob-type: BlockBlob");

	// Expect processed blob to succeed
	expect_value(blob_cb, reason, EVP_BLOB_CALLBACK_REASON_DONE);
	expect_value(blob_cb, result->result, EVP_BLOB_RESULT_SUCCESS);
	expect_value(blob_cb, result->http_status, HTTP_STATUS_OK);
	expect_value(blob_cb, result->error, 0);
	result = EVP_processEvent(ctxt->client, 5000);
	assert_int_equal(result, EVP_OK);

	EVP_BlobRequestHttpExt_free(request);
}

void
test_http_ext_header_limits(void **state)
{
	struct EVP_BlobRequestHttpExt *request =
		EVP_BlobRequestHttpExt_initialize();
	// Test the headers limit and the free function
	unsigned int i;
	for (i = 0; i < 200; i++) {
		if (EVP_OK != EVP_BlobRequestHttpExt_addHeader(
				      request, "Dummy", "dummy")) {
			break;
		};
	}

	// i should be the maximum number of headers
	assert_int_equal(i, 101);

	EVP_BlobRequestHttpExt_free(request);
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
	// start agent
	test.agent = agent_test_start();

	// create backdoor instance
	test.client = evp_agent_add_instance(test.agent, "backdoor");
	assert_non_null(test.client);
	*state = &test;
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
		cmocka_unit_test(test_http_ext_get_memory),
		cmocka_unit_test(test_http_ext_get_file),
		cmocka_unit_test(test_http_ext_put_file),
		cmocka_unit_test(test_http_ext_get_file_range),
		cmocka_unit_test(test_http_ext_get_file_range_azure),
		cmocka_unit_test(test_http_ext_get_null_memory_range_azure),
		cmocka_unit_test(test_http_ext_header_limits),
	};
	// setup and run tests
	return cmocka_run_group_tests(tests, setup, teardown);
}
