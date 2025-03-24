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
test_http_get_memory(void **state)
{
	// test HTTP GET to memory
	struct test *ctxt = *state;

	EVP_RESULT result;
	struct EVP_BlobRequestHttp request = {.url = TEST_HTTP_GET_URL};
	struct EVP_BlobLocalStore localstore = {0};
	char cb_data;

	result = EVP_blobOperation(ctxt->client, EVP_BLOB_TYPE_HTTP,
				   EVP_BLOB_OP_GET, &request, &localstore,
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
}

void
test_http_get_file(void **state)
{
	// test HTTP GET to file
	struct test *ctxt = *state;

	char *filename;
	xasprintf(&filename, "%s/%s", path_get(MODULE_INSTANCE_PATH_ID),
		  TEST_HTTP_GET_FILE);

	EVP_RESULT result;
	struct EVP_BlobRequestHttp request = {.url = TEST_HTTP_GET_URL};
	struct EVP_BlobLocalStore localstore = {.filename = filename};
	char cb_data;

	/* we can't use expect_string because webclient_perform will be called
	 * from a different thread */
	result = EVP_blobOperation(ctxt->client, EVP_BLOB_TYPE_HTTP,
				   EVP_BLOB_OP_GET, &request, &localstore,
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
}

void
test_http_put_file(void **state)
{
	// test HTTP PUT to file
	struct test *ctxt = *state;

	char *filename;
	xasprintf(&filename, "%s/%s", path_get(MODULE_INSTANCE_PATH_ID),
		  TEST_HTTP_PUT_FILE);

	EVP_RESULT result;
	struct EVP_BlobRequestHttp request = {.url = TEST_HTTP_PUT_URL};
	struct EVP_BlobLocalStore localstore = {.filename = filename};
	char cb_data;

	result = EVP_blobOperation(ctxt->client, EVP_BLOB_TYPE_HTTP,
				   EVP_BLOB_OP_PUT, &request, &localstore,
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
		cmocka_unit_test(test_http_get_memory),
		cmocka_unit_test(test_http_get_file),
		cmocka_unit_test(test_http_put_file),
	};
	// setup and run tests
	return cmocka_run_group_tests(tests, setup, teardown);
}
