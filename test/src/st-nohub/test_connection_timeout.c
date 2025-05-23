/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <evp/sdk.h>

#include <internal/util.h>

#include "webclient/webclient.h"

#include "agent_test.h"
#include "hub.h"
#include "path.h"

#define TEST_HTTP_GET_URL  "https://baz/boo"
#define TEST_HTTP_PUT_URL  "http://foobar"
#define TEST_HTTP_GET_FILE "foobar.txt"
#define TEST_HTTP_PUT_FILE "boofar.bin"

int
__wrap_webclient_get_poll_info(FAR struct webclient_context *ctx,
			       FAR struct webclient_poll_info *info)
{
	return 0;
}

int
__wrap_webclient_perform(FAR struct webclient_context *ctx)
{
	return -EAGAIN;
}

static void
blob_cb(EVP_BLOB_CALLBACK_REASON reason, const void *vp, void *userData)
{
	const struct EVP_BlobResultAzureBlob *result = vp;
	check_expected(reason);
	check_expected(result->result);
	check_expected(result->error);
}

void
test_connection_timeout(void **state)
{
	// start agent
	struct evp_agent_context *ctxt = agent_test_start();
	agent_poll_status(ctxt, EVP_AGENT_STATUS_CONNECTED, 10);

	// create backdoor instance
	struct EVP_client *sdk_handle =
		evp_agent_add_instance(ctxt, "backdoor-timeout");
	assert_non_null(sdk_handle);

	// prepare tests
	EVP_RESULT result;
	char cb_data;
	char *filename;
	xasprintf(&filename, "%s/%s", path_get(MODULE_INSTANCE_PATH_ID),
		  TEST_HTTP_GET_FILE);
	assert_non_null(filename);

	struct EVP_BlobLocalStore localstore = {
		.filename = filename,
	};

	// test HTTP GET to file
	struct EVP_BlobRequestHttp request = {
		.url = TEST_HTTP_GET_URL,
	};
	result = EVP_blobOperation(sdk_handle, EVP_BLOB_TYPE_HTTP,
				   EVP_BLOB_OP_GET, &request, &localstore,
				   blob_cb, &cb_data);

	// Expect processed blob to time-out
	expect_value(blob_cb, reason, EVP_BLOB_CALLBACK_REASON_DONE);
	expect_value(blob_cb, result->result, EVP_BLOB_RESULT_ERROR);
	expect_value(blob_cb, result->error, ETIMEDOUT);
	result = EVP_processEvent(sdk_handle, -1);
	assert_int_equal(result, EVP_OK);

	free(filename);
}

int
setup(void **state)
{
	int rv;
	agent_test_setup();
	rv = systemf("mkdir -p %s", path_get(MODULE_INSTANCE_PATH_ID));
	assert_int_equal(rv, 0);
	rv = systemf("touch %s/%s", path_get(MODULE_INSTANCE_PATH_ID),
		     TEST_HTTP_PUT_FILE);
	assert_int_equal(0, rv);
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
		cmocka_unit_test(test_connection_timeout)

	};
	// setup and run tests
	return cmocka_run_group_tests(tests, setup, teardown);
}
