/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <webclient/webclient.h>

#include <evp/sdk.h>

#include <internal/util.h>

#include "agent_test.h"
#include "hub.h"
#include "path.h"

#define TEST_HTTP_GET_URL  "https://baz/boo"
#define TEST_HTTP_PUT_URL  "http://foobar"
#define TEST_HTTP_GET_FILE "foobar.txt"
#define TEST_HTTP_PUT_FILE "boofar.bin"

static pthread_mutex_t webclient_hang_lock;

int
__wrap_webclient_get_poll_info(FAR struct webclient_context *ctx,
			       FAR struct webclient_poll_info *info)
{
	return 0;
}

int
__wrap_webclient_perform(FAR struct webclient_context *ctx)
{
	/* provide a way for us to lock the thread using the mutex */
	pthread_mutex_lock(&webclient_hang_lock);
	pthread_mutex_unlock(&webclient_hang_lock);
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
test_connections_disconnecting(void **state)
{
	// init mutex
	pthread_mutex_init(&webclient_hang_lock, NULL);

	// start agent
	struct evp_agent_context *ctxt = agent_test_start();
	agent_poll_status(ctxt, EVP_AGENT_STATUS_CONNECTED, 10);

	// create backdoor instance
	struct EVP_client *sdk_handle =
		evp_agent_add_instance(ctxt, "backdoor-disconnecting");
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

	// Hang the webclient thread
	pthread_mutex_lock(&webclient_hang_lock);

	// test HTTP GET to file
	struct EVP_BlobRequestHttp request = {
		.url = TEST_HTTP_GET_URL,
	};

	// Send blob operation
	result = EVP_blobOperation(sdk_handle, EVP_BLOB_TYPE_HTTP,
				   EVP_BLOB_OP_GET, &request, &localstore,
				   blob_cb, &cb_data);

	// wait a bit for the blob operation to start
	sleep(1);

	// Disconnection
	result = evp_agent_disconnect(ctxt);
	assert_int_equal(result, EVP_OK);
	agent_poll_status(ctxt, EVP_AGENT_STATUS_DISCONNECTING, 0);

	// let the webclient_perform thread continue
	pthread_mutex_unlock(&webclient_hang_lock);

	// We must go to DISCONNECTED in 5 seconds maximum
	agent_poll_status(ctxt, EVP_AGENT_STATUS_DISCONNECTED, 5);

	// Expect processed blob to abort
	expect_value(blob_cb, reason, EVP_BLOB_CALLBACK_REASON_DONE);
	expect_value(blob_cb, result->result, EVP_BLOB_RESULT_ERROR);
	expect_value(blob_cb, result->error, ENETDOWN);
	result = EVP_processEvent(sdk_handle, 2000);
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
		cmocka_unit_test(test_connections_disconnecting)

	};
	// setup and run tests
	return cmocka_run_group_tests(tests, setup, teardown);
}
