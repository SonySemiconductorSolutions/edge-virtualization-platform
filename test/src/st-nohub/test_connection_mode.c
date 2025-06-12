/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <errno.h>
#include <semaphore.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <evp/sdk.h>

#include <internal/util.h>

#include "webclient/webclient.h"

#include "agent_test.h"
#include "hub.h"
#include "path.h"
#include "xlog.h"
#include "xpthread.h"

#define TEST_HTTP_GET_URL  "https://baz/boo"
#define TEST_HTTP_PUT_URL  "http://foobar"
#define TEST_HTTP_GET_FILE "foobar.txt"
#define TEST_HTTP_PUT_FILE "boofar.bin"

#define HTTP_STATUS_OK        200
#define PROCESS_EVENT_TIMEOUT 3000

struct test {
	sem_t sem;
	char *filename;
};

static struct test g_test;

int __real_connections_webclient_perform(FAR struct webclient_context *ctx);

int
__wrap_connections_webclient_perform(FAR struct webclient_context *ctx)
{
	// Sync point with test thread. If enabled, will wait for other
	// call to `sync_join` from the other thread.
	assert(!sem_post(&g_test.sem));
	return __real_connections_webclient_perform(ctx);
}

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
test_disconnect_reconnect(void **state)
{
	struct test *t = *state;

	// start agent
	struct evp_agent_context *ctxt = agent_test_start();
	agent_poll_status(ctxt, EVP_AGENT_STATUS_CONNECTED, 10);

	// create backdoor instance
	struct EVP_client *sdk_handle =
		evp_agent_add_instance(ctxt, "backdoor-mode");
	assert_non_null(sdk_handle);

	// prepare tests
	EVP_RESULT result;
	char cb_data;
	xasprintf(&t->filename, "%s/%s", path_get(MODULE_INSTANCE_PATH_ID),
		  TEST_HTTP_GET_FILE);
	assert_non_null(t->filename);

	struct EVP_BlobLocalStore localstore = {
		.filename = t->filename,
	};

	// test HTTP GET to file
	struct EVP_BlobRequestHttp request = {
		.url = TEST_HTTP_GET_URL,
	};
	result = EVP_blobOperation(sdk_handle, EVP_BLOB_TYPE_HTTP,
				   EVP_BLOB_OP_GET, &request, &localstore,
				   blob_cb, &cb_data);
	assert_int_equal(result, EVP_OK);

	// Disconnection
	result = evp_agent_disconnect(ctxt);
	assert_int_equal(result, EVP_OK);
	agent_poll_status(ctxt, EVP_AGENT_STATUS_DISCONNECTED, 2);

	// Control race condition: wait for blob work to be started and before
	// http operation is performed.
	assert_int_equal(sem_wait(&t->sem), 0);

	// Expect processed blob to have failed
	expect_value(blob_cb, reason, EVP_BLOB_CALLBACK_REASON_DONE);
	expect_value(blob_cb, result->result, EVP_BLOB_RESULT_ERROR);
	expect_value(blob_cb, result->http_status, 0);
	expect_value(blob_cb, result->error, ENETDOWN);
	result = EVP_processEvent(sdk_handle, PROCESS_EVENT_TIMEOUT);
	assert_int_equal(result, EVP_OK);

	// Blob download cannot be performed when disconnected
	result = EVP_blobOperation(sdk_handle, EVP_BLOB_TYPE_HTTP,
				   EVP_BLOB_OP_GET, &request, &localstore,
				   blob_cb, &cb_data);
	assert_int_equal(result, EVP_OK);

	// Expect processed blob to fail
	expect_value(blob_cb, reason, EVP_BLOB_CALLBACK_REASON_DONE);
	expect_value(blob_cb, result->result, EVP_BLOB_RESULT_ERROR);
	expect_value(blob_cb, result->http_status, 0);
	expect_value(blob_cb, result->error, ENETDOWN);
	result = EVP_processEvent(sdk_handle, PROCESS_EVENT_TIMEOUT);
	assert_int_equal(result, EVP_OK);

	result = evp_agent_connect(ctxt);
	assert_int_equal(result, EVP_OK);
	agent_poll_status(ctxt, EVP_AGENT_STATUS_CONNECTED, 10);

	// Blob download can be performed when connected
	result = EVP_blobOperation(sdk_handle, EVP_BLOB_TYPE_HTTP,
				   EVP_BLOB_OP_GET, &request, &localstore,
				   blob_cb, &cb_data);
	assert_int_equal(result, EVP_OK);

	// Expect processed blob to succeed
	expect_value(blob_cb, reason, EVP_BLOB_CALLBACK_REASON_DONE);
	expect_value(blob_cb, result->result, EVP_BLOB_RESULT_SUCCESS);
	expect_value(blob_cb, result->http_status, HTTP_STATUS_OK);
	expect_value(blob_cb, result->error, 0);
	result = EVP_processEvent(sdk_handle, PROCESS_EVENT_TIMEOUT);
	assert_int_equal(result, EVP_OK);
}

int
setup(void **state)
{
	struct test *t = &g_test;

	int rv;
	rv = sem_init(&t->sem, 0, 0);
	assert_int_equal(0, rv);
	agent_test_setup();
	rv = systemf("mkdir -p %s", path_get(MODULE_INSTANCE_PATH_ID));
	assert_int_equal(rv, 0);
	rv = systemf("touch %s/%s", path_get(MODULE_INSTANCE_PATH_ID),
		     TEST_HTTP_GET_FILE);
	assert_int_equal(0, rv);

	*state = t;
	return 0;
}

int
teardown(void **state)
{
	struct test *t = *state;

	free(t->filename);

	if (sem_destroy(&t->sem))
		return -1;

	agent_test_exit();
	return 0;
}

int
main(void)
{
	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_disconnect_reconnect),
	};
	// setup and run tests
	return cmocka_run_group_tests(tests, setup, teardown);
}
