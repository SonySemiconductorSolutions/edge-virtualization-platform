/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
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

static sem_t in_sem, out_sem;

int
__wrap_webclient_get_poll_info(FAR struct webclient_context *ctx,
			       FAR struct webclient_poll_info *info)
{
	return 0;
}

int
__wrap_webclient_perform(FAR struct webclient_context *ctx)
{
	assert(!sem_post(&in_sem));
	assert(!sem_wait(&out_sem));
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

static int
on_conn_status(const void *data, void *user)
{
	agent_write_to_pipe(data);
	return 0;
}

void
test_connections_disconnecting(void **state)
{
	// init mutex
	assert_int_equal(sem_init(&in_sem, 0, 0), 0);
	assert_int_equal(sem_init(&out_sem, 0, 0), 0);

	// start agent
	struct evp_agent_context *ctxt = agent_test_start();

	assert_int_equal(
		evp_agent_notification_subscribe(ctxt, "agent/conn_status",
						 on_conn_status, NULL),
		0);

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

	// test HTTP GET to file
	struct EVP_BlobRequestHttp request = {
		.url = TEST_HTTP_GET_URL,
	};

	// Send blob operation
	result = EVP_blobOperation(sdk_handle, EVP_BLOB_TYPE_HTTP,
				   EVP_BLOB_OP_GET, &request, &localstore,
				   blob_cb, &cb_data);

	// wait for webclient_perform to be called
	assert_int_equal(sem_wait(&in_sem), 0);

	// Disconnection
	assert_int_equal(evp_agent_disconnect(ctxt), EVP_OK);
	agent_poll(verify_equals, "disconnecting");

	// let the webclient_perform thread continue
	assert_int_equal(sem_post(&out_sem), 0);

	agent_poll(verify_equals, "disconnected");

	// Expect processed blob to abort
	expect_value(blob_cb, reason, EVP_BLOB_CALLBACK_REASON_DONE);
	expect_value(blob_cb, result->result, EVP_BLOB_RESULT_ERROR);
	expect_value(blob_cb, result->error, ENETDOWN);
	assert_int_equal(EVP_processEvent(sdk_handle, -1), EVP_OK);

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
