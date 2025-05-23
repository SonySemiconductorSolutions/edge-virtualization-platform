/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

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

#define TEST_HTTP_GET_URL  "https://baz/boo"
#define TEST_HTTP_GET_FILE "foobar.txt"

static void
blob_cb(EVP_BLOB_CALLBACK_REASON reason, const void *vp, void *userData)
{
}

/**
 * The goal of this test is check that the agent clean correctly the blob queue
 * when it is stopped */
void
cancel_blob_operation_in_progress(void **state)
{
	// start agent
	struct evp_agent_context *ctxt = agent_test_start();

	// create backdoor instance
	struct EVP_client *sdk_handle =
		evp_agent_add_instance(ctxt, "backdoor");
	assert_non_null(sdk_handle);

	// prepare tests
	EVP_RESULT result;
	static struct EVP_BlobLocalStore localstore;
	static char cb_data;
	localstore.io_cb = 0;
	localstore.blob_len = 0;
	localstore.filename = NULL;

	struct EVP_BlobRequestHttpExt *request =
		EVP_BlobRequestHttpExt_initialize();
	EVP_BlobRequestHttpExt_setUrl(request, TEST_HTTP_GET_URL);

	xasprintf((char **)&localstore.filename, "%s/%s",
		  path_get(MODULE_INSTANCE_PATH_ID), TEST_HTTP_GET_FILE);
	/* we can't use expect_string because webclient_perform will be called
	 * from a different thread */
	for (int i = 0; i < 10; i++) {
		xlog_info("Sending blob operation %d", i);
		char *url;
		xasprintf(&url, TEST_HTTP_GET_URL "/blob_n%d", i);
		EVP_BlobRequestHttpExt_setUrl(request, url);
		free(url);
		result = EVP_blobOperation(sdk_handle, EVP_BLOB_TYPE_HTTP_EXT,
					   EVP_BLOB_OP_GET, request,
					   &localstore, blob_cb, &cb_data);
	}

	free(__UNCONST(localstore.filename));
	result = EVP_processEvent(sdk_handle, 1000);
	assert_int_equal(result, EVP_OK);

	// Wait for agent to finish. It will cancel some blob operations
	xlog_info("Exiting agent");
	agent_test_exit();

	EVP_BlobRequestHttpExt_free(request);
}

int
setup(void **state)
{
	agent_test_setup();
	return 0;
}

int
main(void)
{
	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(cancel_blob_operation_in_progress),
	};

	// setup and run tests
	return cmocka_run_group_tests(tests, setup, NULL);
}
