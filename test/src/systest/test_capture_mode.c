/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <internal/util.h>

#include "webclient/webclient.h"

#include "../sync.h"
#include "agent_test.h"
#include "evp/sdk.h"
#include "hub.h"
#include "mqtt.h"
#include "path.h"
#include "xlog.h"
#include "xpthread.h"

enum {
	IOT_PLATFORM_LOWERCASE,
};

/*
 * Test capture mode
 *
 * This test is design to mimick the expected capture mode for CamFW.
 * The lifecycle of the agent is as such:
 * 1. Device wakes up
 * 2. Agent starts with no conection to the hub but HTTP enable (capture mode)
 * 3. Agent starts module(s) from persistent deployment
 * 4. Module(s) upload blobs
 * 5. Agent stops
 * 6. Device goes back to sleep
 */
#define TEST_PROCESS_EVENT_TIMEOUT 10000

#define RECONCILE_STATUS_EVT "reconcileStatus"

#define TEST_DEPLOYMENT_ID "4619b7ed-02a9-8c8f-44cd-000000000001"
#define TEST_HTTP_GET_URL  "https://baz/boo"
#define TEST_HTTP_PUT_URL  "http://foobar"
#define TEST_HTTP_GET_FILE "foobar.txt"
#define TEST_HTTP_PUT_FILE "boofar.bin"

#define HTTP_STATUS_OK 200

struct test_context {
	struct evp_agent_context *agent;
	struct EVP_client *sdk_handle;
	char *filename;
	bool mqtt_publish_called;
};

static struct test_context g_context;

/* This is defined weak here to allow it to be intercepted in specific tests */
enum MQTTErrors
__wrap_mqtt_publish(struct mqtt_client *client, const char *topic_name,
		    const void *application_message,
		    size_t application_message_size, uint8_t publish_flags)
{
	g_context.mqtt_publish_called = true;
	if (!get_connected()) {
		return MQTT_ERROR_SOCKET_ERROR;
	}
	return MQTT_OK;
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
test_capture_mode(void **state)
{
	struct test_context *ctxt = &g_context;

	// prepare tests
	char cb_data;

	// test HTTP GET to file
	struct EVP_BlobRequestHttp request = {
		.url = TEST_HTTP_GET_URL,
	};

	struct EVP_BlobLocalStore localstore = {
		.filename = ctxt->filename,
	};

	EVP_RESULT result;
	// Blob operations are enabled in capture mode
	result = EVP_blobOperation(ctxt->sdk_handle, EVP_BLOB_TYPE_HTTP,
				   EVP_BLOB_OP_GET, &request, &localstore,
				   blob_cb, &cb_data);
	assert_int_equal(result, EVP_OK);

	// Expect processed blob to succeed
	expect_value(blob_cb, reason, EVP_BLOB_CALLBACK_REASON_DONE);
	expect_value(blob_cb, result->result, EVP_BLOB_RESULT_SUCCESS);
	expect_value(blob_cb, result->http_status, HTTP_STATUS_OK);
	expect_value(blob_cb, result->error, 0);
	result =
		EVP_processEvent(ctxt->sdk_handle, TEST_PROCESS_EVENT_TIMEOUT);
	assert_int_equal(result, EVP_OK);

	// Ensure no mqtt transmission occured
	assert_false(g_context.mqtt_publish_called);
}

static int
on_reconcile_status(const void *args, void *user)
{
	const struct reconcileStatusNotify *notify = args;
	char *msg;
	xasprintf(&msg, RECONCILE_STATUS_EVT "@%s:%s", notify->deploymentId,
		  notify->reconcileStatus);
	agent_write_to_pipe(msg);
	free(msg);
	return 0;
}

int
setup_suite(void **state)
{
	int rv;
	struct test_context *ctxt = &g_context;

	agent_register_payload(IOT_PLATFORM_LOWERCASE, EVP_HUB_TYPE_EVP1_TB,
			       "evp1");
	agent_register_payload(IOT_PLATFORM_LOWERCASE, EVP_HUB_TYPE_EVP2_TB,
			       "tb");

	agent_test_enable_capture_mode();
	agent_test_setup();

	const char *desired = path_get(DESIRED_TWINS_PATH_ID);
	// Forcibly create the destination dir as agent hasn't started yet.
	assert_int_equal(systemf("mkdir -p %s", path_get(TWINS_PATH_ID)), 0);
	// Initialize current deployment in evp data dir/twins/desired
	rv = systemf("cp src/systest/test_capture_mode_desired.%s.json "
		     "%s",
		     agent_get_payload(IOT_PLATFORM_LOWERCASE), desired);
	assert_int_equal(0, rv);
	xasprintf(&ctxt->filename, "%s/%s", path_get(MODULE_INSTANCE_PATH_ID),
		  TEST_HTTP_GET_FILE);
	rv = systemf("mkdir `dirname %s`", ctxt->filename);
	assert_int_equal(0, rv);
	rv = systemf("touch %s", ctxt->filename);
	assert_int_equal(0, rv);

	// start agent
	ctxt->agent = *state = agent_test_start();
	evp_agent_notification_subscribe(g_context.agent,
					 "deployment/reconcileStatus",
					 on_reconcile_status, NULL);

	// create backdoor instance
	ctxt->sdk_handle =
		evp_agent_add_instance(ctxt->agent, "backdoor-capture");
	assert_non_null(ctxt->sdk_handle);

	// Wait for deployment completion
	agent_poll(verify_contains,
		   RECONCILE_STATUS_EVT "@" TEST_DEPLOYMENT_ID ":ok");
	return 0;
}

int
teardown_suite(void **state)
{
	struct test_context *ctxt = &g_context;
	// wait for agent to finish
	agent_test_exit();
	free(ctxt->filename);
	return 0;
}

int
main(void)
{
	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_capture_mode),
	};
	// setup and run tests
	return cmocka_run_group_tests(tests, setup_suite, teardown_suite);
}
