/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <internal/util.h>

#include "agent_test.h"
#include "blob.h"
#include "evp/sdk.h"
#include "mqtt_custom.h"
#include "xlog.h"

#define DEVICE_ID   "10001"
#define MODULE_NAME "requester"
#define FILENAME    "some-filename"

#define ERROR_MESSAGE                                                         \
	"ModuleInstanceStorageId[moduleStorageKey=null, "                     \
	"moduleInstanceId=17cef5e7-037a-41e3-9e11-d41d47d0a1eb] does not "    \
	"exist"

#define REQID_FMT     "%s"
#define REQID_EVP1_TB REQID_FMT
#define REQID_EVP2_TB REQID_FMT

enum test_mstp_null_payloads { MSTP_REQ, MSTP_RES };

static void *user_data = "some-user-data";

static const char mstp_request_tb[] =
	"{"
	"\"method\":\"evp-d2c\","
	"\"params\":{"
	"\"storagetoken-request\":{"
	"\"reqid\":\"" REQID_EVP2_TB "\","
	"\"filename\":\"" FILENAME "\","
	"\"moduleInstanceId\":\"" MODULE_NAME "\""
	"}"
	"}"
	"}";

static const char mstp_response_tb[] =
	"{"
	"\"storagetoken-response\":{"
	"\"reqid\":\"" REQID_EVP2_TB "\","
	"\"status\":\"error\","
	"\"errorMessage\":\"" ERROR_MESSAGE "\","
	"\"URL\":null,"
	"\"headers\":null"
	"}"
	"}";

enum MQTTErrors
__wrap_mqtt_publish(struct mqtt_client *client, const char *topic_name,
		    const void *application_message,
		    size_t application_message_size, uint8_t publish_flags)
{
	agent_write_to_pipe(topic_name);

	char *payload = xstrndup((char *)application_message,
				 application_message_size);
	xlog_info("MQTT publish %s: %s", topic_name, payload);
	agent_write_to_pipe(payload);
	free(payload);

	return MQTT_OK;
}

static void
blob_cb(EVP_BLOB_CALLBACK_REASON reason, const void *vp, void *userData)
{
	struct EVP_BlobResultEvp *lvp = (struct EVP_BlobResultEvp *)vp;

	check_expected(reason);
	check_expected(lvp->result);
	check_expected(lvp->error);
	check_expected(userData);
}

static void
test_mstp_null_evp2(void)
{
	// start agent
	struct evp_agent_context *ctxt = agent_test_start();

	// create instance
	struct EVP_client *h = evp_agent_add_instance(ctxt, MODULE_NAME);
	assert_non_null(h);

	// make a blob request
	EVP_RESULT result;

	struct EVP_BlobRequestEvpExt request;
	request.remote_name = FILENAME;
	request.storage_name = NULL; // will cause the error

	// make a local store
	struct EVP_BlobLocalStore localStore;
	localStore.filename = FILENAME;

	// the blob operation should fire an mSTP token request
	result = EVP_blobOperation(h, EVP_BLOB_TYPE_EVP_EXT, EVP_BLOB_OP_PUT,
				   &request, &localStore, blob_cb, user_data);

	assert_int_equal(result, EVP_OK);

	// Wait for the rpc request and get the reqid from topic (compatible
	// between EVP1 and EVP2)
	char *msg;
	uintmax_t reqid;
	msg = agent_poll_fetch(verify_contains, "v1/devices/me/rpc/request/");
	assert_int_equal(sscanf(msg, "v1/devices/me/rpc/request/%ju", &reqid),
			 1);
	assert_non_null(msg);
	free(msg);

	char *reqid_str;
	assert_int_not_equal(asprintf(&reqid_str, "%ju", reqid), -1);

	// wait for the mstp request on mqtt
	char *payload;
	payload = agent_get_payload_formatted(MSTP_REQ, reqid_str);
	agent_poll(verify_equals, payload);
	free(payload);

	// send mstp response
	payload = agent_get_payload_formatted(MSTP_RES, reqid_str);
	agent_send_storagetoken_response(ctxt, payload, reqid_str);
	free(payload);

	free(reqid_str);

	// wait for the blob_cb
	expect_value(blob_cb, reason, EVP_BLOB_CALLBACK_REASON_DONE);
	expect_value(blob_cb, lvp->result, EVP_BLOB_CALLBACK_REASON_EXIT);
	expect_value(blob_cb, lvp->error, 5);
	expect_value(blob_cb, userData, user_data);

	EVP_processEvent(h, 1000);
}

void
test_mstp_null(void **state)
{
	switch (agent_test_get_hub_type()) {

	case EVP_HUB_TYPE_EVP2_TB:
		test_mstp_null_evp2();
		break;

	case EVP_HUB_TYPE_EVP1_TB:
		printf("This test is not supported for EVP1.\n");
		break;

	default:
		break;
	}
}

int
setup(void **state)
{
	agent_test_setup();

	agent_register_payload(MSTP_REQ, EVP_HUB_TYPE_EVP2_TB,
			       mstp_request_tb);

	agent_register_payload(MSTP_RES, EVP_HUB_TYPE_EVP2_TB,
			       mstp_response_tb);

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
		cmocka_unit_test(test_mstp_null),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup, teardown);
}
