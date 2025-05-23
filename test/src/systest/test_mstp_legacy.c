/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <internal/util.h>

#include "agent_test.h"
#include "blob.h"
#include "evp/sdk.h"
#include "module_instance_impl.h"
#include "mqtt_custom.h"
#include "req.h"
#include "xlog.h"

#define DEVICE_ID    "10001"
#define MODULE_NAME  "requester"
#define FILENAME     "some-filename"
#define STORAGE_NAME "storage-name"
#define SOME_SAS_URL                                                          \
	"https://evpstoragecontainer.blob.core.windows.net/evpcontainer/"     \
	"blob_test"

enum test_mstp_payloads {
	MSTP_REQUEST_1,
	MSTP_REQUEST_TOPIC_1,
	MSTP_RESPONSE_1,
};

struct test_context {
	struct EVP_client *h;
	struct evp_agent_context *agent;
	EVP_RPC_ID reqid;
};

#define REQID_FMT "%s"

#define EVP1_MSTP_REQUEST_1                                                   \
	"{"                                                                   \
	"\"method\":\"StorageToken\","                                        \
	"\"params\":{"                                                        \
	"\"filename\":\"" FILENAME "\","                                      \
	"\"moduleInstanceName\":\"" MODULE_NAME "\""                          \
	"}"                                                                   \
	"}"

#define EVP1_MSTP_REQUEST_TOPIC_1 "v1/devices/me/rpc/request/" REQID_FMT

#define EVP1_MSTP_RESPONSE_1                                                  \
	"{"                                                                   \
	"\"method\":\"StorageToken\","                                        \
	"\"params\":{"                                                        \
	"\"URL\":\"" SOME_SAS_URL "\","                                       \
	"\"headers\":{\"x-ms-blob-type\":"                                    \
	"\"BlockBlob\"},"                                                     \
	"\"cert\":\"56176780-9747-11ed-9bd5-"                                 \
	"5f138e81521e\""                                                      \
	"}"                                                                   \
	"}"

static void *user_data = "some-user-data";
static const char reqid_signal[] = "evp_send_storagetoken_request";
static struct test_context g_ctxt;

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

unsigned int
__wrap_blob_put(struct blob_work *wk,
		unsigned int (*do_put)(struct blob_work *, int))
{
	agent_write_to_pipe(wk->url);
	return BLOB_RESULT_SUCCESS;
}

static void
blob_cb(EVP_BLOB_CALLBACK_REASON reason, const void *vp, void *userData)
{
	check_expected(reason);
	check_expected(userData);
}

static void
agent_poll_formatted_payload(agent_test_verify_t verify, unsigned int id,
			     const char *reqid)
{
	char *payload;
	payload = agent_get_payload_formatted(id, reqid);
	agent_poll(verify, payload);
	free(payload);
}

static void
check_request_and_respond(struct test_context *ctxt)
{
	char *payload;
	char *reqid_str;

	agent_poll(verify_equals, reqid_signal);

	xasprintf(&reqid_str, "%lu", ctxt->reqid);

	// wait for the mstp request on mqtt
	agent_poll_formatted_payload(verify_equals, MSTP_REQUEST_TOPIC_1,
				     reqid_str);
	agent_poll_formatted_payload(verify_equals, MSTP_REQUEST_1, reqid_str);

	payload = agent_get_payload_formatted(MSTP_RESPONSE_1, reqid_str);
	agent_send_storagetoken_response(ctxt->agent, payload, reqid_str);
	free(payload);
	free(reqid_str);
}

/**
 * The goal of this test is to be sure that the EVP SDK supports
 * EVP1 legacy mstp. It means that storage_name field is optional.
 * When a module send a blob operation with `storage_name = NULL`
 * the agent will send a request without this field.
 *
 * This test is only executed for EVP1
 * This test complements test_mstp.c
 */
void
test_mstp_evp1_legacy(void **state)
{

	if (agent_test_get_hub_type() == EVP_HUB_TYPE_EVP2_TB) {
		/* This test only applies for evp1 */
		return;
	}

	struct test_context *ctxt = *state;
	// make a blob request
	EVP_RESULT result;

	struct EVP_BlobRequestEvpExt request;
	request.remote_name = FILENAME;
	// storage_name is not required for evp1 (legacy)
	request.storage_name = NULL;

	// make a local store
	struct EVP_BlobLocalStore localStore;
	localStore.filename = FILENAME;

	// the blob operation should fire an mSTP token request
	result = EVP_blobOperation(ctxt->h, EVP_BLOB_TYPE_EVP_EXT,
				   EVP_BLOB_OP_PUT, &request, &localStore,
				   blob_cb, user_data);
	assert_int_equal(result, EVP_OK);

	// Expected after 2 other requests
	check_request_and_respond(ctxt);

	// wait for the http request
	agent_poll(verify_equals, SOME_SAS_URL);

	// wait for the blob_cb
	expect_value(blob_cb, reason, EVP_BLOB_CALLBACK_REASON_DONE);
	expect_value(blob_cb, userData, user_data);

	EVP_processEvent(ctxt->h, 1000);
}

int
__wrap_evp_send_storagetoken_request(struct evp_agent_context *agent,
				     struct request *req, JSON_Value *v)
{
	int __real_evp_send_storagetoken_request(
		struct evp_agent_context * agent, struct request * req,
		JSON_Value * v);

	g_ctxt.reqid = req->id;
	agent_write_to_pipe(reqid_signal);
	return __real_evp_send_storagetoken_request(agent, req, v);
}

int
setup(void **state)
{
	struct test_context *ctxt = *state = &g_ctxt;

	agent_test_setup();
	agent_register_payload(MSTP_REQUEST_1, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_MSTP_REQUEST_1);
	agent_register_payload(MSTP_REQUEST_TOPIC_1, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_MSTP_REQUEST_TOPIC_1);
	agent_register_payload(MSTP_RESPONSE_1, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_MSTP_RESPONSE_1);

	// start agent
	ctxt->agent = agent_test_start();

	// create instance
	ctxt->h = evp_agent_add_instance(ctxt->agent, MODULE_NAME);
	assert_non_null(ctxt->h);
	return 0;
}

int
teardown(void **state)
{
	// wait for agent to finish
	agent_test_exit();
	return 0;
}

int
main(void)
{
	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_mstp_evp1_legacy),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup, teardown);
}
