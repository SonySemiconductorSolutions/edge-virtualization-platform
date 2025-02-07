/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE

#include <assert.h>
#include <inttypes.h>
#include <libweb/http.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <evp/sdk_sys.h>
#include <parson.h>

#include <internal/util.h>

#include "agent_internal.h"
#include "agent_test.h"
#include "hub.h"
#include "websrv/websrv.h"
#include "xlog.h"

#define REQID_FMT "%s"

#define DEVICE_ID    "10001"
#define MODULE_NAME  "$system"
#define FILENAME     "some-filename"
#define STORAGE_NAME "storage-name"
#define SOME_SAS_URL                                                          \
	"https://evpstoragecontainer.blob.core.windows.net/evpcontainer/"     \
	"blob_test"

#define EVP1_MSTP_REQUEST_1                                                   \
	"{"                                                                   \
	"\"method\":\"StorageToken\","                                        \
	"\"params\":{"                                                        \
	"\"filename\":\"" FILENAME "\","                                      \
	"\"moduleInstanceName\":\"" MODULE_NAME "\","                         \
	"\"storageName\":\"" STORAGE_NAME "\""                                \
	"}"                                                                   \
	"}"

#define EVP1_MSTP_REQUEST_TOPIC_1 "v1/devices/me/rpc/request/" REQID_FMT

#define EVP1_MSTP_RESPONSE_1                                                  \
	"{"                                                                   \
	"\"method\":\"StorageToken\","                                        \
	"\"params\":{"                                                        \
	"\"URL\":\"%s\","                                                     \
	"\"headers\":{\"x-ms-blob-type\":"                                    \
	"\"BlockBlob\"},"                                                     \
	"\"cert\":\"56176780-9747-11ed-9bd5-"                                 \
	"5f138e81521e\""                                                      \
	"}"                                                                   \
	"}"

#define TB_MSTP_REQUEST_1                                                     \
	"{"                                                                   \
	"\"method\":\"evp-d2c\","                                             \
	"\"params\":{"                                                        \
	"\"storagetoken-request\":{"                                          \
	"\"reqid\":\"" REQID_FMT "\","                                        \
	"\"filename\":\"" FILENAME "\","                                      \
	"\"moduleInstanceId\":\"" MODULE_NAME "\","                           \
	"\"key\":\"" STORAGE_NAME "\""                                        \
	"}"                                                                   \
	"}"                                                                   \
	"}"

#define TB_MSTP_REQUEST_TOPIC_1 "v1/devices/me/rpc/request/" REQID_FMT

#define TB_MSTP_RESPONSE_1                                                    \
	"{"                                                                   \
	"\"storagetoken-response\":{"                                         \
	"\"reqid\":\"" REQID_FMT "\","                                        \
	"\"status\":\"ok\","                                                  \
	"\"URL\":\"%s\","                                                     \
	"\"headers\":{\"x-ms-blob-type\":"                                    \
	"\"BlockBlob\"}"                                                      \
	"}"                                                                   \
	"}"

enum test_mstp_payloads {
	MSTP_REQUEST_1,
	MSTP_REQUEST_TOPIC_1,
	MSTP_RESPONSE_1,
};

/* Arbitrary number. */
enum { BLOB_LEN = 4096, MAGIC = 'F' };

struct test {
	unsigned short port;
	char *url;
	enum SYS_result result;
	struct SYS_client *c;
	struct evp_agent_context *ctxt;
	bool done;
	EVP_RPC_ID reqid;
	char *evp1_response;
	char *evp2_response;
} test;

struct webclient_context;

static const char reqid_signal[] = "evp_send_storagetoken_request";

void
__wrap_webclient_perform(FAR struct webclient_context *ctx)
{
	void __real_webclient_perform(FAR struct webclient_context *);

	__real_webclient_perform(ctx);
}

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

static enum SYS_result
blob_cb(struct SYS_client *c, struct SYS_blob_data *blob,
	enum SYS_callback_reason reason, void *user)
{
	struct test *test = user;

	switch (reason) {
	case SYS_REASON_MORE_DATA:
		memset(blob->blob_buffer, MAGIC, blob->len);
		break;

	case SYS_REASON_FINISHED:
		test->done = true;
		agent_write_to_pipe("blob_cb");
		break;

	case SYS_REASON_TIMEOUT:
	case SYS_REASON_ERROR:
		abort();
	}

	return SYS_RESULT_OK;
}

static void *
sysapp(void *args)
{
	struct test *test = args;
	enum SYS_result *result = &test->result;

	*result = SYS_put_blob_mstp(test->c, STORAGE_NAME, FILENAME, BLOB_LEN,
				    blob_cb, test);

	if (*result) {
		fprintf(stderr, "%s: SYS_put_blob failed with %s\n", __func__,
			SYS_result_tostr(*result));
		goto end;
	}

	for (;;) {
		*result = SYS_process_event(test->c, -1);

		switch (*result) {
		case SYS_RESULT_OK:
			if (test->done) {
				goto end;
			}

			break;
		case SYS_RESULT_TIMEDOUT:
			break;

		default:
			fprintf(stderr,
				"%s: SYS_process_event failed with %s\n",
				__func__, SYS_result_tostr(*result));
			goto end;
		}
	}

end:

	return NULL;
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
test_sysapp_blob_put_mstp(void **state)
{
	struct test *test = *state;

	pthread_t thread;

	assert_int_equal(pthread_create(&thread, NULL, sysapp, test), 0);

	char *payload;
	char *reqid_str;

	agent_poll(verify_equals, reqid_signal);
	xasprintf(&reqid_str, "%lu", test->reqid);

	// wait for the mstp request on mqtt
	agent_poll_formatted_payload(verify_equals, MSTP_REQUEST_TOPIC_1,
				     reqid_str);
	agent_poll_formatted_payload(verify_equals, MSTP_REQUEST_1, reqid_str);

	if (agent_test_get_hub_type() == EVP_HUB_TYPE_EVP2_TB) {
		payload = agent_get_payload_formatted(MSTP_RESPONSE_1,
						      reqid_str, test->url);
	} else {
		payload = agent_get_payload_formatted(MSTP_RESPONSE_1,
						      test->url);
	}

	agent_send_storagetoken_response(test->ctxt, payload, reqid_str);
	free(payload);
	free(reqid_str);

	agent_poll(verify_equals, "on_put");
	agent_poll(verify_equals, "blob_cb");

	assert_int_equal(pthread_join(thread, NULL), 0);
	assert_int_equal(test->result, SYS_RESULT_OK);
}

static int
on_put(const struct http_payload *p, struct http_response *r, void *user)
{
	/* NuttX webclient requires a body for PUT responses, even if not
	 * needed. */
	static const char body[] = "hello!";

	/* Notify the test that this callback was actually called */
	agent_write_to_pipe("on_put");

	FILE *f = fopen(p->u.put.tmpname, "rb");
	char b;

	assert(f);

	for (int i = 0; i < BLOB_LEN; i++) {

		assert(fread(&b, 1, 1, f));
		assert(b == MAGIC);
	}

	assert(!fread(&b, 1, 1, f));
	assert(feof(f) && !ferror(f));
	assert(!fclose(f));

	*r = (struct http_response){
		.status = HTTP_STATUS_OK,
		.buf.ro = body,
		.n = strlen(body),
	};

	return 0;
}

static int
setup(void **state)
{
	if (websrv_setup(0)) {
		fprintf(stderr, "%s: websrv_setup failed\n", __func__);
		return -1;
	}

	if (websrv_add_route("/test", HTTP_OP_PUT, on_put, NULL)) {
		fprintf(stderr, "%s: websrv_add_route failed\n", __func__);
		return -1;
	}

	if (websrv_get_port(&test.port)) {
		fprintf(stderr, "%s: websrv_get_port failed\n", __func__);
		return -1;
	}

	if (websrv_start()) {
		fprintf(stderr, "%s: websrv_start failed\n", __func__);
		return -1;
	}

	if (asprintf(&test.url, "http://localhost:%hu/test", test.port) < 0) {
		fprintf(stderr, "%s: asprintf(3) failed\n", __func__);
		return -1;
	}

	agent_test_setup();

	agent_register_payload(MSTP_REQUEST_1, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_MSTP_REQUEST_1);
	agent_register_payload(MSTP_REQUEST_TOPIC_1, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_MSTP_REQUEST_TOPIC_1);
	agent_register_payload(MSTP_RESPONSE_1, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_MSTP_RESPONSE_1);

	agent_register_payload(MSTP_REQUEST_1, EVP_HUB_TYPE_EVP2_TB,
			       TB_MSTP_REQUEST_1);
	agent_register_payload(MSTP_REQUEST_TOPIC_1, EVP_HUB_TYPE_EVP2_TB,
			       TB_MSTP_REQUEST_TOPIC_1);
	agent_register_payload(MSTP_RESPONSE_1, EVP_HUB_TYPE_EVP2_TB,
			       TB_MSTP_RESPONSE_1);

	test.ctxt = agent_test_start();

	if (!test.ctxt) {
		fprintf(stderr, "%s: agent_test_start failed\n", __func__);
		return -1;
	}

	test.c = evp_agent_register_sys_client(test.ctxt);

	if (!test.c) {
		fprintf(stderr, "%s: evp_agent_register_sysapp failed\n",
			__func__);
		return -1;
	}

	*state = &test;
	return 0;
}

int
__wrap_evp_send_storagetoken_request(struct evp_agent_context *agent,
				     struct request *req, JSON_Value *v)
{
	int __real_evp_send_storagetoken_request(
		struct evp_agent_context * agent, struct request * req,
		JSON_Value * v);

	test.reqid = req->id;
	agent_write_to_pipe(reqid_signal);
	return __real_evp_send_storagetoken_request(agent, req, v);
}

static int
teardown(void **state)
{
	struct test *test = *state;

	if (evp_agent_unregister_sys_client(test->ctxt, test->c)) {
		fprintf(stderr, "%s: evp_agent_unregister_sysapp failed\n",
			__func__);
	}

	free(test->evp1_response);
	free(test->evp2_response);
	free(test->url);
	agent_test_exit();

	if (websrv_stop()) {
		fprintf(stderr, "%s: websrv_stop failed\n", __func__);
		return -1;
	}

	websrv_teardown();
	return 0;
}

int
main(void)
{
	static const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_sysapp_blob_put_mstp),
	};

	return cmocka_run_group_tests(tests, setup, teardown);
}
