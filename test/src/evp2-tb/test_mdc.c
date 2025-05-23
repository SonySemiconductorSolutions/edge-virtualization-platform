/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <inttypes.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <cmocka.h>
#include <evp/agent.h>
#include <parson.h>

#include <internal/util.h>

#include "agent_internal.h"
#include "direct_command.h"
#include "fsutil.h"
#include "hub.h"
#include "mqtt.h"
#include "req.h"
#include "xlog.h"

#define MDC_METHOD   "test-method"
#define MDC_INSTANCE "test-instance"

void hub_evp2_tb_on_message(struct evp_agent_context *ctxt, const char *topic,
			    int packet_id, int qos_level, const char *payload);

const char *req_payload_fmt = "{"
			      "  \"method\": \"evp-c2d\","
			      "  \"params\": {"
			      "    \"direct-command-request\":{"
			      "      \"reqid\": \"%" PRIu64 "\","
			      "      \"method\": \"" MDC_METHOD "\","
			      "      \"instance\": \"" MDC_INSTANCE "\","
			      "      \"params\": \"\""
			      "    }"
			      "  }"
			      "}";
const char *res_payload_fmt =
	"{\"direct-command-response\":{\"status\":\"ok\",\"reqid\":"
	"\"%" PRIu64 "\",\"response\":\"response-%" PRIu64 "\"}}";

void
__wrap_evp_process_direct_command_request(
	struct evp_agent_context *ctxt, struct direct_command_request *dc_req)
{
	check_expected(dc_req->reqid);
	check_expected(dc_req->instance);
	check_expected(dc_req->method);
	function_called();
}

int
__wrap_request_insert(struct request *req)
{
	check_expected(req->id);
	check_expected(req->payload);
	request_free(req);
	function_called();
	return 0;
}

/**
 * Common mdc request test
 *
 * @param[in] topicid: topic id of the mocked received request
 * @param[in] reqid: request id of the mdc request
 * @param[in] should_ignore: if is expected to ignore request
 */
void
test_mdc_request(struct evp_agent_context *ctxt, EVP_RPC_ID topicid,
		 EVP_RPC_ID reqid, bool should_ignore)
{
	char *req_payload;
	char *topic;

	xasprintf(&topic, "v1/devices/me/rpc/request/%" PRIu64, topicid);
	xasprintf(&req_payload, req_payload_fmt, reqid);

	if (!should_ignore) {
		expect_value(__wrap_evp_process_direct_command_request,
			     dc_req->reqid, reqid);
		expect_string(__wrap_evp_process_direct_command_request,
			      dc_req->instance, MDC_INSTANCE);
		expect_string(__wrap_evp_process_direct_command_request,
			      dc_req->method, MDC_METHOD);
		expect_function_call(
			__wrap_evp_process_direct_command_request);
	}

	hub_evp2_tb_on_message(ctxt, topic, 0, 0, req_payload);

	free(req_payload);
	free(topic);
}

/**
 * Common mdc response test
 *
 * If topic id is 0, no response is expected to be sent.
 *
 * @param[in] topicid: topic id where the response is expected to be
 * @param[in] reqid: request id of the mdc response
 */
void
test_mdc_response(struct evp_agent_context *ctxt, EVP_RPC_ID topicid,
		  EVP_RPC_ID reqid)
{
	char *res_payload = NULL;
	char *response = NULL;

	xasprintf(&response, "response-%" PRIu64, reqid);
	xasprintf(&res_payload, res_payload_fmt, reqid, reqid);
	expect_value(__wrap_request_insert, req->id, topicid);
	expect_string(__wrap_request_insert, req->payload, res_payload);
	expect_function_call(__wrap_request_insert);

	struct direct_command_response *res = direct_command_response_ctor(
		reqid, response, DIRECT_COMMAND_RESPONSE_STATUS_OK,
		MDC_INSTANCE);

	ctxt->hub->send_direct_command_response(ctxt->transport_ctxt, res);
	direct_command_response_dtor(res);

	free(res_payload);
	free(response);
}

void
test_mdc_req_mapping(void **state)
{
	/*
	 * Send same request twice.
	 * The second identical request should be dropped.
	 */
	test_mdc_request(*state, 0, 1234, false); // First request
	test_mdc_request(*state, 1, 1234, true);  // Second request
	test_mdc_response(*state, 0, 1234);       // Reply to first request
}

#define MDC_REQUEST_CAPACITY 16

void
test_mdc_multi_req_discard_oldest(void **state)
{
	EVP_RPC_ID topicid = 0;
	EVP_RPC_ID reqid = 1101;

	/* Fill up map buffer */
	for (int i = 0; i < MDC_REQUEST_CAPACITY + 1; i++) {
		test_mdc_request(*state, topicid, reqid, false);

		reqid++;
		topicid++;
	}

	topicid = 1; // first request should have been discarded
	reqid = 1102;
	for (int i = 0; i < MDC_REQUEST_CAPACITY; i++) {
		test_mdc_response(*state, topicid, reqid);

		reqid++;
		topicid++;
	}
}

void
test_mdc_multi_req_unordered_response(void **state)
{
	EVP_RPC_ID topicid = 2001;
	EVP_RPC_ID reqid = 1101;

	/* Fill up map buffer */
	for (int i = 0; i < 5; i++) {
		test_mdc_request(*state, topicid, reqid, false);

		reqid++;
		topicid++;
	}

	test_mdc_response(*state, 2004, 1104);
	test_mdc_response(*state, 2002, 1102);
	test_mdc_response(*state, 2003, 1103);
	test_mdc_response(*state, 2005, 1105);
}

static int
setup(void **state)
{
	putenv("EVP_MQTT_HOST=test.mqtt.host.value");
	putenv("EVP_MQTT_PORT=1234");
	putenv("EVP_IOT_PLATFORM=TB");
	struct evp_agent_context *ctxt = evp_agent_setup("test");
	evp_agent_start(ctxt);
	*state = ctxt;
	return 0;
}

static int
teardown(void **state)
{
	evp_agent_stop(*state);
	evp_agent_free(*state);
	return 0;
}

int
main(void)
{

	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_mdc_req_mapping),
		cmocka_unit_test(test_mdc_multi_req_discard_oldest),
		cmocka_unit_test(test_mdc_multi_req_unordered_response),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup, teardown);
}
