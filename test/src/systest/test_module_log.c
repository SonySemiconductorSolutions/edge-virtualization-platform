/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <parson.h>

#include <internal/util.h>

#include "agent_test.h"
#include "fsutil.h"
#include "module_log_cap.h"
#include "module_log_queue.h"
#include "module_log_streaming.h"
#include "mqtt_custom.h"

enum test_module_log_payloads {
	DEPLOYMENT_MANIFEST_1,
};

#define LOG_APP      "07fe77d5-7117-4326-9042-47fda5dd9bf5"
#define LOG_APP_INV  "APP-not-installed"
#define LOG_1_STREAM "stdout"
#define LOG_1_MSG    "A log message"
#define LOG_2_STREAM "stderr"
#define LOG_2_MSG    "ERROR:Something bad happened"
#define LOG_TIME     "2023-01-01T00:00:00.000000Z"
#define DEPLOYMENT_FILE_EVP1                                                  \
	"src/systest/test_telemetry_deployment_payload-evp1.json"
#define DEPLOYMENT_FILE_EVP2                                                  \
	"src/systest/test_telemetry_deployment_payload-evp2.json"

/* RPC (direct comand) can not repeat reqId number, otherwise
 * the agent discards the request.
 * So use a global counter to avoid this case
 */
static int req_id_counter = 0;
static char *deployment_evp1 = NULL;
static char *deployment_evp2 = NULL;

#define TB_LOG1                                                               \
	"{"                                                                   \
	"\"log\":\"" LOG_1_MSG "\","                                          \
	"\"app\":\"" LOG_APP "\","                                            \
	"\"stream\":\"" LOG_1_STREAM "\","                                    \
	"\"time\":\"" LOG_TIME "\""                                           \
	"}"

#define TB_LOG2                                                               \
	"{"                                                                   \
	"\"log\":\"" LOG_2_MSG "\","                                          \
	"\"app\":\"" LOG_APP "\","                                            \
	"\"stream\":\"" LOG_2_STREAM "\","                                    \
	"\"time\":\"" LOG_TIME "\""                                           \
	"}"

#define LOG_ENABLE_PAYLOAD_TRUE_TB_EVP1  "{\"log_enable\":true}"
#define LOG_ENABLE_PAYLOAD_TRUE_TB_EVP2  "{\\\"log_enable\\\":true}"
#define LOG_ENABLE_PAYLOAD_FALSE_TB_EVP1 "{\"log_enable\":false}"
#define LOG_ENABLE_PAYLOAD_FALSE_TB_EVP2 "{\\\"log_enable\\\":false}"
#define MDC_RESPONSE_VALUE_EMPTY_TB_EVP1 "{}"
#define MDC_RESPONSE_VALUE_EMPTY_TB_EVP2 "\"{}\""
#define MDC_RESPONSE_ERROR_INSTANCE_NOT_FOUND_TB_EVP1                         \
	"{\"error\":\"Instance not found\"}"
#define MDC_RESPONSE_ERROR_INSTANCE_NOT_FOUND_TB_EVP2                         \
	"{\\\"error\\\":\\\"Instance not found\\\"}"
#define MDC_MSG_LOG_FORMAT_TB_EVP1                                            \
	"{"                                                                   \
	"\"method\": \"ModuleMethodCall\","                                   \
	"  \"params\": {"                                                     \
	"    \"moduleMethod\": \"$agent/%s\","                                \
	"    \"moduleInstance\": \"%s\","                                     \
	"    \"params\": %s}"                                                 \
	"}"
#define MDC_MSG_LOG_FORMAT_TB_EVP2                                            \
	"{"                                                                   \
	"  \"direct-command-request\": {"                                     \
	"  \"reqid\":\"%d\","                                                 \
	"  \"method\":\"$agent/%s\","                                         \
	"  \"instance\":\"%s\","                                              \
	"  \"params\":\"%s\"}"                                                \
	"}"

static const struct test_input_set {
	const char *log_1;
	const char *log_2;
	const char *log_enable_payload_true;
	const char *log_enable_payload_false;
	const char *mdc_response_value_empty;
	const char *mdc_response_error_instance_not_found;
	const char *mdc_msg_log_format;
} test_inputs[] = {
	[EVP_HUB_TYPE_EVP1_TB] =
		{
			.log_1 = TB_LOG1,
			.log_2 = TB_LOG2,
			.log_enable_payload_true =
				LOG_ENABLE_PAYLOAD_TRUE_TB_EVP1,
			.log_enable_payload_false =
				LOG_ENABLE_PAYLOAD_FALSE_TB_EVP1,
			.mdc_response_value_empty =
				MDC_RESPONSE_VALUE_EMPTY_TB_EVP1,
			.mdc_response_error_instance_not_found =
				MDC_RESPONSE_ERROR_INSTANCE_NOT_FOUND_TB_EVP1,
			.mdc_msg_log_format = MDC_MSG_LOG_FORMAT_TB_EVP1,
		},
	[EVP_HUB_TYPE_EVP2_TB] =
		{
			.log_1 = TB_LOG1,
			.log_2 = TB_LOG2,
			.log_enable_payload_true =
				LOG_ENABLE_PAYLOAD_TRUE_TB_EVP2,
			.log_enable_payload_false =
				LOG_ENABLE_PAYLOAD_FALSE_TB_EVP2,
			.mdc_response_value_empty =
				MDC_RESPONSE_VALUE_EMPTY_TB_EVP2,
			.mdc_response_error_instance_not_found =
				MDC_RESPONSE_ERROR_INSTANCE_NOT_FOUND_TB_EVP2,
			.mdc_msg_log_format = MDC_MSG_LOG_FORMAT_TB_EVP2,
		},
};

static char *
mdc_msg_log_evp1(const char *method, const char *instance, bool param)
{
	const struct test_input_set *set = &test_inputs[EVP_HUB_TYPE_EVP1_TB];
	char *payload;
	const char *const param_final =
		strcmp(method, "set")
			? "{}"
			: (param ? set->log_enable_payload_true
				 : set->log_enable_payload_false);

	xasprintf(&payload, set->mdc_msg_log_format, method, instance,
		  param_final);
	return payload;
}

static char *
mdc_msg_log_evp2(int reqid, const char *method, const char *instance,
		 bool param)
{
	const struct test_input_set *set = &test_inputs[EVP_HUB_TYPE_EVP2_TB];
	char *payload;
	const char *const param_final =
		strcmp(method, "set")
			? "{}"
			: (param ? set->log_enable_payload_true
				 : set->log_enable_payload_false);

	xasprintf(&payload, set->mdc_msg_log_format, reqid, method, instance,
		  param_final);
	return payload;
}

static char *
mdc_msg_log(int reqid, const char *method, const char *instance, bool param)
{
	switch (agent_test_get_hub_type()) {
	case EVP_HUB_TYPE_EVP1_TB:
		return mdc_msg_log_evp1(method, instance, param);

	case EVP_HUB_TYPE_EVP2_TB:
		return mdc_msg_log_evp2(reqid, method, instance, param);

	default:
		break;
	}

	return NULL;
}

struct test_module_log_context {
	struct evp_agent_context *agent_ctxt;
	int stdout;
	int stderr;
};

struct test_module_log_context g_module_log_ctxt;

void
__wrap_getrealtime(struct timespec *tp)
{
	/* return UNIX time for 2023-01-01T00:00:00.000000Z */
	tp->tv_nsec = 0;
	tp->tv_sec = 1672531200;
}

static void
cloud_sends_mdc_set_log_enable_evp2_tb(struct test_module_log_context *ctxt,
				       const char *instance_name, bool state)
{
	char *topic;
	xasprintf(&topic, "v1/devices/me/rpc/request/%d", req_id_counter);
	// Keep the same reqid than topic (EVP1 case)
	char *msg = mdc_msg_log(req_id_counter, "set", instance_name, state);
	// direct command request
	char *payload;
	xasprintf(&payload, "{\"method\": \"evp-c2d\", \"params\": %s}", msg);
	evp_agent_send(ctxt->agent_ctxt, topic, payload);
	free(payload);
	free(msg);
	free(topic);
}

static void
cloud_sends_mdc_set_log_enable_evp1_tb(struct test_module_log_context *ctxt,
				       const char *instance_name, bool state)
{
	char *topic;
	xasprintf(&topic, "v1/devices/me/rpc/request/%d", req_id_counter);
	// Keep the same reqid than topic (EVP1 case)
	char *msg = mdc_msg_log(req_id_counter, "set", instance_name, state);

	// direct command request
	evp_agent_send(ctxt->agent_ctxt, topic, msg);
	free(msg);
	free(topic);
}

static void
cloud_sends_mdc_set_log_enable(struct test_module_log_context *ctxt,
			       const char *instance_name, bool state)
{
	/* Global reqId counter to not repeat the number */
	req_id_counter++;

	switch (agent_test_get_hub_type()) {
	case EVP_HUB_TYPE_EVP1_TB:
		cloud_sends_mdc_set_log_enable_evp1_tb(ctxt, instance_name,
						       state);
		break;

	case EVP_HUB_TYPE_EVP2_TB:
		cloud_sends_mdc_set_log_enable_evp2_tb(ctxt, instance_name,
						       state);
		break;

	default:
		break;
	}
}

static void
cloud_sends_mdc_get_log_enable_evp1_tb(struct test_module_log_context *ctxt,
				       const char *instance_name)
{
	char *topic;
	xasprintf(&topic, "v1/devices/me/rpc/request/%d", req_id_counter);
	char *msg = mdc_msg_log(req_id_counter, "get", instance_name, true);

	// direct command request
	evp_agent_send(ctxt->agent_ctxt, topic, msg);
	free(msg);
	free(topic);
}

static void
cloud_sends_mdc_get_log_enable_evp2_tb(struct test_module_log_context *ctxt,
				       const char *instance_name)
{
	char *topic;
	xasprintf(&topic, "v1/devices/me/rpc/request/%d", req_id_counter);
	char *msg = mdc_msg_log(req_id_counter, "get", instance_name, true);
	// direct command request
	char *payload;
	xasprintf(&payload, "{\"method\": \"evp-c2d\", \"params\": %s}", msg);
	evp_agent_send(ctxt->agent_ctxt, topic, payload);
	free(payload);
	free(msg);
	free(topic);
}

static void
cloud_sends_mdc_get_log_enable(struct test_module_log_context *ctxt,
			       const char *instance_name)
{
	/* Global reqId counter to not repeat the number */
	req_id_counter++;

	switch (agent_test_get_hub_type()) {
	case EVP_HUB_TYPE_EVP1_TB:
		cloud_sends_mdc_get_log_enable_evp1_tb(ctxt, instance_name);
		break;

	case EVP_HUB_TYPE_EVP2_TB:
		cloud_sends_mdc_get_log_enable_evp2_tb(ctxt, instance_name);
		break;

	default:
		break;
	}
}

static void
test_module_log(void **state)
{
	struct test_module_log_context *ctxt = *state;
	const enum evp_hub_type hub = agent_test_get_hub_type();
	const struct test_input_set *in_set = &test_inputs[hub];
	(void)ctxt;

	cloud_sends_mdc_get_log_enable(ctxt, LOG_APP);

	switch (hub) {
	case EVP_HUB_TYPE_EVP1_TB:
		/* Fall through. */
	case EVP_HUB_TYPE_EVP2_TB:
		agent_poll(verify_contains, in_set->log_enable_payload_true);
		break;

	default:
		break;
	}

	dprintf(ctxt->stdout, LOG_1_MSG "\n");
	dprintf(ctxt->stderr, LOG_2_MSG "\n");

	struct multi_check set[] = {
		{.value = in_set->log_1},
		{.value = in_set->log_2},
		{.value = NULL}, // List termination
	};
	agent_poll(verify_contains_in_unordered_set, set);
}

static void
test_module_log_inv_instance(void **state)
{
	struct test_module_log_context *ctxt = *state;
	const enum evp_hub_type hub = agent_test_get_hub_type();
	const struct test_input_set *set = &test_inputs[hub];
	(void)ctxt;

	cloud_sends_mdc_set_log_enable(ctxt, LOG_APP_INV, true);

	switch (agent_test_get_hub_type()) {
	case EVP_HUB_TYPE_EVP1_TB:
		/* Fall through. */
	case EVP_HUB_TYPE_EVP2_TB:
		agent_poll(verify_contains,
			   set->mdc_response_error_instance_not_found);
		break;

	default:
		break;
	}
}

/**
 * Feature to test:
 * 		When the queue is full, the oldest messages are discarded
 * 		For this test we will discard only 1 message
 *
 * Steps:
 * 	- Enable log
 * 	- Write a log msg_hello bigger than the half size of the queue
 *  - Write a log msg_bye bigger than the half size of the queue. so it will
 * force to discard the previous one.
 *  - Check msg_bye is reported via telemetry
 *  - Make sure that there are no more telemetries, the first message (hello)
 * was discarded
 */
static void
test_module_log_discard_oldest(void **state)
{
	struct test_module_log_context *ctxt = *state;
	const enum evp_hub_type hub = agent_test_get_hub_type();
	const struct test_input_set *set = &test_inputs[hub];
	(void)ctxt;

	cloud_sends_mdc_get_log_enable(ctxt, LOG_APP);

	switch (agent_test_get_hub_type()) {
	case EVP_HUB_TYPE_EVP1_TB:
		/* Fall through. */
	case EVP_HUB_TYPE_EVP2_TB:
		agent_poll(verify_contains, set->log_enable_payload_true);
		break;

	default:
		break;
	}

	char hello_msg[CONFIG_EVP_AGENT_MODULE_LOG_REPORT_LEN / 2 + 2];
	char bye_msg[CONFIG_EVP_AGENT_MODULE_LOG_REPORT_LEN / 2 + 2];

	/* Prepare log messages */
	memset(hello_msg, 'H', sizeof(hello_msg));
	hello_msg[sizeof(hello_msg) - 2] = '\n';
	hello_msg[sizeof(hello_msg) - 1] = 0;

	memset(bye_msg, 'B', sizeof(bye_msg));
	bye_msg[sizeof(bye_msg) - 2] = '\n';
	bye_msg[sizeof(bye_msg) - 1] = '\0';

	/* Syncronize the telemetry ouptut Why?
	 * We need to be sure that the first message hello is not reported in a
	 * previous slot. So we need to check that the module log output is
	 * done inside the same log period report, to verify that hello message
	 * is not present in the telemetry.
	 *
	 * 	To clarify, the expected behaviour is:
	 * 	- module: log hello_msg
	 * 	- agent: put hello in queue
	 * 	- module: log bye_msg
	 * 	- agent: put bye in queue, remove hello (max size reached)
	 * 	- agent: tigger timer telemetry report (period 1 second)
	 *  - telemetry: {"device/log":[{{"log":"bbbb",...}] (as hello is
	 * discarded)
	 *
	 * 	But we can have this case:
	 * 	- module: log hello_msg
	 * 	- agent: put hello in queue
	 * 	- agent: tigger timer telemetry report (period 1 second)
	 *  - telemetry: {"device/log":[{{"log":"hhhh",...}]  <<== FLAKY
	 * 	- module: log bye_msg
	 * 	- agent: put bye in queue
	 * 	- agent: trigger telemetry report (period 1 seond) report
	 * telemetry
	 *  - telemetry: {"device/log":[{{"log":"bbbb",...}]   <<== FLAKY
	 * test!!! we don't check that the message is discarded
	 *
	 * So adding the SYNC-stamp message, sincronize the commands just
	 * before the trigger timer action, so we can be sure that the message
	 * is discarded
	 *
	 */

	/* Send the syncronize and wait for it */
	dprintf(ctxt->stdout, "SYNC-stamp\n");
	agent_poll(verify_contains, "SYNC-stamp");

	/* Now we have a full slot */
	dprintf(ctxt->stdout, "%s", hello_msg);
	dprintf(ctxt->stdout, "%s", bye_msg);

	/* New line is not send via telemetry, as it is used to flush split log
	 * messages */
	bye_msg[sizeof(bye_msg) - 2] = '\0';

	expect_unexpect_t val = {.expect = bye_msg, .unexpect = hello_msg};
	agent_poll(verify_contains_except, &val);
}

int
setup(void **state)
{
	struct test_module_log_context *ctxt = *state;
	struct EVP_client *sdk_handle =
		evp_agent_add_instance(ctxt->agent_ctxt, "backdoor-telemetry");
	assert_non_null(sdk_handle);

	ctxt->stdout = module_log_cap_open(LOG_APP, "stdout");
	ctxt->stderr = module_log_cap_open(LOG_APP, "stderr");

	cloud_sends_mdc_set_log_enable(ctxt, LOG_APP, true);

	const enum evp_hub_type hub = agent_test_get_hub_type();
	const struct test_input_set *set = &test_inputs[hub];

	switch (hub) {
	case EVP_HUB_TYPE_EVP1_TB:
		/* Fall through. */
	case EVP_HUB_TYPE_EVP2_TB:
		{
			char *response = NULL;

			xasprintf(&response, "\"response\":%s",
				  set->mdc_response_value_empty);
			agent_poll(verify_contains, response);
			free(response);
		}
		break;

	default:
		break;
	}

	return 0;
}

int
teardown(void **state)
{
	struct test_module_log_context *ctxt = *state;

	module_log_cap_close(LOG_APP, "stdout");
	module_log_cap_close(LOG_APP, "stderr");
	ctxt->stdout = -1;

	return 0;
}

int
group_setup(void **state)
{
	agent_test_setup();

	// read and serialise EVP1 json
	size_t sz;
	char *tmp = read_file(DEPLOYMENT_FILE_EVP1, &sz, true);
	JSON_Value *value = json_value_init_string(tmp);
	deployment_evp1 = json_serialize_to_string(value);
	assert_non_null(deployment_evp1);
	agent_register_payload(DEPLOYMENT_MANIFEST_1, EVP_HUB_TYPE_EVP1_TB,
			       deployment_evp1);
	json_value_free(value);
	free(tmp);

	// read and register EVP2 json
	deployment_evp2 = read_file(DEPLOYMENT_FILE_EVP2, &sz, true);
	assert_non_null(deployment_evp2);
	agent_register_payload(DEPLOYMENT_MANIFEST_1, EVP_HUB_TYPE_EVP2_TB,
			       deployment_evp2);

	struct test_module_log_context *ctxt = &g_module_log_ctxt;
	ctxt->agent_ctxt = agent_test_start();
	*state = &g_module_log_ctxt;

	return 0;
}

int
group_teardown(void **state)
{
	agent_test_exit();
	free(deployment_evp1);
	free(deployment_evp2);
	return 0;
}

int
main(void)
{
	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_module_log, setup,
						teardown),

		cmocka_unit_test_setup_teardown(test_module_log_inv_instance,
						setup, teardown),

		cmocka_unit_test_setup_teardown(test_module_log_discard_oldest,
						setup, teardown),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
