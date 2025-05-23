/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <config.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <evp/sdk.h>
#include <parson.h>

#include <internal/util.h>

#include "agent_test.h"
#include "global.h"
#include "hub.h"
#include "module_instance.h"
#include "mqtt_custom.h"

enum test_instance_state_payloads {
	DEPLOYMENT_MANIFEST_1,
	DEPLOYMENT_MANIFEST_2,
	MESSAGE_1,
	MESSAGE_2
};

struct state {
	struct evp_agent_context *ctxt;
	struct agent_deployment d;
	struct EVP_client *handle1;
	struct EVP_client *handle2;
};

#define REPORT_STATUS_INTERVAL_MIN 3
#define REPORT_STATUS_INTERVAL_MAX 5

#define TEST_DEPLOYMENT_ID1 "2dc1a1c3-531b-4693-abba-a4a039bb827d"
#define TEST_DEPLOYMENT_ID2 "2dc1a1c3-531b-4693-abba-a4a039bb827e"

#define TEST_INSTANCE_ID1 "07fe77d5-7117-4326-9042-47fda5dd9bf5"
#define TEST_INSTANCE_ID2 "07fe77d5-7117-4326-9042-47fda5dd9bf6"

#define TEST_MODULE_ID1 "b91fe3e8-df6d-41b7-90cb-72f8b92bdf5e"
#define TEST_MODULE_ID2 "b91fe3e8-df6d-41b7-90cb-72f8b92bdf5f"

#define STATE_1     "This is a test"
#define STATE_1_B64 "VGhpcyBpcyBhIHRlc3Q="
#define STATE_2     "{\"key\":\"value\"}"
#define STATE_2_B64 "eyJrZXkiOiJ2YWx1ZSJ9"

#define EVP1_DEPLOYMENT_MANIFEST_1                                            \
	"\"{ "                                                                \
	"        \\\"deploymentId\\\": "                                      \
	"\\\"" TEST_DEPLOYMENT_ID1 "\\\","                                    \
	"        \\\"instanceSpecs\\\": {"                                    \
	"            \\\"" TEST_INSTANCE_ID1 "\\\": {"                        \
	"                \\\"moduleId\\\": \\\"" TEST_MODULE_ID1 "\\\","      \
	"                \\\"entryPoint\\\": \\\"backdoor-state1\\\","        \
	"                \\\"version\\\": 1,"                                 \
	"                \\\"publish\\\": {},"                                \
	"                \\\"subscribe\\\": {}"                               \
	"            },"                                                      \
	"            \\\"" TEST_INSTANCE_ID2 "\\\": {"                        \
	"                \\\"moduleId\\\": \\\"" TEST_MODULE_ID2 "\\\","      \
	"                \\\"entryPoint\\\": \\\"backdoor-state2\\\","        \
	"                \\\"version\\\": 1,"                                 \
	"                \\\"publish\\\": {},"                                \
	"                \\\"subscribe\\\": {}"                               \
	"            }"                                                       \
	"        },"                                                          \
	"        \\\"modules\\\": {"                                          \
	"            \\\"" TEST_MODULE_ID1 "\\\": {"                          \
	"                \\\"moduleImpl\\\": \\\"spawn\\\","                  \
	"                \\\"downloadUrl\\\": \\\"\\\","                      \
	"                \\\"hash\\\": \\\"\\\""                              \
	"            },"                                                      \
	"            \\\"" TEST_MODULE_ID2 "\\\": {"                          \
	"                \\\"moduleImpl\\\": \\\"spawn\\\","                  \
	"                \\\"downloadUrl\\\": \\\"\\\","                      \
	"                \\\"hash\\\": \\\"\\\""                              \
	"            }"                                                       \
	"        },"                                                          \
	"        \\\"publishTopics\\\": {},"                                  \
	"        \\\"subscribeTopics\\\": {}"                                 \
	"}\""

#define EVP1_DEPLOYMENT_MANIFEST_2                                            \
	"\"{ "                                                                \
	"        \\\"deploymentId\\\": "                                      \
	"\\\"" TEST_DEPLOYMENT_ID2 "\\\","                                    \
	"        \\\"instanceSpecs\\\": {"                                    \
	"            \\\"" TEST_INSTANCE_ID1 "\\\": {"                        \
	"                \\\"moduleId\\\": \\\"" TEST_MODULE_ID1 "\\\","      \
	"                \\\"entryPoint\\\": \\\"backdoor-state1\\\","        \
	"                \\\"version\\\": 1,"                                 \
	"                \\\"publish\\\": {},"                                \
	"                \\\"subscribe\\\": {}"                               \
	"            }"                                                       \
	"        },"                                                          \
	"        \\\"modules\\\": {"                                          \
	"            \\\"" TEST_MODULE_ID1 "\\\": {"                          \
	"                \\\"moduleImpl\\\": \\\"spawn\\\","                  \
	"                \\\"downloadUrl\\\": \\\"\\\","                      \
	"                \\\"hash\\\": \\\"\\\""                              \
	"            },"                                                      \
	"            \\\"" TEST_MODULE_ID2 "\\\": {"                          \
	"                \\\"moduleImpl\\\": \\\"spawn\\\","                  \
	"                \\\"downloadUrl\\\": \\\"\\\","                      \
	"                \\\"hash\\\": \\\"\\\""                              \
	"            }"                                                       \
	"        },"                                                          \
	"        \\\"publishTopics\\\": {},"                                  \
	"        \\\"subscribeTopics\\\": {}"                                 \
	"}\""

#define EVP2_DEPLOYMENT_MANIFEST_1                                            \
	"{"                                                                   \
	"        \"deploymentId\": \"" TEST_DEPLOYMENT_ID1 "\","              \
	"        \"instanceSpecs\": {"                                        \
	"            \"" TEST_INSTANCE_ID1 "\": {"                            \
	"                \"moduleId\": \"" TEST_MODULE_ID1 "\","              \
	"                \"publish\": {},"                                    \
	"                \"subscribe\": {}"                                   \
	"            },"                                                      \
	"            \"" TEST_INSTANCE_ID2 "\": {"                            \
	"                \"moduleId\": \"" TEST_MODULE_ID2 "\","              \
	"                \"publish\": {},"                                    \
	"                \"subscribe\": {}"                                   \
	"            }"                                                       \
	"        },"                                                          \
	"        \"modules\": {"                                              \
	"            \"" TEST_MODULE_ID1 "\": {"                              \
	"                \"entryPoint\": \"backdoor-state1\","                \
	"                \"moduleImpl\": \"spawn\","                          \
	"                \"downloadUrl\": \"\","                              \
	"                \"hash\": \"\""                                      \
	"            },"                                                      \
	"            \"" TEST_MODULE_ID2 "\": {"                              \
	"                \"entryPoint\": \"backdoor-state2\","                \
	"                \"moduleImpl\": \"spawn\","                          \
	"                \"downloadUrl\": \"\","                              \
	"                \"hash\": \"\""                                      \
	"            }"                                                       \
	"        },"                                                          \
	"        \"publishTopics\": {},"                                      \
	"        \"subscribeTopics\": {}"                                     \
	"}"

#define EVP2_DEPLOYMENT_MANIFEST_2                                            \
	"{"                                                                   \
	"        \"deploymentId\": \"" TEST_DEPLOYMENT_ID2 "\","              \
	"        \"instanceSpecs\": {"                                        \
	"            \"" TEST_INSTANCE_ID1 "\": {"                            \
	"                \"moduleId\": \"" TEST_MODULE_ID1 "\","              \
	"                \"publish\": {},"                                    \
	"                \"subscribe\": {}"                                   \
	"            }"                                                       \
	"        },"                                                          \
	"        \"modules\": {"                                              \
	"            \"" TEST_MODULE_ID1 "\": {"                              \
	"                \"entryPoint\": \"backdoor-state1\","                \
	"                \"moduleImpl\": \"spawn\","                          \
	"                \"downloadUrl\": \"\","                              \
	"                \"hash\": \"\""                                      \
	"            },"                                                      \
	"            \"" TEST_MODULE_ID2 "\": {"                              \
	"                \"entryPoint\": \"backdoor-state2\","                \
	"                \"moduleImpl\": \"spawn\","                          \
	"                \"downloadUrl\": \"\","                              \
	"                \"hash\": \"\""                                      \
	"            }"                                                       \
	"        },"                                                          \
	"        \"publishTopics\": {},"                                      \
	"        \"subscribeTopics\": {}"                                     \
	"}"

static void
state_cb(EVP_STATE_CALLBACK_REASON reason, void *userData)
{
	function_called();
	check_expected(reason);
	check_expected(userData);
	*(char *)userData = '\0';
}

void
test_instance_state(void **state)
{
	EVP_RESULT r;
	time_t t1, t2;
	char state_userdata[1];
	struct state *st = *state;

	/* Send initial state */
	*state_userdata = 'c';
	r = EVP_sendState(st->handle1, "test_topic", STATE_1, strlen(STATE_1),
			  state_cb, state_userdata);

	assert_int_equal(r, EVP_OK);
	expect_function_call(state_cb);
	expect_value(state_cb, reason, EVP_STATE_CALLBACK_REASON_SENT);
	expect_value(state_cb, userData, state_userdata);
	while (*state_userdata)
		EVP_processEvent(st->handle1, 1000);

	agent_poll(verify_json, "state/" TEST_INSTANCE_ID1 "/test_topic=%s",
		   agent_get_payload(MESSAGE_1));
	t1 = time(NULL);

	/* Send new state */
	*state_userdata = 'c';
	r = EVP_sendState(st->handle1, "test_topic", STATE_2, strlen(STATE_2),
			  state_cb, state_userdata);
	assert_int_equal(r, EVP_OK);
	expect_function_call(state_cb);
	expect_value(state_cb, reason, EVP_STATE_CALLBACK_REASON_SENT);
	expect_value(state_cb, userData, state_userdata);
	while (*state_userdata)
		EVP_processEvent(st->handle1, 1000);
	agent_poll(verify_json, "state/" TEST_INSTANCE_ID1 "/test_topic=%s",
		   agent_get_payload(MESSAGE_2));
	t2 = time(NULL);

	assert_true(difftime(t2, t1) >= REPORT_STATUS_INTERVAL_MIN);
}

void
test_instance_state2(void **state)
{
	EVP_RESULT r;
	char state_userdata[1];
	struct state *st = *state;

	*state_userdata = 'c';
	r = EVP_sendState(st->handle2, "test_topic", STATE_1, strlen(STATE_1),
			  state_cb, state_userdata);
	assert_int_equal(r, EVP_OK);
	expect_function_call(state_cb);
	expect_value(state_cb, reason, EVP_STATE_CALLBACK_REASON_SENT);
	expect_value(state_cb, userData, state_userdata);
	while (*state_userdata)
		EVP_processEvent(st->handle2, 1000);

	agent_poll(verify_json,
		   "state/" TEST_INSTANCE_ID2 "/test_topic=%s,"
		   "state/" TEST_INSTANCE_ID1 "/test_topic=%s",
		   agent_get_payload(MESSAGE_1), agent_get_payload(MESSAGE_2));

	agent_ensure_deployment(&st->d,
				agent_get_payload(DEPLOYMENT_MANIFEST_2),
				TEST_DEPLOYMENT_ID2);

	agent_poll(verify_json,
		   ".=$#,"
		   "state/" TEST_INSTANCE_ID1 "/test_topic=%s",
		   1, agent_get_payload(MESSAGE_2));
}

void
test_instance_long_state(void **state)
{
	char state_blob[CONFIG_EVP_MQTT_SEND_BUFF_SIZE + 20];
	const char state_userdata[] = "user data";
	EVP_RESULT result;
	struct state *st = *state;
	struct EVP_client *sdk_handle = st->handle1;

	memset(state_blob, 'E', sizeof(state_blob));
	state_blob[sizeof(state_blob) - 1] = '\0';

	result = EVP_sendState(sdk_handle, "test_topic", state_blob,
			       sizeof(state_blob), state_cb,
			       (void *)state_userdata);
	assert_int_equal(result, EVP_TOOBIG);
}

int
setup(void **state)
{
	struct evp_agent_context *ctxt;
	static struct state st;

	// Set periodic report intervals
	putenv("EVP_REPORT_STATUS_INTERVAL_MIN_SEC=" ___STRING(
		REPORT_STATUS_INTERVAL_MIN));
	putenv("EVP_REPORT_STATUS_INTERVAL_MAX_SEC=" ___STRING(
		REPORT_STATUS_INTERVAL_MAX));

	agent_test_setup();
	agent_register_payload(DEPLOYMENT_MANIFEST_1, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_DEPLOYMENT_MANIFEST_1);
	agent_register_payload(DEPLOYMENT_MANIFEST_2, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_DEPLOYMENT_MANIFEST_2);

	agent_register_payload(DEPLOYMENT_MANIFEST_1, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_DEPLOYMENT_MANIFEST_1);
	agent_register_payload(DEPLOYMENT_MANIFEST_2, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_DEPLOYMENT_MANIFEST_2);

	agent_register_payload(MESSAGE_1, EVP_HUB_TYPE_EVP1_TB, STATE_1_B64);
	agent_register_payload(MESSAGE_1, EVP_HUB_TYPE_EVP2_TB, STATE_1);
	agent_register_payload(MESSAGE_2, EVP_HUB_TYPE_EVP1_TB, STATE_2_B64);
	agent_register_payload(MESSAGE_2, EVP_HUB_TYPE_EVP2_TB, STATE_2);

	ctxt = agent_test_start();
	assert_non_null(ctxt);
	st.d = (struct agent_deployment){.ctxt = ctxt};

	// create backdoor instances
	st.handle1 = evp_agent_add_instance(ctxt, "backdoor-state1");
	st.handle2 = evp_agent_add_instance(ctxt, "backdoor-state2");
	assert_non_null(st.handle1);
	assert_non_null(st.handle2);

	agent_ensure_deployment(&st.d,
				agent_get_payload(DEPLOYMENT_MANIFEST_1),
				TEST_DEPLOYMENT_ID1);
	st.ctxt = ctxt;
	*state = &st;

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
		cmocka_unit_test(test_instance_state),
		cmocka_unit_test(test_instance_state2),
		cmocka_unit_test(test_instance_long_state),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup, teardown);
}
