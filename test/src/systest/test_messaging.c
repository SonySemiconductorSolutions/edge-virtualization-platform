/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <evp/sdk.h>
#include <parson.h>

#include <internal/util.h>

#include "agent_test.h"
#include "hub.h"
#include "module_instance.h"
#include "mqtt_custom.h"

#define TEST_PROCESS_EVENT_TIMEOUT 5000

enum test_messaging_payloads { DEPLOYMENT_MANIFEST_1 };

#define TEST_DEPLOYMENT_ID1 "4fa905ae-e103-46ab-a8b9-73be07599708"

#define EVP1_DEPLOYMENT_MANIFEST_1                                            \
	"\"{ "                                                                \
	"        \\\"deploymentId\\\": "                                      \
	"\\\"" TEST_DEPLOYMENT_ID1 "\\\","                                    \
	"        \\\"instanceSpecs\\\": {"                                    \
	"            \\\"b218f90b-9228-423f-8e02-000000000001\\\": {"         \
	"                \\\"moduleId\\\": "                                  \
	"\\\"b218f90b-9228-423f-8e02-a6d3527bc15d\\\","                       \
	"                \\\"entryPoint\\\": \\\"backdoor-one\\\","           \
	"                \\\"version\\\": 1,"                                 \
	"                \\\"publish\\\": {"                                  \
	"                        \\\"alias-one\\\": "                         \
	"\\\"publish-topic-one\\\""                                           \
	"                },"                                                  \
	"                \\\"subscribe\\\": {}"                               \
	"            },"                                                      \
	"            \\\"c8fba53c-ffd9-439b-849d-000000000001\\\": {"         \
	"                \\\"moduleId\\\": "                                  \
	"\\\"a12c6772-54c4-4bcf-8419-6b6ad6724c8e\\\","                       \
	"                \\\"entryPoint\\\": \\\"backdoor-two\\\","           \
	"                \\\"version\\\": 1,"                                 \
	"                \\\"publish\\\": {},"                                \
	"                \\\"subscribe\\\": {"                                \
	"                        \\\"alias-two\\\": "                         \
	"\\\"subscribe-topic-one\\\""                                         \
	"                }"                                                   \
	"            }"                                                       \
	"        },"                                                          \
	"        \\\"modules\\\": {"                                          \
	"            \\\"b218f90b-9228-423f-8e02-a6d3527bc15d\\\": {"         \
	"                \\\"moduleImpl\\\": \\\"spawn\\\","                  \
	"                \\\"downloadUrl\\\": \\\"\\\","                      \
	"                \\\"hash\\\": \\\"\\\""                              \
	"            },"                                                      \
	"            \\\"a12c6772-54c4-4bcf-8419-6b6ad6724c8e\\\": {"         \
	"                \\\"moduleImpl\\\": \\\"spawn\\\","                  \
	"                \\\"downloadUrl\\\": \\\"\\\","                      \
	"                \\\"hash\\\": \\\"\\\""                              \
	"            }"                                                       \
	"        },"                                                          \
	"        \\\"publishTopics\\\": {"                                    \
	"                \\\"publish-topic-one\\\": {"                        \
	"                        \\\"type\\\": \\\"local\\\","                \
	"                        \\\"topic\\\": \\\"topic-one\\\""            \
	"                }"                                                   \
	"        },"                                                          \
	"        \\\"subscribeTopics\\\": {"                                  \
	"                \\\"subscribe-topic-one\\\": {"                      \
	"                        \\\"type\\\": \\\"local\\\","                \
	"                        \\\"topic\\\": \\\"topic-one\\\""            \
	"                }"                                                   \
	"        }"                                                           \
	"}\""

#define EVP2_DEPLOYMENT_MANIFEST_1                                            \
	"{"                                                                   \
	"        \"deploymentId\": \"" TEST_DEPLOYMENT_ID1 "\","              \
	"        \"instanceSpecs\": {"                                        \
	"            \"b218f90b-9228-423f-8e02-000000000001\": {"             \
	"                \"moduleId\": "                                      \
	"\"b218f90b-9228-423f-8e02-a6d3527bc15d\","                           \
	"                \"publish\": {"                                      \
	"                        \"alias-one\": \"publish-topic-one\""        \
	"                },"                                                  \
	"                \"subscribe\": {}"                                   \
	"            },"                                                      \
	"            \"c8fba53c-ffd9-439b-849d-000000000001\": {"             \
	"                \"moduleId\": "                                      \
	"\"a12c6772-54c4-4bcf-8419-6b6ad6724c8e\","                           \
	"                \"publish\": {},"                                    \
	"                \"subscribe\": {"                                    \
	"                        \"alias-two\": \"subscribe-topic-one\""      \
	"                }"                                                   \
	"            }"                                                       \
	"        },"                                                          \
	"        \"modules\": {"                                              \
	"            \"b218f90b-9228-423f-8e02-a6d3527bc15d\": {"             \
	"                \"entryPoint\": \"backdoor-one\","                   \
	"                \"moduleImpl\": \"spawn\","                          \
	"                \"downloadUrl\": \"\","                              \
	"                \"hash\": \"\""                                      \
	"            },"                                                      \
	"            \"a12c6772-54c4-4bcf-8419-6b6ad6724c8e\": {"             \
	"                \"entryPoint\": \"backdoor-two\","                   \
	"                \"moduleImpl\": \"spawn\","                          \
	"                \"downloadUrl\": \"\","                              \
	"                \"hash\": \"\""                                      \
	"            }"                                                       \
	"        },"                                                          \
	"        \"publishTopics\": {"                                        \
	"                \"publish-topic-one\": {"                            \
	"                        \"type\": \"local\","                        \
	"                        \"topic\": \"topic-one\""                    \
	"                }"                                                   \
	"        },"                                                          \
	"        \"subscribeTopics\": {"                                      \
	"                \"subscribe-topic-one\": {"                          \
	"                        \"type\": \"local\","                        \
	"                        \"topic\": \"topic-one\""                    \
	"                }"                                                   \
	"        }"                                                           \
	"}"

static void
recv_message_cb(const char *topic, const void *msgPayload,
		size_t msgPayloadLen, void *userData)
{
	check_expected(topic);
	check_expected(msgPayload);
	check_expected(msgPayloadLen);
	check_expected(userData);
}

static void
send_message_cb(EVP_MESSAGE_SENT_CALLBACK_REASON reason, void *userData)
{
	check_expected(reason);
	check_expected(userData);
}

void
test_messaging(void **state)
{
	// start agent
	struct evp_agent_context *ctxt = agent_test_start();
	assert_non_null(ctxt);
	struct agent_deployment d = {.ctxt = ctxt};

	// create backdoor instances
	struct EVP_client *sdk_handle_one =
		evp_agent_add_instance(ctxt, "backdoor-one");
	assert_non_null(sdk_handle_one);
	struct EVP_client *sdk_handle_two =
		evp_agent_add_instance(ctxt, "backdoor-two");
	assert_non_null(sdk_handle_two);

	// deployment
	agent_ensure_deployment(&d, agent_get_payload(DEPLOYMENT_MANIFEST_1),
				TEST_DEPLOYMENT_ID1);

	EVP_RESULT result;
	const char testPayload[] = "This is the message payload";
	const char userSendData[] = "message send callback data";
	const char userRecvData[] = "message receive callback data";

	// configure callback and send message
	result = EVP_setMessageCallback(sdk_handle_two, recv_message_cb,
					(void *)userRecvData);
	assert_int_equal(EVP_OK, result);

	result = EVP_sendMessage(sdk_handle_one, "alias-one", testPayload,
				 sizeof(testPayload), send_message_cb,
				 (void *)userSendData);
	assert_int_equal(EVP_OK, result);
	// check receive callback
	expect_string(recv_message_cb, topic, "alias-two");
	expect_memory(recv_message_cb, msgPayload, testPayload,
		      sizeof(testPayload));
	expect_value(recv_message_cb, msgPayloadLen, sizeof(testPayload));
	expect_memory(recv_message_cb, userData, userRecvData,
		      sizeof(userRecvData));

	agent_profile_scope("EVP_processEvent")
	{
		result = EVP_processEvent(sdk_handle_two,
					  TEST_PROCESS_EVENT_TIMEOUT);
		assert_int_equal(EVP_OK, result);
	}

	// check send callback
	expect_value(send_message_cb, reason, EVP_STATE_CALLBACK_REASON_SENT);
	expect_memory(send_message_cb, userData, userSendData,
		      sizeof(userSendData));

	agent_profile_scope("EVP_processEvent")
	{
		result = EVP_processEvent(sdk_handle_one,
					  TEST_PROCESS_EVENT_TIMEOUT);
		assert_int_equal(EVP_OK, result);
	}

	// test unknown/invalid alias
	result = EVP_sendMessage(sdk_handle_one, "invalid-alias", testPayload,
				 sizeof(testPayload), send_message_cb,
				 (void *)userSendData);
	assert_int_equal(EVP_OK, result);
	expect_value(send_message_cb, reason,
		     EVP_MESSAGE_SENT_CALLBACK_REASON_ERROR);
	expect_memory(send_message_cb, userData, userSendData,
		      sizeof(userSendData));

	agent_profile_scope("EVP_processEvent")
	{
		result = EVP_processEvent(sdk_handle_one,
					  TEST_PROCESS_EVENT_TIMEOUT);
		assert_int_equal(EVP_OK, result);
	}
}

int
setup(void **state)
{
	agent_test_setup();
	agent_register_payload(DEPLOYMENT_MANIFEST_1, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_DEPLOYMENT_MANIFEST_1);
	agent_register_payload(DEPLOYMENT_MANIFEST_1, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_DEPLOYMENT_MANIFEST_1);
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
		cmocka_unit_test(test_messaging),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup, teardown);
}
