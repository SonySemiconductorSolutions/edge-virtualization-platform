/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <evp/sdk.h>
#include <parson.h>

#include <internal/util.h>

#include "agent_test.h"
#include "hub.h"
#include "module.h"
#include "module_instance.h"
#include "mqtt_custom.h"

enum test_wasm_config_echo_payloads {
	DEPLOYMENT_MANIFEST_1,
	EMPTY_DEPLOYMENT_MANIFEST_1,
	JSON_STATUS_CHECK,
	JSON_STATE_PLACEHOLDER,
};

#define TEST_DEPLOYMENT_ID1       "deployment-1"
#define TEST_EMPTY_DEPLOYMENT_ID1 "deployment-2"
#define TEST_INSTANCE_ID1         "instance-001"
#define TEST_INSTANCE_ID2         "instance-002"
#define TEST_INSTANCE_ID3         "instance-003"
#define MODULE_ID1                "backdoor-EA_Main"
#define MODULE_ID2                "backdoor-EA_UD"
#define MODULE_ID3                "module-A"
#define BACKDOOR_1_ENTRY          "backdoor-EA_Main"
#define BACKDOOR_2_ENTRY          "backdoor-EA_UD"

#define MODULE_PATH "../test_modules/config_echo.wasm"
#define MODULE_URL  "file://" MODULE_PATH
#define MODULE_HASH                                                           \
	"579fca500ec9f67a661e8b1a3a59a114a97029c46776d6ad9502fb183f1a1f7d"

#define EVP1_JSON_STATUS_CHECK "deploymentStatus=#{reconcileStatus=%s"
#define TB_JSON_STATUS_CHECK   "deploymentStatus.reconcileStatus=%s"

#define JSON_STATE_CHECK(Id) "state/" Id "/placeholder=%s"

#define PLACEHOLDER_VALUE                                                     \
	"eyJWZXJzaW9uIjp7IkNhbWVyYVNldHVwRmlsZVZlcnNpb24iOnsiQ29sb3JNYXRyaXh" \
	"TdGQiOiJNNFExanRQZnlWcTB2Nk9JQWJoTVZrMmUvdkpuR2NDYnptKzY3MUNXV3ZjPS" \
	"IsIkNvbG9yTWF0cml4Q3VzdG9tIjoiIiwiR2FtbWFTdGQiOiJsSEl1RmRNYk5KdkhUM" \
	"FFEeWZ2dmdnWnJnRkpzQ3J3bm9lbC80YU5qUCswPSIsIkdhbW1hQ3VzdG9tIjoiIiwi" \
	"TFNDSVNQU3RkIjoiWUpNMlhIMDlmUFFUMFZpaFFZKzlxaFpIREhXZW5Fb2JoZ2dGY2R" \
	"idnpOST0iLCJMU0NJU1BDdXN0b20iOiIiLCJMU0NSYXdTdGQiOiIiLCJMU0NSYXdDdX" \
	"N0b20iOiIiLCJQcmVXQlN0ZCI6ImZRTmM3K1d1SEIvUXBDTllDeVF4Q28zVzkxVUZzc" \
	"lQ5TG1mRm1PQVFwWGs9IiwiUHJlV0JDdXN0b20iOiIiLCJEZXdhcnBTdGQiOiIxVjdR" \
	"NXBvOXVUMFJJWlNmWnhKaGtXZWVjNENsK2JIN2tKdjBFTzhMV1EwPSIsIkRld2FycEN" \
	"1c3RvbSI6IiJ9fSwiU3RhdHVzIjp7IlNlbnNvciI6IlN0YW5kYnkiLCJBcHBsaWNhdG" \
	"lvblByb2Nlc3NvciI6IklkbGUiLCJIb3Vyc01ldGVyIjoyfSwiT1RBIjp7IlVwZGF0Z" \
	"VByb2d"
#define PLACEHOLDER_VALUE_B64                                                 \
	"ZXlKV1pYSnphVzl1SWpwN0lrTmhiV1Z5WVZObGRIVndSbWxzWlZabGNuTnBiMjRpT25" \
	"zaVEyOXNiM0pOWVhSeWFYaFRkR1FpT2lKTk5GRXhhblJRWm5sV2NUQjJOazlKUVdKb1" \
	"RWWnJNbVV2ZGtwdVIyTkRZbnB0S3pZM01VTlhWM1pqUFNJc0lrTnZiRzl5VFdGMGNtb" \
	"DRRM1Z6ZEc5dElqb2lJaXdpUjJGdGJXRlRkR1FpT2lKc1NFbDFSbVJOWWs1S2RraFVN" \
	"RkZFZVdaMmRtZG5XbkpuUmtwelEzSjNibTlsYkM4MFlVNXFVQ3N3UFNJc0lrZGhiVzF" \
	"oUTNWemRHOXRJam9pSWl3aVRGTkRTVk5RVTNSa0lqb2lXVXBOTWxoSU1EbG1VRkZVTU" \
	"ZacGFGRlpLemx4YUZwSVJFaFhaVzVGYjJKb1oyZEdZMlJpZG5wT1NUMGlMQ0pNVTBOS" \
	"lUxQkRkWE4wYjIwaU9pSWlMQ0pNVTBOU1lYZFRkR1FpT2lJaUxDSk1VME5TWVhkRGRY" \
	"TjBiMjBpT2lJaUxDSlFjbVZYUWxOMFpDSTZJbVpSVG1NM0sxZDFTRUl2VVhCRFRsbER" \
	"lVkY0UTI4elZ6a3hWVVp6Y2xRNVRHMW1SbTFQUVZGd1dHczlJaXdpVUhKbFYwSkRkWE" \
	"4wYjIwaU9pSWlMQ0pFWlhkaGNuQlRkR1FpT2lJeFZqZFJOWEJ2T1hWVU1GSkpXbE5tV" \
	"25oS2FHdFhaV1ZqTkVOc0sySklOMnRLZGpCRlR6aE1WMUV3UFNJc0lrUmxkMkZ5Y0VO" \
	"MWMzUnZiU0k2SWlKOWZTd2lVM1JoZEhWeklqcDdJbE5sYm5OdmNpSTZJbE4wWVc1a1l" \
	"ua2lMQ0pCY0hCc2FXTmhkR2x2YmxCeWIyTmxjM052Y2lJNklrbGtiR1VpTENKSWIzVn" \
	"ljMDFsZEdWeUlqb3lmU3dpVDFSQklqcDdJbFZ3WkdGMFpWQnliMmQ="

#define EVP1_DEPLOYMENT_MANIFEST_1                                            \
	"\"{"                                                                 \
	"        \\\"deploymentId\\\": \\\"" TEST_DEPLOYMENT_ID1 "\\\","      \
	"        \\\"instanceSpecs\\\": {"                                    \
	"            \\\"" TEST_INSTANCE_ID1 "\\\": {"                        \
	"                \\\"moduleId\\\": \\\"" MODULE_ID1 "\\\","           \
	"                \\\"entryPoint\\\": \\\"" BACKDOOR_1_ENTRY "\\\","   \
	"                \\\"version\\\": 1,"                                 \
	"                \\\"publish\\\": {},"                                \
	"                \\\"subscribe\\\": {}"                               \
	"            },"                                                      \
	"            \\\"" TEST_INSTANCE_ID2 "\\\": {"                        \
	"                \\\"moduleId\\\": \\\"" MODULE_ID1 "\\\","           \
	"                \\\"entryPoint\\\": \\\"" BACKDOOR_2_ENTRY "\\\","   \
	"                \\\"version\\\": 1,"                                 \
	"                \\\"publish\\\": {},"                                \
	"                \\\"subscribe\\\": {}"                               \
	"            },"                                                      \
	"            \\\"" TEST_INSTANCE_ID3 "\\\": {"                        \
	"                \\\"moduleId\\\": \\\"" MODULE_ID3 "\\\","           \
	"                \\\"entryPoint\\\": \\\"main\\\","                   \
	"                \\\"version\\\": 1,"                                 \
	"                \\\"publish\\\": {},"                                \
	"                \\\"subscribe\\\": {}"                               \
	"            }"                                                       \
	"        },"                                                          \
	"        \\\"modules\\\": {"                                          \
	"            \\\"" MODULE_ID1 "\\\": {"                               \
	"                \\\"moduleImpl\\\": \\\"spawn\\\","                  \
	"                \\\"downloadUrl\\\": \\\"\\\","                      \
	"                \\\"hash\\\": \\\"\\\""                              \
	"            },"                                                      \
	"            \\\"" MODULE_ID2 "\\\": {"                               \
	"                \\\"moduleImpl\\\": \\\"spawn\\\","                  \
	"                \\\"downloadUrl\\\": \\\"\\\","                      \
	"                \\\"hash\\\": \\\"\\\""                              \
	"            },"                                                      \
	"            \\\"" MODULE_ID3 "\\\": {"                               \
	"                \\\"moduleImpl\\\": \\\"wasm\\\","                   \
	"                \\\"downloadUrl\\\": \\\"" MODULE_URL "\\\","        \
	"                \\\"hash\\\": \\\"" MODULE_HASH "\\\""               \
	"            }"                                                       \
	"        },"                                                          \
	"        \\\"publishTopics\\\": {},"                                  \
	"        \\\"subscribeTopics\\\": {}"                                 \
	"}\""

#define EVP1_EMPTY_DEPLOYMENT_MANIFEST_1                                      \
	"\"{ "                                                                \
	"        \\\"deploymentId\\\": "                                      \
	"\\\"" TEST_EMPTY_DEPLOYMENT_ID1 "\\\","                              \
	"        \\\"instanceSpecs\\\": {},"                                  \
	"        \\\"modules\\\": {},"                                        \
	"        \\\"publishTopics\\\": {},"                                  \
	"        \\\"subscribeTopics\\\": {}"                                 \
	"}\""

#define EVP2_DEPLOYMENT_MANIFEST_1                                            \
	"{"                                                                   \
	"        \"deploymentId\": \"" TEST_DEPLOYMENT_ID1 "\","              \
	"        \"instanceSpecs\": {"                                        \
	"            \"" TEST_INSTANCE_ID1 "\": {"                            \
	"                \"moduleId\": \"" MODULE_ID1 "\","                   \
	"                \"publish\": {},"                                    \
	"                \"subscribe\": {}"                                   \
	"            },"                                                      \
	"            \"" TEST_INSTANCE_ID2 "\": {"                            \
	"                \"moduleId\": \"" MODULE_ID2 "\","                   \
	"                \"publish\": {},"                                    \
	"                \"subscribe\": {}"                                   \
	"            },"                                                      \
	"            \"" TEST_INSTANCE_ID3 "\": {"                            \
	"                \"moduleId\": \"" MODULE_ID3 "\","                   \
	"                \"publish\": {},"                                    \
	"                \"subscribe\": {}"                                   \
	"            }"                                                       \
	"        },"                                                          \
	"        \"modules\": {"                                              \
	"            \"" MODULE_ID1 "\": {"                                   \
	"                \"entryPoint\": \"" BACKDOOR_1_ENTRY "\","           \
	"                \"moduleImpl\": \"spawn\","                          \
	"                \"downloadUrl\": \"\","                              \
	"                \"hash\": \"\""                                      \
	"            },"                                                      \
	"            \"" MODULE_ID2 "\": {"                                   \
	"                \"entryPoint\": \"" BACKDOOR_2_ENTRY "\","           \
	"                \"moduleImpl\": \"spawn\","                          \
	"                \"downloadUrl\": \"\","                              \
	"                \"hash\": \"\""                                      \
	"            },"                                                      \
	"            \"" MODULE_ID3 "\": {"                                   \
	"                \"entryPoint\": \"main\","                           \
	"                \"moduleImpl\": \"wasm\","                           \
	"                \"downloadUrl\": \"" MODULE_URL "\","                \
	"                \"hash\": \"" MODULE_HASH "\""                       \
	"            }"                                                       \
	"        },"                                                          \
	"        \"publishTopics\": {},"                                      \
	"        \"subscribeTopics\": {}"                                     \
	"}"

#define EVP2_EMPTY_DEPLOYMENT_MANIFEST_1                                      \
	"{"                                                                   \
	"        \"deploymentId\": \"" TEST_EMPTY_DEPLOYMENT_ID1 "\","        \
	"        \"instanceSpecs\": {},"                                      \
	"        \"modules\": {},"                                            \
	"        \"publishTopics\": {},"                                      \
	"        \"subscribeTopics\": {}"                                     \
	"}"

static void
state_cb(EVP_STATE_CALLBACK_REASON reason, void *userData)
{
	check_expected(reason);
	check_expected(userData);
}

void
report_backdoor_states_with_renamed_instance_id(void **state)
{
	struct evp_agent_context *ctxt = *state;
	struct agent_deployment d = {.ctxt = ctxt};

	struct EVP_client *backdoor_main, *backdoor_ud;
	backdoor_main = evp_agent_add_instance(ctxt, BACKDOOR_1_ENTRY);
	assert_non_null(backdoor_main);
	backdoor_ud = evp_agent_add_instance(ctxt, BACKDOOR_2_ENTRY);
	assert_non_null(backdoor_ud);

	// Initilize
	agent_ensure_deployment(&d, NULL, NULL);

	/* Backdoor sends placeholder state at startup */
	EVP_RESULT res;
	res = EVP_sendState(backdoor_main, "placeholder", PLACEHOLDER_VALUE,
			    strlen(PLACEHOLDER_VALUE), state_cb, (void *)NULL);
	assert_int_equal(res, EVP_OK);

	// Process state event
	expect_value(state_cb, reason, EVP_STATE_CALLBACK_REASON_SENT);
	expect_value(state_cb, userData, NULL);
	res = EVP_processEvent(backdoor_main, 10000);
	assert_int_equal(res, EVP_OK);

	// wait for the placeholder state with backdoor entry as instance id
	const char *placeholder = agent_get_payload(JSON_STATE_PLACEHOLDER);
	agent_poll(verify_json, JSON_STATE_CHECK(BACKDOOR_1_ENTRY),
		   placeholder);

	// deploy
	agent_ensure_deployment(&d, agent_get_payload(DEPLOYMENT_MANIFEST_1),
				TEST_DEPLOYMENT_ID1);

	// wait for the placeholder state with renamed backdoor instance id
	agent_poll(verify_json, JSON_STATE_CHECK(TEST_INSTANCE_ID1),
		   placeholder);

	// send empty deployment
	agent_ensure_deployment(&d,
				agent_get_payload(EMPTY_DEPLOYMENT_MANIFEST_1),
				TEST_EMPTY_DEPLOYMENT_ID1);
}

static int
setup(void **state)
{
	agent_test_setup();

	/* EVP1 */
	agent_register_payload(EMPTY_DEPLOYMENT_MANIFEST_1,
			       EVP_HUB_TYPE_EVP1_TB,
			       EVP1_EMPTY_DEPLOYMENT_MANIFEST_1);
	agent_register_payload(DEPLOYMENT_MANIFEST_1, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_DEPLOYMENT_MANIFEST_1);

	/* EVP2 */
	agent_register_payload(EMPTY_DEPLOYMENT_MANIFEST_1,
			       EVP_HUB_TYPE_EVP2_TB,
			       EVP2_EMPTY_DEPLOYMENT_MANIFEST_1);
	agent_register_payload(DEPLOYMENT_MANIFEST_1, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_DEPLOYMENT_MANIFEST_1);

	/* Common */
	agent_register_payload(JSON_STATUS_CHECK, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_JSON_STATUS_CHECK);
	agent_register_payload(JSON_STATUS_CHECK, EVP_HUB_TYPE_EVP2_TB,
			       TB_JSON_STATUS_CHECK);
	agent_register_payload(JSON_STATE_PLACEHOLDER, EVP_HUB_TYPE_EVP1_TB,
			       PLACEHOLDER_VALUE_B64);
	agent_register_payload(JSON_STATE_PLACEHOLDER, EVP_HUB_TYPE_EVP2_TB,
			       PLACEHOLDER_VALUE);

	// start agent
	struct evp_agent_context *ctxt = agent_test_start();

	*state = ctxt;
	return 0;
}

static int
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
		cmocka_unit_test(
			report_backdoor_states_with_renamed_instance_id),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup, teardown);
}
