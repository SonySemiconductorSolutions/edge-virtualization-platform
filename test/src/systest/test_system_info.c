/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <parson.h>

#include <internal/util.h>

#include "agent_test.h"
#include "hub.h"
#include "module_instance.h"
#include "module_instance_impl.h"
#include "mqtt_custom.h"

enum test_system_info_payloads { DEPLOYMENT_MANIFEST_1 };

#define TEST_DEPLOYMENT_ID1 "2dc1a1c3-531b-4693-abba-a4a039bb827d"
#define TEST_INSTANCE_ID1   "07fe77d5-7117-4326-9042-47fda5dd9bf5"

#define EVP1_DEPLOYMENT_MANIFEST_1                                            \
	"\"{ "                                                                \
	"        \\\"deploymentId\\\": "                                      \
	"\\\"2dc1a1c3-531b-4693-abba-a4a039bb827d\\\","                       \
	"        \\\"instanceSpecs\\\": {"                                    \
	"            \\\"07fe77d5-7117-4326-9042-47fda5dd9bf5\\\": {"         \
	"                \\\"moduleId\\\": "                                  \
	"\\\"b91fe3e8-df6d-41b7-90cb-72f8b92bdf5e\\\","                       \
	"                \\\"entryPoint\\\": \\\"backdoor-mdc\\\","           \
	"                \\\"version\\\": 1,"                                 \
	"                \\\"publish\\\": {},"                                \
	"                \\\"subscribe\\\": {}"                               \
	"            }"                                                       \
	"        },"                                                          \
	"        \\\"modules\\\": {"                                          \
	"            \\\"b91fe3e8-df6d-41b7-90cb-72f8b92bdf5e\\\": {"         \
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
	"        \"deploymentId\": \"2dc1a1c3-531b-4693-abba-a4a039bb827d\"," \
	"        \"instanceSpecs\": {"                                        \
	"            \"07fe77d5-7117-4326-9042-47fda5dd9bf5\": {"             \
	"                \"moduleId\": "                                      \
	"\"b91fe3e8-df6d-41b7-90cb-72f8b92bdf5e\","                           \
	"                \"publish\": {},"                                    \
	"                \"subscribe\": {}"                                   \
	"            }"                                                       \
	"        },"                                                          \
	"        \"modules\": {"                                              \
	"            \"b91fe3e8-df6d-41b7-90cb-72f8b92bdf5e\": {"             \
	"                \"entryPoint\": \"backdoor-mdc\","                   \
	"                \"moduleImpl\": \"spawn\","                          \
	"                \"downloadUrl\": \"\","                              \
	"                \"hash\": \"\""                                      \
	"            }"                                                       \
	"        },"                                                          \
	"        \"publishTopics\": {},"                                      \
	"        \"subscribeTopics\": {}"                                     \
	"}"

void
test_instance_state(void **state)
{
	// start agent
	struct evp_agent_context *ctxt = agent_test_start();

	// create backdoor instance
	struct EVP_client *h = evp_agent_add_instance(ctxt, "backdoor-mdc");
	assert_non_null(h);

	// deployment
	agent_send_initial(ctxt, agent_get_payload(DEPLOYMENT_MANIFEST_1),
			   NULL, NULL);
	agent_poll(verify_contains, TEST_INSTANCE_ID1);

	if (EVP_HUB_TYPE_EVP1_TB == agent_test_get_hub_type()) {
		agent_poll(verify_json,
			   "systemInfo.protocolVersion=%s,"
			   "systemInfo.utsname.sysname=%t,"
			   "systemInfo.utsname.nodename=%t,"
			   "systemInfo.utsname.release=%t,"
			   "systemInfo.utsname.machine=%t,"
			   "systemInfo.utsname.version=%t",
			   "EVP1", JSONString, JSONString, JSONString,
			   JSONString, JSONString);
	} else if (EVP_HUB_TYPE_EVP2_TB == agent_test_get_hub_type()) {
		agent_poll(verify_json,
			   "systemInfo.protocolVersion=%s,"
			   "systemInfo.os=%t,"
			   "systemInfo.arch=%t,"
			   "systemInfo.evp_agent=%t,"
			   "systemInfo.wasmMicroRuntime=%t",
			   "EVP2-TB", JSONString, JSONString, JSONString,
			   JSONString);
	}
}

int
setup(void **state)
{
	// Force max time to 3 because the test is checking the report 2 times
	// consecutivily. Otherwise we will get a timeout, since
	// default value is defined by MAX_REPORT_INTERVAL_SEC
	putenv("EVP_REPORT_STATUS_INTERVAL_MAX_SEC=3");

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
		cmocka_unit_test(test_instance_state),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup, teardown);
}
