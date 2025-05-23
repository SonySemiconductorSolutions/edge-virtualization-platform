/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <pthread.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include <cmocka.h>
#include <evp/agent.h>

#include "hub.h"
#include "manifest.h"

bool
__wrap_hub_tb_is_ready_to_report(void)
{
	return true;
}

static const char *deployment_manifest1 =
	"{ "
	"        \"deploymentId\": \"98368966-92e4-4312-a9cd-1a03b09b9c92\","
	"        \"instanceSpecs\": {"
	"            \"b218f90b-9228-423f-8e02-aa107c47a9e9\": {"
	"                \"moduleId\": "
	"\"b218f90b-9228-423f-8e02-a6d3527bc15d\","
	"                \"publish\": {},"
	"                \"subscribe\": {}"
	"            },"
	"            \"b218f90b-9228-423f-8e02-aa107c47a9e8\": {"
	"                \"moduleId\": "
	"\"b218f90b-9228-423f-8e02-a6d3527bc15e\","
	"                \"publish\": {},"
	"                \"subscribe\": {}"
	"            }"
	"        },"
	"        \"modules\": {"
	"            \"b218f90b-9228-423f-8e02-a6d3527bc15d\": {"
	"                \"entryPoint\": \"backdoor-EA_Main\","
	"                \"moduleImpl\": \"spawn\","
	"                \"downloadUrl\": \"\","
	"                \"hash\": \"\""
	"            },"
	"            \"b218f90b-9228-423f-8e02-a6d3527bc15e\": {"
	"                \"entryPoint\": \"backdoor-EA_UD\","
	"                \"moduleImpl\": \"spawn\","
	"                \"downloadUrl\": \"\","
	"                \"hash\": \"\""
	"            }"
	"        },"
	"        \"publishTopics\": {},"
	"        \"subscribeTopics\": {}"
	"}";

static const char *deployment_manifest2 =
	"{"
	"        \"deploymentId\": \"8543e017-2d93-444b-bd4c-bcaa39c46095\","
	"        \"instanceSpecs\": {"
	"        },"
	"        \"modules\": {"
	"        },"
	"        \"publishTopics\": {},"
	"        \"subscribeTopics\": {}"
	"}";

static const char *deployment_manifest3 =
	"{ "
	"        \"deploymentId\": \"6c608879-1205-46c4-9542-616e2f5ca763\","
	"        \"instanceSpecs\": {"
	"            \"2d852a9e-fef7-4089-8a8e-d74e9e6dd2cd\": {"
	"                \"moduleId\": "
	"\"b871ed45-f849-4585-87ad-4c5f37202782\","
	"                \"publish\": {},"
	"                \"subscribe\": {}"
	"            },"
	"            \"1607ce72-c54b-4d78-b25b-473f1f03854c\": {"
	"                \"moduleId\": "
	"\"adc743bb-033a-4391-b50e-5d92e63c4f74\","
	"                \"publish\": {},"
	"                \"subscribe\": {}"
	"            }"
	"        },"
	"        \"modules\": {"
	"            \"b871ed45-f849-4585-87ad-4c5f37202782\": {"
	"                \"entryPoint\": \"backdoor-EA_Main\","
	"                \"moduleImpl\": \"spawn\","
	"                \"downloadUrl\": \"\","
	"                \"hash\": \"\""
	"            },"
	"            \"adc743bb-033a-4391-b50e-5d92e63c4f74\": {"
	"                \"entryPoint\": \"backdoor-EA_UD\","
	"                \"moduleImpl\": \"spawn\","
	"                \"downloadUrl\": \"\","
	"                \"hash\": \"\""
	"            }"
	"        },"
	"        \"publishTopics\": {},"
	"        \"subscribeTopics\": {}"
	"}";

void
test_embed(void **state)
{
	// instantiate and start EVP Agent
	struct evp_agent_context *ctxt;
	ctxt = evp_agent_setup("evp_agent_main");
	assert_non_null(ctxt);
	int ret = evp_agent_start(ctxt);
	assert_int_equal(ret, 0);

	// create backdoor instance
	struct EVP_client *m1a =
		evp_agent_add_instance(ctxt, "backdoor-EA_Main");
	assert_non_null(m1a);
	struct EVP_client *m2a =
		evp_agent_add_instance(ctxt, "backdoor-EA_UD");
	assert_non_null(m2a);

	// send and process dummy deployment
	JSON_Value *value = json_parse_string(deployment_manifest1);
	assert_non_null(value);
	save_deployment(ctxt, value);
	json_value_free(value);
	for (int cnt = 3; cnt; cnt--) {
		ret = evp_agent_loop(ctxt);
		assert_int_equal(ret, 0);
	}

	// ensure that dummy instances are attached to backdoor instances
	struct EVP_client *m1b = evp_agent_get_instance(
		ctxt, "b218f90b-9228-423f-8e02-aa107c47a9e9");
	assert_ptr_equal(m1a, m1b);
	struct EVP_client *m2b = evp_agent_get_instance(
		ctxt, "b218f90b-9228-423f-8e02-aa107c47a9e8");
	assert_ptr_equal(m2a, m2b);

	// send empty deployment
	value = json_parse_string(deployment_manifest2);
	assert_non_null(value);
	save_deployment(ctxt, value);
	json_value_free(value);
	for (int cnt = 3; cnt; cnt--) {
		ret = evp_agent_loop(ctxt);
		assert_int_equal(ret, 0);
	}

	// ensure that dummy instance name is reverted to backdoor
	m1b = evp_agent_get_instance(ctxt, "backdoor-EA_Main");
	assert_ptr_equal(m1a, m1b);
	m2b = evp_agent_get_instance(ctxt, "backdoor-EA_UD");
	assert_ptr_equal(m2a, m2b);

	// send new deployment
	value = json_parse_string(deployment_manifest3);
	assert_non_null(value);
	save_deployment(ctxt, value);
	json_value_free(value);
	for (int cnt = 3; cnt; cnt--) {
		ret = evp_agent_loop(ctxt);
		assert_int_equal(ret, 0);
	}

	// ensure that new dummy instances are attached to backdoor instances
	m1b = evp_agent_get_instance(ctxt,
				     "2d852a9e-fef7-4089-8a8e-d74e9e6dd2cd");
	assert_ptr_equal(m1a, m1b);
	m2b = evp_agent_get_instance(ctxt,
				     "1607ce72-c54b-4d78-b25b-473f1f03854c");
	assert_ptr_equal(m2a, m2b);

	// stop and clean up EVP Agent
	ret = evp_agent_stop(ctxt);
	evp_agent_free(ctxt);
	assert_int_equal(ret, 0);
}

int
setup(void **state)
{
	putenv("EVP_MQTT_HOST=test.mqtt.host.value");
	putenv("EVP_MQTT_PORT=1234");
	putenv("EVP_IOT_PLATFORM=TB");
	return 0;
}

int
main(void)
{
	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_embed),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup, NULL);
}
