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

#include "webclient/webclient.h"

#include "agent_test.h"
#include "hub.h"
#include "module_instance.h"
#include "mqtt_custom.h"

enum test_wasm_http_ext_payloads {
	DEPLOYMENT_MANIFEST_1,
	EMPTY_DEPLOYMENT_MANIFEST_1,
	INSTANCE_CONFIG_1,
	EXPECTED_STATE_1,
	EXPECTED_STATE_2,
};

#define TEST_DEPLOYMENT_ID1       "4fa905ae-e103-46ab-a8b9-73be07599708"
#define TEST_EMPTY_DEPLOYMENT_ID1 "4fa905ae-e103-46ab-a8b9-73be07599709"
#define TEST_INSTANCE_ID1         "b218f90b-9228-423f-8e02-000000000001"

#define MODULE_PATH "../test_modules/download_http_ext_memory.wasm"

#define MODULE_HASH                                                           \
	"b7f12e8918cdffb6f9a4f462262e627a410b5d3d9f280212350a3cf8a06e8521"

#define EVP1_DEPLOYMENT_MANIFEST_1                                            \
	"\"{ "                                                                \
	"        \\\"deploymentId\\\": "                                      \
	"\\\"" TEST_DEPLOYMENT_ID1 "\\\","                                    \
	"        \\\"instanceSpecs\\\": {"                                    \
	"            \\\"" TEST_INSTANCE_ID1 "\\\": {"                        \
	"                \\\"moduleId\\\": "                                  \
	"\\\"b218f90b-9228-423f-8e02-a6d3527bc15d\\\","                       \
	"                \\\"entryPoint\\\": \\\"main\\\","                   \
	"                \\\"version\\\": 1,"                                 \
	"                \\\"publish\\\": {},"                                \
	"                \\\"subscribe\\\": {}"                               \
	"            }"                                                       \
	"        },"                                                          \
	"        \\\"modules\\\": {"                                          \
	"            \\\"b218f90b-9228-423f-8e02-a6d3527bc15d\\\": {"         \
	"                \\\"moduleImpl\\\": \\\"wasm\\\","                   \
	"                \\\"downloadUrl\\\": \\\"file://%s\\\","             \
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

#define EVP1_INSTANCE_CONFIG_1                                                \
	"{"                                                                   \
	"	\"configuration/" TEST_INSTANCE_ID1 "/instance_name\": "      \
	"\"YjIxOGY5MGItOTIyOC00MjNmLThlMDItMDAwMDAwMDAwMDAxCg==\","           \
	"	\"configuration/" TEST_INSTANCE_ID1 "/download\": "           \
	"\"aHR0cDovL2V2cHN0b3JhZ2Vjb250YWluZXIuYmxvYi5jb3JlLndpbmRvd3MubmV0L" \
	"2V2cGNvbnRhaW5lci1wdWIvY2lfdGVzdF9maWxlcy9ibG9iXzFNQi5qcGc=\","      \
	"	\"configuration/" TEST_INSTANCE_ID1 "/local_file\": "         \
	"\"YmxvYl9odHRwX2h0dHBfZmlsZS0x\""                                    \
	"}"

#define EVP2_DEPLOYMENT_MANIFEST_1                                            \
	"{"                                                                   \
	"        \"deploymentId\": \"" TEST_DEPLOYMENT_ID1 "\","              \
	"        \"instanceSpecs\": {"                                        \
	"            \"" TEST_INSTANCE_ID1 "\": {"                            \
	"                \"moduleId\": "                                      \
	"\"b218f90b-9228-423f-8e02-a6d3527bc15d\","                           \
	"                \"publish\": {},"                                    \
	"                \"subscribe\": {}"                                   \
	"            }"                                                       \
	"        },"                                                          \
	"        \"modules\": {"                                              \
	"            \"b218f90b-9228-423f-8e02-a6d3527bc15d\": {"             \
	"                \"entryPoint\": \"main\","                           \
	"                \"moduleImpl\": \"wasm\","                           \
	"                \"downloadUrl\": "                                   \
	"\"file://%s\","                                                      \
	"                \"hash\": "                                          \
	"\"" MODULE_HASH ""                                                   \
	"\""                                                                  \
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

#define EVP2_INSTANCE_CONFIG_1                                                \
	"{"                                                                   \
	"	\"configuration/" TEST_INSTANCE_ID1 "/"                       \
	"instance_name\": "                                                   \
	"\"YjIxOGY5MGItOTIyOC00MjNmLThlMDItMDAwMDAwMDAwMDAxCg==\","           \
	"	\"configuration/" TEST_INSTANCE_ID1 "/"                       \
	"download\": "                                                        \
	"\"aHR0cDovL2V2cHN0b3JhZ2Vjb250YWluZXIuYmxvYi5jb3JlLndpbmRvd3MubmV0L" \
	"2V2cGNvbnRhaW5lci1wdWIvY2lfdGVzdF9maWxlcy9ibG9iXzFNQi5qcGc=\","      \
	"	\"configuration/" TEST_INSTANCE_ID1 "/"                       \
	"local_file\": "                                                      \
	"\"YmxvYl9odHRwX2h0dHBfZmlsZS0x\""                                    \
	"}"

#define EVP1_EXPECTED_STATE_1 "Z19zdGVwID0gMA=="
#define EVP2_EXPECTED_STATE_1 "g_step = 0"
#define EVP1_EXPECTED_STATE_2 "Z19zdGVwID0gMTAwMA=="
#define EVP2_EXPECTED_STATE_2 "g_step = 1000"

#define HTTP_STATUS_OK 200

int
__wrap_webclient_perform(FAR struct webclient_context *ctx)
{
	ctx->http_status = HTTP_STATUS_OK;
	char *buffer = "hello";
	int len = 5;
	ctx->sink_callback(HTTP_STATUS_OK, &buffer, 0, 5, &len,
			   ctx->sink_callback_arg);
	return 0;
}
void
test_wasm_mod_http_ext(void **state)
{
	// start agent
	struct evp_agent_context *ctxt = agent_test_start();
	struct agent_deployment d = {.ctxt = ctxt};

	// deploy
	agent_ensure_deployment(&d, agent_get_payload(DEPLOYMENT_MANIFEST_1),
				TEST_DEPLOYMENT_ID1);

	// wait for module ready
	agent_poll(verify_contains,
		   agent_get_payload(EXPECTED_STATE_1)); // g_step = 0

	// send instance config
	agent_send_instance_config(ctxt, agent_get_payload(INSTANCE_CONFIG_1));

	// wait for download to finish
	agent_poll(verify_contains,
		   agent_get_payload(EXPECTED_STATE_2)); // g_step = 1000

	// send empty deployment
	agent_ensure_deployment(&d,
				agent_get_payload(EMPTY_DEPLOYMENT_MANIFEST_1),
				TEST_EMPTY_DEPLOYMENT_ID1);
}

static char *deployment1;
static char *deployment2;

static int
teardown(void **state)
{
	agent_test_exit();
	free(deployment1);
	free(deployment2);
	return 0;
}

static int
setup(void **state)
{
	agent_test_setup();

	char *path = MODULE_PATH;
	char *abspath;
	if (*path != '/') {
		abspath = realpath(path, NULL);
	} else {
		abspath = xstrdup(path);
	}

	xasprintf(&deployment1, EVP1_DEPLOYMENT_MANIFEST_1, abspath);

	xasprintf(&deployment2, EVP2_DEPLOYMENT_MANIFEST_1, abspath);

	free(abspath);

	agent_register_payload(DEPLOYMENT_MANIFEST_1, EVP_HUB_TYPE_EVP1_TB,
			       deployment1);
	agent_register_payload(INSTANCE_CONFIG_1, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_INSTANCE_CONFIG_1);
	agent_register_payload(DEPLOYMENT_MANIFEST_1, EVP_HUB_TYPE_EVP2_TB,
			       deployment2);
	agent_register_payload(EMPTY_DEPLOYMENT_MANIFEST_1,
			       EVP_HUB_TYPE_EVP2_TB,
			       EVP2_EMPTY_DEPLOYMENT_MANIFEST_1);
	agent_register_payload(EMPTY_DEPLOYMENT_MANIFEST_1,
			       EVP_HUB_TYPE_EVP1_TB,
			       EVP1_EMPTY_DEPLOYMENT_MANIFEST_1);
	agent_register_payload(INSTANCE_CONFIG_1, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_INSTANCE_CONFIG_1);
	agent_register_payload(EXPECTED_STATE_1, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_EXPECTED_STATE_1);
	agent_register_payload(EXPECTED_STATE_1, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_EXPECTED_STATE_1);

	agent_register_payload(EXPECTED_STATE_2, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_EXPECTED_STATE_2);
	agent_register_payload(EXPECTED_STATE_2, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_EXPECTED_STATE_2);

	return 0;
}

int
main(void)
{
	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_wasm_mod_http_ext),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup, teardown);
}
