/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE

#include <sys/stat.h>

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <evp/sdk.h>
#include <parson.h>
#include <wasm_export.h>

#include <internal/util.h>

#include "agent_test.h"
#include "base64.h"
#include "hub.h"
#include "module_instance.h"
#include "mqtt_custom.h"
#include "path.h"
#include "xlog.h"
#include "xpthread.h"

enum {
	DEPLOYMENT,
	EMPTY_DEPLOYMENT,
};

#define EMPTY_DEPLOYMENT_ID "f3a8a5b9-a44c-477d-9d36-6e65e9fc764f"
#define DEPLOYMENT_ID       "aaeba249-5c02-41b8-9452-7b19a556a312"
#define INSTANCE_ID         "10709a54-1d35-4955-b087-2380863f7eea"
#define MODULE_ID           "0329dea0-bd16-4e8a-be29-cd415c1a10ff"
#define MODULE_PATH         "../test_modules/upload_http_file.wasm"
#define MODULE_HASH                                                           \
	"f08befebf564843f9882bb160d5f61e69db0da3fb485cb6b243b361baeb50198"

#define EVP1_DEPLOYMENT_MANIFEST                                              \
	"\"{ "                                                                \
	"        \\\"deploymentId\\\": "                                      \
	"\\\"" DEPLOYMENT_ID "\\\","                                          \
	"        \\\"instanceSpecs\\\": {"                                    \
	"            \\\"" INSTANCE_ID "\\\": {"                              \
	"                \\\"moduleId\\\": "                                  \
	"\\\"" MODULE_ID "\\\","                                              \
	"                \\\"entryPoint\\\": \\\"main\\\","                   \
	"                \\\"version\\\": 1,"                                 \
	"                \\\"publish\\\": {},"                                \
	"                \\\"subscribe\\\": {}"                               \
	"            }"                                                       \
	"        },"                                                          \
	"        \\\"modules\\\": {"                                          \
	"            \\\"" MODULE_ID "\\\": {"                                \
	"                \\\"moduleImpl\\\": \\\"wasm\\\","                   \
	"                \\\"downloadUrl\\\": \\\"file://" MODULE_PATH        \
	"\\\","                                                               \
	"                \\\"hash\\\": \\\"\\\""                              \
	"            }"                                                       \
	"        },"                                                          \
	"        \\\"publishTopics\\\": {},"                                  \
	"        \\\"subscribeTopics\\\": {}"                                 \
	"}\""

#define EVP1_EMPTY_DEPLOYMENT_MANIFEST                                        \
	"\"{ "                                                                \
	"        \\\"deploymentId\\\": "                                      \
	"\\\"" EMPTY_DEPLOYMENT_ID "\\\","                                    \
	"        \\\"instanceSpecs\\\": {},"                                  \
	"        \\\"modules\\\": {},"                                        \
	"        \\\"publishTopics\\\": {},"                                  \
	"        \\\"subscribeTopics\\\": {}"                                 \
	"}\""

#define EVP2_DEPLOYMENT_MANIFEST                                              \
	"{"                                                                   \
	"    \"deploymentId\": \"" DEPLOYMENT_ID "\","                        \
	"    \"instanceSpecs\": {"                                            \
	"        \"" INSTANCE_ID "\": {"                                      \
	"            \"moduleId\": \"" MODULE_ID "\","                        \
	"            \"publish\": {},"                                        \
	"            \"subscribe\": {}"                                       \
	"        }"                                                           \
	"    },"                                                              \
	"    \"modules\": {"                                                  \
	"        \"" MODULE_ID "\": {"                                        \
	"            \"downloadUrl\": \"file://" MODULE_PATH "\","            \
	"            \"entryPoint\": \"main\","                               \
	"            \"hash\": \"" MODULE_HASH "\","                          \
	"            \"moduleImpl\": \"wasm\""                                \
	"        }"                                                           \
	"    },"                                                              \
	"    \"publishTopics\": {},"                                          \
	"    \"subscribeTopics\": {}"                                         \
	"}"

#define EVP2_EMPTY_DEPLOYMENT_MANIFEST                                        \
	"{"                                                                   \
	"        \"deploymentId\": \"" EMPTY_DEPLOYMENT_ID "\","              \
	"        \"instanceSpecs\": {},"                                      \
	"        \"modules\": {},"                                            \
	"        \"publishTopics\": {},"                                      \
	"        \"subscribeTopics\": {}"                                     \
	"}"

struct test {
	struct evp_agent_context *ctxt;
};

static void
test_failed_wasm_load(void **state)
{
	struct test *test = *state;

	agent_send_initial(test->ctxt, agent_get_payload(DEPLOYMENT), NULL,
			   NULL);
	agent_ensure_instance_status(INSTANCE_ID, "error");
	agent_send_deployment(test->ctxt, agent_get_payload(EMPTY_DEPLOYMENT));
	agent_ensure_deployment_status(EMPTY_DEPLOYMENT_ID, "ok");
}

int
__wrap_plat_mod_fs_file_munmap(struct mod_fs_mmap_handle *handle)
{
	int __real_plat_mod_fs_file_munmap(struct mod_fs_mmap_handle * handle);

	/* We do not want to leak the handle. */
	__real_plat_mod_fs_file_munmap(handle);
	return -1;
}

wasm_module_t
__wrap_wasm_runtime_load(uint8_t *buf, uint32_t size, char *error_buf,
			 uint32_t error_buf_size)
{
	snprintf(error_buf, error_buf_size, "(generated from: %s)", __func__);
	return NULL;
}

static int
setup(void **state)
{
	static struct test test;

	*state = &test;
	agent_test_setup();

	agent_register_payload(DEPLOYMENT, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_DEPLOYMENT_MANIFEST);
	agent_register_payload(EMPTY_DEPLOYMENT, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_EMPTY_DEPLOYMENT_MANIFEST);

	agent_register_payload(DEPLOYMENT, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_DEPLOYMENT_MANIFEST);
	agent_register_payload(EMPTY_DEPLOYMENT, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_EMPTY_DEPLOYMENT_MANIFEST);

	assert_non_null(test.ctxt = agent_test_start());

	return 0;
}

static int
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
		cmocka_unit_test(test_failed_wasm_load),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup, teardown);
}
