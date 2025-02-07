/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sys/stat.h>

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
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
#include "platform.h"
#include "websrv/websrv.h"
#include "xlog.h"

enum test_wasm_config_echo_payloads {
	DEPLOYMENT_MANIFEST_1,
	EMPTY_DEPLOYMENT_MANIFEST_1,
	INSTANCE_CONFIG_1
};

#define TEST_DEPLOYMENT_ID1       "4fa905ae-e103-46ab-a8b9-73be07599708"
#define TEST_EMPTY_DEPLOYMENT_ID1 "4fa905ae-e103-46ab-a8b9-73be07599709"
#define TEST_INSTANCE_ID1         "b218f90b-9228-423f-8e02-000000000001"

#define DUMMY_KEY   "download"
#define DUMMY_VALUE "Zm9vYmFyCg=="

#define MODULE_PATH "http://localhost:%hu/config_echo.wasm"

#define MODULE_HASH                                                           \
	"69b6948b7c7f31462a235f374c9a9c682521806827b9bc76f64246c40624da8c"

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
	"                \\\"downloadUrl\\\": \\\"" MODULE_PATH "\\\","       \
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
	"	\"configuration/" TEST_INSTANCE_ID1 "/" DUMMY_KEY             \
	"\": \"" DUMMY_VALUE "\""                                             \
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
	"\"" MODULE_PATH "\","                                                \
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
	"	\"configuration/" TEST_INSTANCE_ID1 "/" DUMMY_KEY             \
	"\": \"" DUMMY_VALUE "\""                                             \
	"}"

int __real_webclient_perform(FAR struct webclient_context *ctx);
int
__wrap_webclient_perform(FAR struct webclient_context *ctx)
{
	return __real_webclient_perform(ctx);
}

int
__wrap_check_hash(struct module *module, const unsigned char *ref,
		  size_t ref_len, char **result)
{
	size_t size;
	const void *input = NULL;
	void *handle = NULL;
	int error = 0;
	handle = plat_mod_fs_file_mmap(module, &input, &size, false, &error);
	if (handle == NULL) {
		return error ? error : EIO;
	}
	plat_mod_fs_file_munmap(handle);
	return 0;
}

void
test_wasm_mod_http_config_echo(void **state)
{
	// start agent
	struct evp_agent_context *ctxt = agent_test_start();
	struct agent_deployment d = {.ctxt = ctxt};

	// deploy
	agent_ensure_deployment(&d, agent_get_payload(DEPLOYMENT_MANIFEST_1),
				TEST_DEPLOYMENT_ID1);

	// send config
	agent_send_instance_config(ctxt, agent_get_payload(INSTANCE_CONFIG_1));

	// wait for the dummy value
	agent_poll(verify_contains, DUMMY_VALUE);

	// send empty deployment
	agent_ensure_deployment(&d,
				agent_get_payload(EMPTY_DEPLOYMENT_MANIFEST_1),
				TEST_EMPTY_DEPLOYMENT_ID1);
}

static char *deployment1;
static char *deployment2;
unsigned short backend_port;

static int
teardown(void **state)
{
	agent_test_exit();
	websrv_stop();
	websrv_teardown();

	free(deployment1);
	free(deployment2);
	return 0;
}

int
on_get_file(const struct http_payload *p, struct http_response *r, void *user)
{
	char *filename;
	struct stat statbuf;

	xlog_info("%s: handling GET for %s", __func__, p->resource);

	xasprintf(&filename, "../test_modules/%s", p->resource + 1);

	assert(stat(filename, &statbuf) == 0);

	FILE *fp = fopen(filename, "rb");
	assert(fp);

	xlog_info("%s: sending %s (%ju bytes) ", __func__, filename,
		  (uintmax_t)statbuf.st_size);

	free(filename);

	*r = (struct http_response){
		.status = HTTP_STATUS_OK,
		.f = fp,
		.n = statbuf.st_size,
	};

	return 0;
}

static int
setup(void **state)
{
	agent_test_setup();

	assert_int_equal(websrv_setup(0), 0);
	assert_int_equal(
		websrv_add_route("/*", HTTP_OP_GET, on_get_file, NULL), 0);

	assert_int_equal(websrv_get_port(&backend_port), 0);
	assert_int_equal(websrv_start(), 0);

	xasprintf(&deployment1, EVP1_DEPLOYMENT_MANIFEST_1, backend_port);

	xasprintf(&deployment2, EVP2_DEPLOYMENT_MANIFEST_1, backend_port);

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
	return 0;
}

int
main(void)
{
	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_wasm_mod_http_config_echo),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup, teardown);
}
