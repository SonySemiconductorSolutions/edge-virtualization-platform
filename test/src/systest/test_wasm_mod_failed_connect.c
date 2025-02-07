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

#include <internal/util.h>

#include "webclient/webclient.h"

#include "agent_test.h"
#include "base64.h"
#include "hub.h"
#include "module_instance.h"
#include "mqtt_custom.h"
#include "path.h"
#include "websrv/websrv.h"
#include "xlog.h"
#include "xpthread.h"

enum {
	DEPLOYMENT,
	CONFIG,
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

/* clang-format off */

#define URL_FMT "http://localhost:%u/blob"

#define EVP1_INSTANCE_CONFIG \
	"{" \
		"\"configuration/" INSTANCE_ID "/upload\": \"%.*s\"," \
		"\"configuration/" INSTANCE_ID "/local_file\": \"bXlfZmlsZS50eHQ=\"" \
	"}"

#define EVP2_INSTANCE_CONFIG \
	"{" \
		"\"configuration/" INSTANCE_ID "/upload\": \"%s\"," \
		"\"configuration/" INSTANCE_ID "/local_file\": \"my_file.txt\"" \
	"}"

/* clang-format on */

struct test {
	unsigned short port;
	struct evp_agent_context *ctxt;
	struct agent_deployment deployment;
};

int
__wrap_connect(int socket, const struct sockaddr *address,
	       socklen_t address_len)
{
	static bool flag;
	int __real_connect(int socket, const struct sockaddr *address,
			   socklen_t address_len);

	if (!flag) {
		errno = EINPROGRESS;
		flag = true;
		return -1;
	}

	return __real_connect(socket, address, address_len);
}

int
__wrap_webclient_perform(FAR struct webclient_context *ctx)
{
	int __real_webclient_perform(FAR struct webclient_context * ctx);
	return __real_webclient_perform(ctx);
}

static void
test_failed_connect(void **state)
{
	struct test *test = *state;
	char *url, *config;

	assert_true(asprintf(&url, URL_FMT, test->port) > 0);

	const char *payload = agent_get_payload(CONFIG);

	switch (agent_test_get_hub_type()) {
	case EVP_HUB_TYPE_EVP1_TB:
		{
			char *b64;
			size_t sz;

			assert_int_equal(
				base64_encode(url, strlen(url), &b64, &sz), 0);
			assert_true(asprintf(&config, payload, (int)sz, b64) >
				    0);
			free(b64);

			agent_send_instance_config(test->ctxt, config);
			agent_poll(verify_json,
				   "state/" INSTANCE_ID "/status=%s",
				   "Z19zdGVwID0gMTAwMA==");
			break;
		}

	case EVP_HUB_TYPE_EVP2_TB:
		assert_true(asprintf(&config, payload, url) > 0);
		agent_send_instance_config(test->ctxt, config);
		agent_poll(verify_json, "state/" INSTANCE_ID "/status=%s",
			   "g_step = 1000");
		break;

	case EVP_HUB_TYPE_UNKNOWN:
		abort();
	}

	free(config);
	free(url);
}

static void
setup_file(void)
{
	const char *mi_path = path_get(MODULE_INSTANCE_PATH_ID);
	char *filepath;

	assert_non_null(mi_path);
	assert_true(asprintf(&filepath,
			     "%s/" INSTANCE_ID
			     "/default_workspace/my_file.txt",
			     mi_path) > 0);

	FILE *f = fopen(filepath, "wb");

	assert_non_null(f);

	long data = 0xfeedc0ffee;
	assert_int_equal(fwrite(&data, sizeof data, 1, f), 1);
	fclose(f);
	free(filepath);
}

static int
setup(void **state)
{
	static struct test test;

	*state = &test;
	agent_test_setup();
	assert_int_equal(websrv_setup(0), 0);
	assert_int_equal(
		websrv_add_route("/*", HTTP_OP_PUT, on_put_default, NULL), 0);

	assert_int_equal(websrv_get_port(&test.port), 0);
	assert_int_equal(websrv_start(), 0);

	agent_register_payload(DEPLOYMENT, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_DEPLOYMENT_MANIFEST);
	agent_register_payload(EMPTY_DEPLOYMENT, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_EMPTY_DEPLOYMENT_MANIFEST);
	agent_register_payload(CONFIG, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_INSTANCE_CONFIG);

	agent_register_payload(DEPLOYMENT, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_DEPLOYMENT_MANIFEST);
	agent_register_payload(EMPTY_DEPLOYMENT, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_EMPTY_DEPLOYMENT_MANIFEST);
	agent_register_payload(CONFIG, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_INSTANCE_CONFIG);

	assert_non_null(test.ctxt = test.deployment.ctxt = agent_test_start());

	agent_ensure_deployment(&test.deployment,
				agent_get_payload(DEPLOYMENT), DEPLOYMENT_ID);

	setup_file();
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
		cmocka_unit_test(test_failed_connect),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup, teardown);
}
