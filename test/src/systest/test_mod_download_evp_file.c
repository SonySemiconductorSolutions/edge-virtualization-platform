/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <internal/util.h>

#include "webclient/webclient.h"

#include "agent_test.h"
#include "base64.h"
#include "evp/sdk.h"
#include "hub.h"
#include "module_instance.h"
#include "mqtt_custom.h"
#include "parson.h"
#include "path.h"
#include "req.h"
#include "websrv/websrv.h"
#include "xlog.h"

enum test_payloads {
	DEPLOYMENT_MANIFEST,
	DEPLOYMENT_MANIFEST_SPAWN,
	DEPLOYMENT_MANIFEST_PYTHON,
	DEPLOYMENT_MANIFEST_EMPTY,

	INSTANCE_CONFIG_WASM,
	INSTANCE_CONFIG_SPAWN,
	INSTANCE_CONFIG_PYTHON,

	STATE_STATUS_READY,
	STATE_STATUS_DONE,
};

enum test_deployment {
	WASM,
	SPAWN,
	PYTHON,
	EMPTY,
};

struct test_context {
	enum test_deployment depl;
	struct evp_agent_context *agent;
	struct agent_deployment d;
	unsigned short port;
};

#define DEPLOYMENT_ID_wasm   "4fa905ae-e103-46ab-a8b9-73be07599708"
#define DEPLOYMENT_ID_spawn  "4fa905ae-e103-46ab-a8b9-73be07599709"
#define DEPLOYMENT_ID_python "4fa905ae-e103-46ab-a8b9-73be0759970B"
#define DEPLOYMENT_ID_empty  "4fa905ae-e103-46ab-a8b9-73be0759970A"
#define INSTANCE_ID_wasm     "b218f90b-9228-423f-8e02-000000000001"
#define INSTANCE_ID_spawn    "b218f90b-9228-423f-8e02-000000000002"
#define INSTANCE_ID_python   "b218f90b-9228-423f-8e02-000000000003"

#define MODULE_URL_BASE "file://../test_modules"
#define MODULE_NAME     "download_http_file"

#define MODULE_ID_wasm  "b218f90b-9228-423f-8e02-a6d3527bc15d"
#define MODULE_URL_wasm MODULE_URL_BASE "/" MODULE_NAME ".wasm"
#define MODULE_HASH_wasm                                                      \
	"a962f28609c8e881314af0d61f4e5e2b25a86403a5c2f92f30845e179d4c1597"

#define MODULE_ID_spawn  "b218f90b-9228-423f-8e02-a6d3527bc15e"
#define MODULE_URL_spawn MODULE_URL_BASE "/" MODULE_NAME ".elf"
#define MODULE_HASH_spawn                                                     \
	"166d28a478d2f0e41aa71c9c8055eff2b6d44ced64b19a2afa6e7d7a401f85ab"

#define MODULE_ID_python  "b218f90b-9228-423f-8e02-a6d3527bc15f"
#define MODULE_URL_python MODULE_URL_BASE "/python/" MODULE_NAME ".zip"
#define MODULE_HASH_python                                                    \
	"8ac87e20c3b47add181726d5996666c23c77ae112952afd2a87c9935730de426"

#define STATE_KEY(Impl, Key) "state/" INSTANCE_ID_##Impl "/" ___STRING(Key)

#define EVP1_DEPLOYMENT_MANIFEST(Impl)                                        \
	"\"{ "                                                                \
	"\\\"deploymentId\\\": \\\"" DEPLOYMENT_ID_##Impl                     \
		"\\\","                                                       \
		"\\\"instanceSpecs\\\": {"                                    \
		"\\\"" INSTANCE_ID_##Impl                                     \
		"\\\": {"                                                     \
		"\\\"moduleId\\\": \\\"" MODULE_ID_##Impl                     \
		"\\\","                                                       \
		"\\\"entryPoint\\\": \\\"main\\\","                           \
		"\\\"version\\\": 1,"                                         \
		"\\\"publish\\\": {},"                                        \
		"\\\"subscribe\\\": {}"                                       \
		"}"                                                           \
		"},"                                                          \
		"\\\"modules\\\": {"                                          \
		"\\\"" MODULE_ID_##Impl                                       \
		"\\\": {"                                                     \
		"\\\"moduleImpl\\\": \\\"" ___STRING(                         \
			Impl) "\\\","                                         \
			      "\\\"downloadUrl\\\": \\\"" MODULE_URL_##Impl   \
		"\\\","                                                       \
		"\\\"hash\\\": \\\"" MODULE_HASH_##Impl                       \
		"\\\""                                                        \
		"}"                                                           \
		"},"                                                          \
		"\\\"publishTopics\\\": {},"                                  \
		"\\\"subscribeTopics\\\": {}"                                 \
		"}\""
/* clang-format on */

#define EVP1_DEPLOYMENT_MANIFEST_EMPTY                                        \
	"\"{ "                                                                \
	"\\\"deploymentId\\\": \\\"" DEPLOYMENT_ID_empty "\\\","              \
	"\\\"instanceSpecs\\\": {},"                                          \
	"\\\"modules\\\": {},"                                                \
	"\\\"publishTopics\\\": {},"                                          \
	"\\\"subscribeTopics\\\": {}"                                         \
	"}\""

/* clang-format off */
#define EVP2_DEPLOYMENT_MANIFEST(Impl)                                        \
	"{"                                                                   \
		"\"deploymentId\": \"" DEPLOYMENT_ID_##Impl "\","             \
		"\"instanceSpecs\": {"                                        \
			"\"" INSTANCE_ID_##Impl "\": {"                       \
				"\"moduleId\": \"" MODULE_ID_##Impl "\","     \
				"\"publish\": {},"                            \
				"\"subscribe\": {}"                           \
			"}"                                                   \
		"},"                                                          \
		"\"modules\": {"                                              \
			"\"" MODULE_ID_##Impl "\": {"                         \
				"\"moduleImpl\": \"" ___STRING(Impl)"\","     \
				"\"entryPoint\": \"main\","                   \
				"\"hash\": \"" MODULE_HASH_##Impl "\","       \
				"\"downloadUrl\": \"" MODULE_URL_##Impl "\""  \
			"}"                                                   \
		"},"                                                          \
		"\"publishTopics\": {},"                                      \
		"\"subscribeTopics\": {}"                                     \
	"}"
/* clang-format on */

#define EVP2_DEPLOYMENT_MANIFEST_EMPTY                                        \
	"{"                                                                   \
	"\"deploymentId\": \"" DEPLOYMENT_ID_empty "\","                      \
	"\"instanceSpecs\": {},"                                              \
	"\"modules\": {},"                                                    \
	"\"publishTopics\": {},"                                              \
	"\"subscribeTopics\": {}"                                             \
	"}"

static struct test_context g_test_context;

void
__wrap_webclient_perform(FAR struct webclient_context *ctx)
{
	void __real_webclient_perform(FAR struct webclient_context *);

	__real_webclient_perform(ctx);
}

static char *
get_instance_config(const struct test_context *ctxt, enum test_deployment depl)
{
	const char *filename = "my_file.txt", *instance_name = "downloader";
	char *url, *b64_filename = NULL, *b64_instance_name = NULL;

	assert_int_not_equal(
		asprintf(&url, "http://localhost:%hu/blob", ctxt->port), -1);

	if (agent_test_get_hub_type() == EVP_HUB_TYPE_EVP1_TB) {
		char *b64_url;
		size_t out;

		assert_int_equal(base64_encode(filename, strlen(filename),
					       &b64_filename, &out),
				 0);
		assert_int_equal(base64_encode(instance_name,
					       strlen(instance_name),
					       &b64_instance_name, &out),
				 0);
		assert_int_equal(
			base64_encode(url, strlen(url), &b64_url, &out), 0);

		filename = b64_filename;
		instance_name = b64_instance_name;
		free(url);
		url = b64_url;
	}

	static const char fmt[] = "{"
				  "\"configuration/%s/instance_name\": \"%s\","
				  "\"configuration/%s/download\": \"%s\","
				  "\"configuration/%s/local_file\": \"%s\""
				  "}";

	static const char *const ids[] = {
		[WASM] = INSTANCE_ID_wasm,
		[SPAWN] = INSTANCE_ID_spawn,
		[PYTHON] = INSTANCE_ID_python,
	};

	const char *id = ids[depl];
	char *cfg;

	assert_int_not_equal(
		asprintf(&cfg, fmt, id, instance_name, id, url, id, filename),
		-1);

	fprintf(stderr, "cfg=%s\n", cfg);

	free(b64_filename);
	free(b64_instance_name);
	free(url);
	return cfg;
}

static const char *
get_instance_state_status_dot(enum test_deployment depl)
{
	const char *configs[] = {
		[WASM] = STATE_KEY(wasm, status) "=%s",
		[SPAWN] = STATE_KEY(spawn, status) "=%s",
		[PYTHON] = STATE_KEY(python, status) "=%s",
	};
	assert_true(depl <= PYTHON);
	return configs[depl];
}

static const char *
get_manifest(enum test_deployment depl)
{
	assert_true(depl <= EMPTY);
	return agent_get_payload(DEPLOYMENT_MANIFEST + depl);
}

static const char *
get_deployment_id(enum test_deployment depl)
{
	static const char *deployment_ids[] = {
		[WASM] = DEPLOYMENT_ID_wasm,
		[SPAWN] = DEPLOYMENT_ID_spawn,
		[PYTHON] = DEPLOYMENT_ID_python,
		[EMPTY] = DEPLOYMENT_ID_empty,
	};
	assert_true(depl <= EMPTY);
	return deployment_ids[depl];
}

static int
teardown(void **state)
{
	// wait for agent to finish
	agent_test_exit();
	assert_int_equal(websrv_stop(), 0);
	assert_int_equal(websrv_teardown(), 0);
	return 0;
}

static int
on_get(const struct http_payload *p, struct http_response *r, void *user)
{
	static const char buf[] = "webclient always requires a body";

	agent_write_to_pipe("GET finished");

	*r = (struct http_response){
		.status = HTTP_STATUS_OK, .buf.ro = buf, .n = sizeof buf - 1};

	return 0;
}

static int
setup(void **state)
{
	struct test_context *ctxt = *state = &g_test_context;

	agent_test_setup();

	// Ensure data dir is present and pristine
	systemf("rm -rf %s/*", path_get(MODULE_INSTANCE_PATH_ID));
	systemf("mkdir -p %s", path_get(MODULE_INSTANCE_PATH_ID));

	// Deployment wasm module
	agent_register_payload(DEPLOYMENT_MANIFEST, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_DEPLOYMENT_MANIFEST(wasm));
	agent_register_payload(DEPLOYMENT_MANIFEST, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_DEPLOYMENT_MANIFEST(wasm));

	// Deployment spawn module
	agent_register_payload(DEPLOYMENT_MANIFEST_SPAWN, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_DEPLOYMENT_MANIFEST(spawn));
	agent_register_payload(DEPLOYMENT_MANIFEST_SPAWN, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_DEPLOYMENT_MANIFEST(spawn));

	// Deployment python module
	agent_register_payload(DEPLOYMENT_MANIFEST_PYTHON,
			       EVP_HUB_TYPE_EVP1_TB,
			       EVP1_DEPLOYMENT_MANIFEST(python));
	agent_register_payload(DEPLOYMENT_MANIFEST_PYTHON,
			       EVP_HUB_TYPE_EVP2_TB,
			       EVP2_DEPLOYMENT_MANIFEST(python));

	// Empty deployment
	agent_register_payload(DEPLOYMENT_MANIFEST_EMPTY, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_DEPLOYMENT_MANIFEST_EMPTY);
	agent_register_payload(DEPLOYMENT_MANIFEST_EMPTY, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_DEPLOYMENT_MANIFEST_EMPTY);

	// verify
	agent_register_payload(STATE_STATUS_READY, EVP_HUB_TYPE_EVP1_TB,
			       "Z19zdGVwID0gMA==");
	agent_register_payload(STATE_STATUS_READY, EVP_HUB_TYPE_EVP2_TB,
			       "g_step = 0");
	agent_register_payload(STATE_STATUS_DONE, EVP_HUB_TYPE_EVP1_TB,
			       "Z19zdGVwID0gMTAwMA==");
	agent_register_payload(STATE_STATUS_DONE, EVP_HUB_TYPE_EVP2_TB,
			       "g_step = 1000");

	struct evp_agent_context *agent = agent_test_start();
	assert_non_null(ctxt);

	*ctxt = (struct test_context){.agent = agent, .d = {.ctxt = agent}};

	assert_int_equal(websrv_setup(0), 0);
	assert_int_equal(websrv_get_port(&ctxt->port), 0);
	assert_int_equal(websrv_add_route("/blob", HTTP_OP_GET, on_get, ctxt),
			 0);
	assert_int_equal(websrv_start(), 0);
	return 0;
}

static void
poll_state_instance_status(enum test_deployment depl, enum test_payloads pl)
{
	agent_poll(verify_json, get_instance_state_status_dot(depl),
		   agent_get_payload(pl));
}

void
test_download_http_blob(struct test_context *ctxt, enum test_deployment depl)
{
	// Deploy simple manifest with instance of the given module id
	agent_ensure_deployment(&ctxt->d, get_manifest(depl),
				get_deployment_id(depl));

	poll_state_instance_status(depl, STATE_STATUS_READY);

	char *cfg = get_instance_config(ctxt, depl);

	// send instance config
	agent_send_instance_config(ctxt->agent, cfg);
	// Not check configuration done, because the module may send the rpc
	// request before sending the new state

	// At this point the module calls EVP_blobOperation and the agent will
	// send a GET request
	// check that the agent sends a blob containing the file
	// contents
	agent_poll(verify_contains, "GET finished");

	poll_state_instance_status(depl, STATE_STATUS_DONE);

	// Undeploy
	agent_ensure_deployment(&ctxt->d, get_manifest(EMPTY),
				get_deployment_id(EMPTY));
	free(cfg);
}

void
test_download_http_blob_wasm(void **state)
{
	test_download_http_blob(*state, WASM);
}

void
test_download_http_blob_spawn(void **state)
{
	test_download_http_blob(*state, SPAWN);
}

void
test_download_http_blob_python(void **state)
{
	test_download_http_blob(*state, PYTHON);
}

int
main(void)
{
	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_download_http_blob_wasm),
		cmocka_unit_test(test_download_http_blob_spawn),
		cmocka_unit_test(test_download_http_blob_python),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup, teardown);
}
