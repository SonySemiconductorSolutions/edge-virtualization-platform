/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sys/stat.h>

#include <errno.h>
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
#include "websrv/websrv.h"
#include "xlog.h"
#include "xpthread.h"

enum test_wasm_config_echo_payloads {
	DEPLOYMENT_MANIFEST_TEMPLATE,
	EMPTY_DEPLOYMENT_MANIFEST,
};

#define DEPLOYMENT_ID0 "4fa905ae-e103-46ab-a8b9-73be07599708"
#define DEPLOYMENT_ID1 "8543e017-2d93-444b-bd4c-bcaa39c46095"
#define DEPLOYMENT_ID2 "e46f226e-3f8a-42fa-a2dd-d287ef64809b"
#define INSTANCE_ID1   "b218f90b-9228-423f-8e02-000000000001"
#define INSTANCE_ID2   "f0fe8678-acf9-4979-8e8b-43c495698593"

#define RECONCILE_EVENT(Id, Event) "on_reconcileStatus/" Id "/" __STRING(Event)

#define DUMMY_KEY        "download"
#define EVP1_DUMMY_VALUE "Zm9vYmFyCg=="
#define EVP2_DUMMY_VALUE "foobar"

#define MODULE_1    "config_echo.wasm"
#define MODULE_2    "messaging.wasm"
#define MODULE_PATH "http://localhost:%hu/%s"

#define MODULE_1_HASH                                                         \
	"579fca500ec9f67a661e8b1a3a59a114a97029c46776d6ad9502fb183f1a1f7d"
#define MODULE_2_HASH                                                         \
	"b34ecae0f7d010e18d4dd03ac9e8bf3e7d06e3b0cb65fd0d9f9a6bb9bfdc9c0f"
#define MODULE_HASH "%s"

#define EVP1_DEPLOYMENT_MANIFEST_TEMPLATE                                     \
	"\"{ "                                                                \
	"        \\\"deploymentId\\\": \\\"%s\\\","                           \
	"        \\\"instanceSpecs\\\": {"                                    \
	"            \\\"%s\\\": {"                                           \
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

#define EVP1_EMPTY_DEPLOYMENT_MANIFEST                                        \
	"\"{ "                                                                \
	"        \\\"deploymentId\\\": "                                      \
	"\\\"" DEPLOYMENT_ID0 "\\\","                                         \
	"        \\\"instanceSpecs\\\": {},"                                  \
	"        \\\"modules\\\": {},"                                        \
	"        \\\"publishTopics\\\": {},"                                  \
	"        \\\"subscribeTopics\\\": {}"                                 \
	"}\""

#define EVP2_DEPLOYMENT_MANIFEST_TEMPLATE                                     \
	"{"                                                                   \
	"        \"deploymentId\": \"%s\","                                   \
	"        \"instanceSpecs\": {"                                        \
	"            \"%s\": {"                                               \
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
	"                \"downloadUrl\": \"" MODULE_PATH "\","               \
	"                \"hash\": \"" MODULE_HASH "\""                       \
	"            }"                                                       \
	"        },"                                                          \
	"        \"publishTopics\": {},"                                      \
	"        \"subscribeTopics\": {}"                                     \
	"}"

#define EVP2_EMPTY_DEPLOYMENT_MANIFEST                                        \
	"{"                                                                   \
	"        \"deploymentId\": \"" DEPLOYMENT_ID0 "\","                   \
	"        \"instanceSpecs\": {},"                                      \
	"        \"modules\": {},"                                            \
	"        \"publishTopics\": {},"                                      \
	"        \"subscribeTopics\": {}"                                     \
	"}"

unsigned short backend_port;
static struct agent_deployment g_deployment;

int __real_webclient_perform(FAR struct webclient_context *ctx);
int
__wrap_webclient_perform(FAR struct webclient_context *ctx)
{
	return __real_webclient_perform(ctx);
}

int
on_get_file(const struct http_payload *p, struct http_response *r, void *user)
{
	char *filename;
	struct stat statbuf;

	xlog_info("%s: handling GET for %s", __func__, p->resource);

	xasprintf(&filename, "../test_modules/%s", p->resource + 1);

	if (stat(filename, &statbuf)) {
		fail_msg("Cannot stat %s", filename);
	}

	FILE *fp = NULL;
	fp = fopen(filename, "rb");
	if (fp == NULL) {
		fail_msg("Failed to open %s", filename);
	};

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
on_reconcileStatus(const void *args, void *user_data)
{
	const struct reconcileStatusNotify *reconcileStatusData = args;

	// deploymentId can be empty (When there is an EmptyDeployment)
	const char *deploymentId = reconcileStatusData->deploymentId;
	if (!deploymentId)
		deploymentId = "empty";

	char *txt;
	xasprintf(&txt, "%s/%s/%s", __func__, deploymentId,
		  reconcileStatusData->reconcileStatus);

	agent_write_to_pipe(txt);
	free(txt);
	return 0;
}

int
test_teardown(void **state)
{
	agent_ensure_deployment(&g_deployment,
				agent_get_payload(EMPTY_DEPLOYMENT_MANIFEST),
				DEPLOYMENT_ID0);
	return 0;
}

static int
suite_teardown(void **state)
{
	websrv_stop();
	websrv_teardown();
	// wait for agent to finish
	agent_test_exit();
	return 0;
}

static int
suite_setup(void **state)
{
	agent_test_setup();

	assert_int_equal(websrv_setup(0), 0);
	assert_int_equal(
		websrv_add_route("/*", HTTP_OP_GET, on_get_file, NULL), 0);

	assert_int_equal(websrv_get_port(&backend_port), 0);
	assert_int_equal(websrv_start(), 0);

	agent_register_payload(DEPLOYMENT_MANIFEST_TEMPLATE,
			       EVP_HUB_TYPE_EVP1_TB,
			       EVP1_DEPLOYMENT_MANIFEST_TEMPLATE);
	agent_register_payload(EMPTY_DEPLOYMENT_MANIFEST, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_EMPTY_DEPLOYMENT_MANIFEST);

	agent_register_payload(DEPLOYMENT_MANIFEST_TEMPLATE,
			       EVP_HUB_TYPE_EVP2_TB,
			       EVP2_DEPLOYMENT_MANIFEST_TEMPLATE);
	agent_register_payload(EMPTY_DEPLOYMENT_MANIFEST, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_EMPTY_DEPLOYMENT_MANIFEST);

	// start agent
	struct evp_agent_context *ctxt = *state = agent_test_start();

	assert_int_equal(evp_agent_notification_subscribe(
				 ctxt, "deployment/reconcileStatus",
				 on_reconcileStatus, NULL),
			 0);

	// Send initial empty deployment
	g_deployment.ctxt = ctxt;
	agent_ensure_deployment(&g_deployment,
				agent_get_payload(EMPTY_DEPLOYMENT_MANIFEST),
				DEPLOYMENT_ID0);

	print_message("[  INFO   ] Deployment ok\n");
	return 0;
}

void
send_deployment(struct evp_agent_context *ctxt, const char *deployment_id,
		const char *instance_id, const char *module_id,
		const char *module_hash)
{
	char *deployment;
	deployment = agent_get_payload_formatted(
		DEPLOYMENT_MANIFEST_TEMPLATE, deployment_id, instance_id,
		backend_port, module_id, module_hash);
	agent_send_deployment(ctxt, deployment);
	free(deployment);
}

void
pause_deployment_not_in_progress(void **state)
{
	struct evp_agent_context *ctxt = *state;

	// Request pause when no module is being downloaded
	assert_int_equal(evp_agent_request_pause_deployment(ctxt), 0);

	// Send a new deployment with a module to download
	send_deployment(ctxt, DEPLOYMENT_ID1, INSTANCE_ID1, MODULE_1,
			MODULE_1_HASH);

	// wait for the deployment status to be paused
	agent_poll(verify_equals, RECONCILE_EVENT(DEPLOYMENT_ID1, paused));

	print_message("[  INFO   ] Paused\n");

	// Resume deployment capability
	assert_int_equal(evp_agent_resume_deployment(ctxt), 0);

	// wait for the deployment status to be resumed
	agent_poll(verify_equals, RECONCILE_EVENT(DEPLOYMENT_ID1, applying));

	// wait for the deployment
	agent_poll(verify_equals, RECONCILE_EVENT(DEPLOYMENT_ID1, ok));
	agent_poll(verify_contains, INSTANCE_ID1);
}

void
pause_deployment_in_progress(void **state)
{
	struct evp_agent_context *ctxt = *state;

	// Send a new deployment with a module to download
	send_deployment(ctxt, DEPLOYMENT_ID2, INSTANCE_ID2, MODULE_2,
			MODULE_2_HASH);

	// wait for the deployment status to be applying
	agent_poll(verify_equals, RECONCILE_EVENT(DEPLOYMENT_ID2, applying));

	// Request pause when no module is being downloaded
	assert_int_equal(evp_agent_request_pause_deployment(ctxt), EAGAIN);

	// Request pause when no module is being downloaded
	while (evp_agent_request_pause_deployment(ctxt)) {
		agent_poll(verify_equals,
			   RECONCILE_EVENT(DEPLOYMENT_ID2, paused));
	}

	print_message("[  INFO   ] Paused\n");

	// Send a new deployment with a module to download
	send_deployment(ctxt, DEPLOYMENT_ID1, INSTANCE_ID1, MODULE_1,
			MODULE_1_HASH);

	// Resume deployment capability
	assert_int_equal(evp_agent_resume_deployment(ctxt), 0);

	// wait for the deployment
	agent_poll(verify_equals, RECONCILE_EVENT(DEPLOYMENT_ID1, ok));
	agent_poll(verify_contains, INSTANCE_ID1);
}

int
main(void)
{
	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_teardown(pause_deployment_not_in_progress,
					  test_teardown),
		cmocka_unit_test_teardown(pause_deployment_in_progress,
					  test_teardown),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, suite_setup, suite_teardown);
}
