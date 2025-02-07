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

enum {
	DEPLOYMENT_MANIFEST_TEMPLATE,
	EMPTY_DEPLOYMENT_MANIFEST,
	DEPLOYMENT_STATUS_1_FMT
};

#define DEPLOYMENT_ID1 "31a42d86-966c-4f93-b5fd-65be7e60348a"
#define DEPLOYMENT_ID0 "4fa905ae-e103-46ab-a8b9-73be07599708"
#define MODULE_ID      "af1215e1-fbf7-4da8-b606-f2a0718ee82a"
#define INSTANCE_ID    "b708c3fa-399e-4d52-9e9c-01d53e95b099"

#define MODULE_FILE "not_found.wasm"
#define MODULE_PATH "http://localhost:%hu/%s"

#define MODULE_1_HASH                                                         \
	"579fca500ec9f67a661e8b1a3a59a114a97029c46776d6ad9502fb183f1a1f7d"
#define MODULE_HASH "%s"

#define EVP1_DEPLOYMENT_MANIFEST_TEMPLATE                                     \
	"\"{ "                                                                \
	"        \\\"deploymentId\\\": \\\"%s\\\","                           \
	"        \\\"instanceSpecs\\\": {"                                    \
	"            \\\"%s\\\": {"                                           \
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
	"\"" MODULE_ID "\","                                                  \
	"                \"publish\": {},"                                    \
	"                \"subscribe\": {}"                                   \
	"            }"                                                       \
	"        },"                                                          \
	"        \"modules\": {"                                              \
	"            \"" MODULE_ID "\": {"                                    \
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

#define EVP1_DEPLOY_STATUS_1_FMT                                              \
	"deploymentStatus=#{"                                                 \
	"modules." MODULE_ID ".failureMessage=%s,"                            \
	"modules." MODULE_ID ".status=%s"                                     \
	"}"

#define EVP2_DEPLOY_STATUS_1_FMT                                              \
	"deploymentStatus.modules." MODULE_ID ".failureMessage=%s,"           \
	"deploymentStatus.modules." MODULE_ID ".status=%s"

unsigned short backend_port;

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

static int
test_teardown(void **state)
{
	struct evp_agent_context *ctxt = *state;
	const char *deployment;

	// send empty deployment
	deployment = agent_get_payload(EMPTY_DEPLOYMENT_MANIFEST);
	agent_send_deployment(ctxt, deployment);
	agent_poll(verify_contains,
		   "on_reconcileStatus/" DEPLOYMENT_ID0 "/ok");
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
on_get_file(const struct http_payload *p, struct http_response *r, void *user)
{
	static const char body[] = "nuttx webclient still requires a body";

	*r = (struct http_response){.status = HTTP_STATUS_NOT_FOUND,
				    .buf.ro = body,
				    .n = strlen(body)};

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

	agent_register_payload(DEPLOYMENT_STATUS_1_FMT, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_DEPLOY_STATUS_1_FMT);
	agent_register_payload(DEPLOYMENT_STATUS_1_FMT, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_DEPLOY_STATUS_1_FMT);

	// start agent
	struct evp_agent_context *ctxt = *state = agent_test_start();

	assert_int_equal(evp_agent_notification_subscribe(
				 ctxt, "deployment/reconcileStatus",
				 on_reconcileStatus, NULL),
			 0);
	const char *deployment;

	// Send initial empty deployment
	deployment = agent_get_payload(EMPTY_DEPLOYMENT_MANIFEST);
	agent_send_initial(ctxt, deployment, NULL, NULL);

	// wait for reconcile status ok
	agent_poll(verify_contains,
		   "on_reconcileStatus/" DEPLOYMENT_ID0 "/ok");

	print_message("[  INFO   ] Deployment ok\n");
	return 0;
}

static void
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

int
__wrap_webclient_perform(FAR struct webclient_context *ctx)
{
	int __real_webclient_perform(FAR struct webclient_context * ctx);
	return __real_webclient_perform(ctx);
}

static void
failed_http(void **state)
{
	struct evp_agent_context *ctxt = *state;

	// Send a new deployment with a module to download
	send_deployment(ctxt, DEPLOYMENT_ID1, INSTANCE_ID, MODULE_FILE,
			MODULE_1_HASH);

	// wait for the deployment status to be applying
	agent_poll(verify_json, agent_get_payload(DEPLOYMENT_STATUS_1_FMT),
		   "Download failed HTTP Response = 404", "error");
}

__attribute__((weak)) int
__wrap_check_hash(struct module *module, const unsigned char *ref,
		  size_t ref_len, char **result)
{
	int __real_check_hash(struct module * module, const unsigned char *ref,
			      size_t ref_len, char **result);
	return __real_check_hash(module, ref, ref_len, result);
}

int
main(void)
{
	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_teardown(failed_http, test_teardown),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, suite_setup, suite_teardown);
}
