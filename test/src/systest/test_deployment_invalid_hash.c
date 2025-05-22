/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <parson.h>

#include <internal/util.h>

#include "agent_test.h"
#include "hub.h"
#include "mqtt_custom.h"

enum test_deployment_payloads {
	DEPLOYMENT_MANIFEST_1,
	DEPLOYMENT_MANIFEST_2,
	DEPLOYMENT_STATUS_1_FMT,
	DEPLOYMENT_STATUS_2_FMT
};

static struct test {
	pthread_mutex_t mtx;
	bool fail;
} test = {.mtx = PTHREAD_MUTEX_INITIALIZER};

#define DEPLOYMENT_ID_1 "4fa905ae-e103-46ab-a8b9-73be07599708"
#define DEPLOYMENT_ID_2 "8543e017-2d93-444b-bd4c-bcaa39c46095"

#define INSTANCE1_ID "acb69828-ccd5-47ee-818c-bd6939c8f40f"
#define INSTANCE2_ID "970ea56c-6334-4ad1-96c9-29473cd94f76"
#define MODULE_ID    "b218f90b-9228-423f-8e02-a6d3527bc15d"
#define MODULE_URL   "file://../test_modules/config_echo.wasm"
#define MODULE_HASH                                                           \
	"73aa09694abf7c7bb8496a82b7de38a24b81a7f93e437a74912413ac4f2be06e"

#define EVP1_DEPLOY_MANIFEST_1                                                \
	"\"{ "                                                                \
	"        \\\"deploymentId\\\": "                                      \
	"\\\"" DEPLOYMENT_ID_1 "\\\","                                        \
	"        \\\"instanceSpecs\\\": {"                                    \
	"            \\\"" INSTANCE1_ID "\\\": {"                             \
	"                \\\"moduleId\\\": "                                  \
	"\\\"" MODULE_ID "\\\","                                              \
	"                \\\"entryPoint\\\": \\\"main\\\","                   \
	"                \\\"version\\\": 1,"                                 \
	"                \\\"publish\\\": {},"                                \
	"                \\\"subscribe\\\": {}"                               \
	"            },"                                                      \
	"            \\\"" INSTANCE2_ID "\\\": {"                             \
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
	"                \\\"downloadUrl\\\": \\\"" MODULE_URL "\\\","        \
	"                \\\"hash\\\": \\\"deadc0ffee\\\""                    \
	"            }"                                                       \
	"        },"                                                          \
	"        \\\"publishTopics\\\": {},"                                  \
	"        \\\"subscribeTopics\\\": {}"                                 \
	"}\""

#define EVP2_DEPLOY_MANIFEST_1                                                \
	"{"                                                                   \
	"        \"deploymentId\": \"" DEPLOYMENT_ID_1 "\","                  \
	"        \"instanceSpecs\": {"                                        \
	"            \"" INSTANCE1_ID "\": {"                                 \
	"                \"moduleId\": "                                      \
	"\"" MODULE_ID "\","                                                  \
	"                \"publish\": {},"                                    \
	"                \"subscribe\": {}"                                   \
	"            },"                                                      \
	"            \"" INSTANCE2_ID "\": {"                                 \
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
	"                \"downloadUrl\": \"" MODULE_URL "\","                \
	"                \"hash\": \"deadc0ffee\""                            \
	"            }"                                                       \
	"        },"                                                          \
	"        \"publishTopics\": {},"                                      \
	"        \"subscribeTopics\": {}"                                     \
	"}"

#define EVP1_DEPLOY_MANIFEST_2                                                \
	"\"{ "                                                                \
	"        \\\"deploymentId\\\": "                                      \
	"\\\"" DEPLOYMENT_ID_2 "\\\","                                        \
	"        \\\"instanceSpecs\\\": {"                                    \
	"            \\\"" INSTANCE1_ID "\\\": {"                             \
	"                \\\"moduleId\\\": "                                  \
	"\\\"" MODULE_ID "\\\","                                              \
	"                \\\"entryPoint\\\": \\\"main\\\","                   \
	"                \\\"version\\\": 1,"                                 \
	"                \\\"publish\\\": {},"                                \
	"                \\\"subscribe\\\": {}"                               \
	"            },"                                                      \
	"            \\\"" INSTANCE2_ID "\\\": {"                             \
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
	"                \\\"downloadUrl\\\": \\\"" MODULE_URL "\\\","        \
	"                \\\"hash\\\": \\\"" MODULE_HASH "\\\""               \
	"            }"                                                       \
	"        },"                                                          \
	"        \\\"publishTopics\\\": {},"                                  \
	"        \\\"subscribeTopics\\\": {}"                                 \
	"}\""

#define EVP2_DEPLOY_MANIFEST_2                                                \
	"{"                                                                   \
	"        \"deploymentId\": \"" DEPLOYMENT_ID_2 "\","                  \
	"        \"instanceSpecs\": {"                                        \
	"            \"" INSTANCE1_ID "\": {"                                 \
	"                \"moduleId\": "                                      \
	"\"" MODULE_ID "\","                                                  \
	"                \"publish\": {},"                                    \
	"                \"subscribe\": {}"                                   \
	"            },"                                                      \
	"            \"" INSTANCE2_ID "\": {"                                 \
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
	"                \"downloadUrl\": \"" MODULE_URL "\","                \
	"                \"hash\": \"" MODULE_HASH "\""                       \
	"            }"                                                       \
	"        },"                                                          \
	"        \"publishTopics\": {},"                                      \
	"        \"subscribeTopics\": {}"                                     \
	"}"

/* clang-format off */

#define EVP1_DEPLOY_STATUS_1_FMT \
	"deploymentStatus=#{" \
		"modules." MODULE_ID ".status=%s," \
		"modules." MODULE_ID ".failureMessage=%s," \
		"reconcileStatus=%s," \
		"deploymentId=%s" \
	"}"

#define EVP2_DEPLOY_STATUS_1_FMT \
	"deploymentStatus.modules." MODULE_ID ".status=%s," \
	"deploymentStatus.modules." MODULE_ID ".failureMessage=%s," \
	"deploymentStatus.reconcileStatus=%s," \
	"deploymentStatus.deploymentId=%s"

#define EVP1_DEPLOY_STATUS_2_FMT \
	"deploymentStatus=#{" \
		"modules." MODULE_ID ".status=%s," \
		"reconcileStatus=%s," \
		"deploymentId=%s" \
	"}"

#define EVP2_DEPLOY_STATUS_2_FMT \
	"deploymentStatus.modules." MODULE_ID ".status=%s," \
	"deploymentStatus.reconcileStatus=%s," \
	"deploymentStatus.deploymentId=%s"

/* clang-format on */

int
__wrap_check_hash(struct module *module, const unsigned char *ref,
		  size_t ref_len, char **result)
{
	assert(!pthread_mutex_lock(&test.mtx));
	*result = test.fail ? xstrdup("Module hash mismatch") : NULL;
	assert(!pthread_mutex_unlock(&test.mtx));
	return 0;
}

static int
on_reconcileStatus(const void *args, void *user_data)
{
	const struct reconcileStatusNotify *reconcileStatusData = args;

	// deploymentId can be empty (Whenre there is an EmptyDeployment)
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

static void
set_fail(bool value)
{
	assert_int_equal(pthread_mutex_lock(&test.mtx), 0);
	test.fail = value;
	assert_int_equal(pthread_mutex_unlock(&test.mtx), 0);
}

static void
test_deployment_invalid_hash(void **state)
{
	struct evp_agent_context *ctxt = *state;

	set_fail(true);
	agent_send_initial(ctxt, agent_get_payload(DEPLOYMENT_MANIFEST_1),
			   NULL, NULL);
	agent_poll(verify_json, agent_get_payload(DEPLOYMENT_STATUS_1_FMT),
		   "error", "Module hash mismatch", "applying",
		   DEPLOYMENT_ID_1);
}

static void
test_deployment_invalid_hash_valid(void **state)
{
	struct evp_agent_context *ctxt = *state;

	set_fail(true);
	agent_send_deployment(ctxt, agent_get_payload(DEPLOYMENT_MANIFEST_1));
	agent_poll(verify_json, agent_get_payload(DEPLOYMENT_STATUS_1_FMT),
		   "error", "Module hash mismatch", "applying",
		   DEPLOYMENT_ID_1);
	set_fail(false);
	agent_send_deployment(ctxt, agent_get_payload(DEPLOYMENT_MANIFEST_2));
	agent_poll(verify_json, agent_get_payload(DEPLOYMENT_STATUS_2_FMT),
		   "ok", "ok", DEPLOYMENT_ID_2);
}

static int
setup(void **state)
{
	agent_test_setup();
	// start agent
	*state = agent_test_start();

	assert_int_equal(evp_agent_notification_subscribe(
				 *state, "deployment/reconcileStatus",
				 on_reconcileStatus, NULL),
			 0);

	agent_register_payload(DEPLOYMENT_MANIFEST_1, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_DEPLOY_MANIFEST_1);
	agent_register_payload(DEPLOYMENT_MANIFEST_1, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_DEPLOY_MANIFEST_1);

	agent_register_payload(DEPLOYMENT_MANIFEST_2, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_DEPLOY_MANIFEST_2);

	agent_register_payload(DEPLOYMENT_MANIFEST_2, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_DEPLOY_MANIFEST_2);

	agent_register_payload(DEPLOYMENT_STATUS_1_FMT, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_DEPLOY_STATUS_1_FMT);
	agent_register_payload(DEPLOYMENT_STATUS_1_FMT, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_DEPLOY_STATUS_1_FMT);

	agent_register_payload(DEPLOYMENT_STATUS_2_FMT, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_DEPLOY_STATUS_2_FMT);
	agent_register_payload(DEPLOYMENT_STATUS_2_FMT, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_DEPLOY_STATUS_2_FMT);

	return 0;
}

static int
teardown(void **state)
{
	agent_test_exit();
	return pthread_mutex_destroy(&test.mtx);
}

int
main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_deployment_invalid_hash),
		cmocka_unit_test(test_deployment_invalid_hash_valid),
	};

	return cmocka_run_group_tests(tests, setup, teardown);
}
