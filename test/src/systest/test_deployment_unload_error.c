/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <parson.h>

#include <internal/util.h>

#include "agent_test.h"
#include "hub.h"
#include "module.h"
#include "mqtt_custom.h"

enum test_deployment_payloads {
	DEPLOYMENT_MANIFEST_1,
	DEPLOYMENT_MANIFEST_2,
	DEPLOYMENT_STATUS_1_FMT,
	DEPLOYMENT_STATUS_1to2_FMT,
	DEPLOYMENT_STATUS_2_FMT
};

static struct test {
	pthread_mutex_t mtx;
	bool hash_fail;
	bool unload_fail;

} test = {.mtx = PTHREAD_MUTEX_INITIALIZER};

#define TEST_DEPLOYMENT_ID1       "4fa905ae-e103-46ab-a8b9-111111111111"
#define TEST_DEPLOYMENT_ID2       "4fa905ae-e103-46ab-a8b9-222222222222"
#define TEST_EMPTY_DEPLOYMENT_ID1 "4fa905ae-e103-46ab-a8b9-73be07599709"

#define TEST_MODULE_ID1 "aaaaaaaa-9228-423f-8e02-111111111111"
#define TEST_MODULE_ID2 "bbbbbbbb-9228-423f-8e02-222222222222"

#define TEST_INSTANCE_ID1 "b218f90b-9228-423f-8e02-111111111111"
#define TEST_INSTANCE_ID2 "b218f90b-9228-423f-8e02-222222222222"

#define EVP1_DEPLOY_STATUS_1_FMT                                              \
	"deploymentStatus=#{"                                                 \
	"modules." TEST_MODULE_ID1 ".status=%s,"                              \
	"reconcileStatus=%s,"                                                 \
	"deploymentId=%s"                                                     \
	"}"

#define EVP2_DEPLOY_STATUS_1_FMT                                              \
	"deploymentStatus.modules." TEST_MODULE_ID1 ".status=%s,"             \
	"deploymentStatus.reconcileStatus=%s,"                                \
	"deploymentStatus.deploymentId=%s"

// 1to2 means the status when deployment 1 is still undeploying
// but there is an error (EAGAIN) unloading the module
// until the agent is able to fix the unloading problem
// and finally starts to apply deployment 2
#define EVP1_DEPLOY_STATUS_1to2_FMT                                           \
	"deploymentStatus=#{"                                                 \
	"modules." TEST_MODULE_ID1 ".status=%s,"                              \
	"reconcileStatus=%s,"                                                 \
	"deploymentId=%s"                                                     \
	"}"

#define EVP2_DEPLOY_STATUS_1to2_FMT                                           \
	"deploymentStatus.modules." TEST_MODULE_ID1 ".status=%s,"             \
	"deploymentStatus.reconcileStatus=%s,"                                \
	"deploymentStatus.deploymentId=%s"

#define EVP1_DEPLOY_STATUS_2_FMT                                              \
	"deploymentStatus=#{"                                                 \
	"modules." TEST_MODULE_ID2 ".status=%s,"                              \
	"reconcileStatus=%s,"                                                 \
	"deploymentId=%s"                                                     \
	"}"

#define EVP2_DEPLOY_STATUS_2_FMT                                              \
	"deploymentStatus.modules." TEST_MODULE_ID2 ".status=%s,"             \
	"deploymentStatus.reconcileStatus=%s,"                                \
	"deploymentStatus.deploymentId=%s"

#define MODULE_URL "file://../test_modules/config_echo.wasm"
#define MODULE_HASH                                                           \
	"579fca500ec9f67a661e8b1a3a59a114a97029c46776d6ad9502fb183f1a1f7d"

#define EVP1_DEPLOYMENT_MANIFEST_1                                            \
	"\"{ "                                                                \
	"        \\\"deploymentId\\\": "                                      \
	"\\\"" TEST_DEPLOYMENT_ID1 "\\\","                                    \
	"        \\\"instanceSpecs\\\": {"                                    \
	"            \\\"" TEST_INSTANCE_ID1 "\\\": {"                        \
	"                \\\"moduleId\\\": "                                  \
	"\\\"" TEST_MODULE_ID1 "\\\","                                        \
	"                \\\"entryPoint\\\": \\\"main\\\","                   \
	"                \\\"version\\\": 1,"                                 \
	"                \\\"publish\\\": {},"                                \
	"                \\\"subscribe\\\": {}"                               \
	"            }"                                                       \
	"        },"                                                          \
	"        \\\"modules\\\": {"                                          \
	"            \\\"" TEST_MODULE_ID1 "\\\": {"                          \
	"                \\\"moduleImpl\\\": \\\"wasm\\\","                   \
	"                \\\"downloadUrl\\\": \\\"" MODULE_URL "\\\","        \
	"                \\\"hash\\\": \\\"" MODULE_HASH "\\\""               \
	"            }"                                                       \
	"        },"                                                          \
	"        \\\"publishTopics\\\": {},"                                  \
	"        \\\"subscribeTopics\\\": {}"                                 \
	"}\""

#define EVP2_DEPLOYMENT_MANIFEST_1                                            \
	"{"                                                                   \
	"        \"deploymentId\": \"" TEST_DEPLOYMENT_ID1 "\","              \
	"        \"instanceSpecs\": {"                                        \
	"            \"" TEST_INSTANCE_ID1 "\": {"                            \
	"                \"moduleId\": "                                      \
	"\"" TEST_MODULE_ID1 "\","                                            \
	"                \"publish\": {},"                                    \
	"                \"subscribe\": {}"                                   \
	"            }"                                                       \
	"        },"                                                          \
	"        \"modules\": {"                                              \
	"            \"" TEST_MODULE_ID1 "\": {"                              \
	"                \"entryPoint\": \"main\","                           \
	"                \"moduleImpl\": \"wasm\","                           \
	"                \"downloadUrl\": "                                   \
	"\"" MODULE_URL "\","                                                 \
	"                \"hash\": "                                          \
	"\"" MODULE_HASH ""                                                   \
	"\""                                                                  \
	"            }"                                                       \
	"        },"                                                          \
	"        \"publishTopics\": {},"                                      \
	"        \"subscribeTopics\": {}"                                     \
	"}"

#define EVP1_DEPLOYMENT_MANIFEST_2                                            \
	"\"{ "                                                                \
	"        \\\"deploymentId\\\": "                                      \
	"\\\"" TEST_DEPLOYMENT_ID2 "\\\","                                    \
	"        \\\"instanceSpecs\\\": {"                                    \
	"            \\\"" TEST_INSTANCE_ID2 "\\\": {"                        \
	"                \\\"moduleId\\\": "                                  \
	"\\\"" TEST_MODULE_ID2 "\\\","                                        \
	"                \\\"entryPoint\\\": \\\"main\\\","                   \
	"                \\\"version\\\": 1,"                                 \
	"                \\\"publish\\\": {},"                                \
	"                \\\"subscribe\\\": {}"                               \
	"            }"                                                       \
	"        },"                                                          \
	"        \\\"modules\\\": {"                                          \
	"            \\\"" TEST_MODULE_ID2 "\\\": {"                          \
	"                \\\"moduleImpl\\\": \\\"wasm\\\","                   \
	"                \\\"downloadUrl\\\": \\\"" MODULE_URL "\\\","        \
	"                \\\"hash\\\": \\\"" MODULE_HASH "\\\""               \
	"            }"                                                       \
	"        },"                                                          \
	"        \\\"publishTopics\\\": {},"                                  \
	"        \\\"subscribeTopics\\\": {}"                                 \
	"}\""

#define EVP2_DEPLOYMENT_MANIFEST_2                                            \
	"{"                                                                   \
	"        \"deploymentId\": \"" TEST_DEPLOYMENT_ID2 "\","              \
	"        \"instanceSpecs\": {"                                        \
	"            \"" TEST_INSTANCE_ID2 "\": {"                            \
	"                \"moduleId\": "                                      \
	"\"" TEST_MODULE_ID2 "\","                                            \
	"                \"publish\": {},"                                    \
	"                \"subscribe\": {}"                                   \
	"            }"                                                       \
	"        },"                                                          \
	"        \"modules\": {"                                              \
	"            \"" TEST_MODULE_ID2 "\": {"                              \
	"                \"entryPoint\": \"main\","                           \
	"                \"moduleImpl\": \"wasm\","                           \
	"                \"downloadUrl\": "                                   \
	"\"" MODULE_URL "\","                                                 \
	"                \"hash\": "                                          \
	"\"" MODULE_HASH ""                                                   \
	"\""                                                                  \
	"            }"                                                       \
	"        },"                                                          \
	"        \"publishTopics\": {},"                                      \
	"        \"subscribeTopics\": {}"                                     \
	"}"

#define EVP1_EMPTY_DEPLOYMENT_MANIFEST_1                                      \
	"\"{ "                                                                \
	"        \\\"deploymentId\\\": "                                      \
	"\\\"" TEST_EMPTY_DEPLOYMENT_ID1 "\\\","                              \
	"        \\\"instanceSpecs\\\": {},"                                  \
	"        \\\"modules\\\": {},"                                        \
	"        \\\"publishTopics\\\": {},"                                  \
	"        \\\"subscribeTopics\\\": {}"                                 \
	"}\""

#define EVP2_EMPTY_DEPLOYMENT_MANIFEST_1                                      \
	"{"                                                                   \
	"        \"deploymentId\": \"" TEST_EMPTY_DEPLOYMENT_ID1 "\","        \
	"        \"instanceSpecs\": {},"                                      \
	"        \"modules\": {},"                                            \
	"        \"publishTopics\": {},"                                      \
	"        \"subscribeTopics\": {}"                                     \
	"}"

/* clang-format on */

int
__wrap_module_unload(const struct ModuleList *list)
{
	int ret;
	int __real_module_unload(const struct ModuleList *list);
	assert(!pthread_mutex_lock(&test.mtx));
	if (test.unload_fail) {
		ret = EAGAIN;
	} else {
		ret = __real_module_unload(list);
	}
	assert(!pthread_mutex_unlock(&test.mtx));
	return ret;
}

int
__wrap_check_hash(struct module *module, const unsigned char *ref,
		  size_t ref_len, char **result)
{
	int ret;
	assert(!pthread_mutex_lock(&test.mtx));
	ret = test.hash_fail ? EINVAL : 0;
	*result = NULL;
	assert(!pthread_mutex_unlock(&test.mtx));
	return ret;
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
set_fail(bool hash_fail, bool unload_fail)
{
	assert_int_equal(pthread_mutex_lock(&test.mtx), 0);
	test.hash_fail = hash_fail;
	test.unload_fail = unload_fail;
	assert_int_equal(pthread_mutex_unlock(&test.mtx), 0);
}

/* clang-format off */
/*
 * To reproduce ADI-2283
 * The goal of this test is to validate that a invalid deployment,
 * for example, a deployment where there is a problem with the hash
 * or signed module
 * is not affecting the nexte valid deployment.
 * The exact case is:
 * 	1- 	Send a deployment DEPLOYMENT_MANIFEST_1 with a module wrong
 * 		signed
 * 	2- 	Check that the reported status is "applying" for
 * 		DEPLOYMENT_MANIFEST_1 since the agent tries to download the
 * 		module again when the hash or the signature is invalid.
 *	3-	Simulate that the there is a blob operation in progress so the
 *		reconcile process can not cancel the current operation and the
 *		agent has to wait until is done. The direct cause of this is that
 *		the unload operation cant not be done (see__wrap_module_unload)
 *	4-	Send a new valid deployment DEPLOYMENT_MANIFEST_2
 *	5-  Check that the reported status is "applying" for
 *		DEPLOYMENT_MANIFEST_1 but reporting the module from
 * 		DEPLOYMENT_MANIFEST_1, since the unload operation is still in progress.
 * 	6- 	Simulate that the agent
 * 		finally was able to unload the module (when the blob operation ends
 * 		the agent can unload the module)
 *	7- 	Finally the new deployment is correctly applied.
 */

/* clang-format on */
static void
test_deployment_unload_error(void **state)
{
	struct evp_agent_context *ctxt = *state;

	/* Step 1 */
	/* Simulate hash error, ok to unload */
	set_fail(true, false);
	agent_send_initial(ctxt, agent_get_payload(DEPLOYMENT_MANIFEST_1),
			   NULL, NULL);
	/* Step 2.
	 * 	The module status is unknow because camFW is not reporting any
	 * 	status at this moment */
	agent_poll(verify_json, agent_get_payload(DEPLOYMENT_STATUS_1_FMT),
		   "unknown", "applying", TEST_DEPLOYMENT_ID1);

	/* Step 3 */
	set_fail(true, true);

	/* Step 4 */
	agent_send_deployment(ctxt, agent_get_payload(DEPLOYMENT_MANIFEST_2));

	/* Step 5 */
	agent_poll(verify_json, agent_get_payload(DEPLOYMENT_STATUS_1to2_FMT),
		   "unknown", "applying", TEST_DEPLOYMENT_ID2);

	/* Step 6 */
	set_fail(false, false);
	/* Step 7 */
	agent_poll(verify_json, agent_get_payload(DEPLOYMENT_STATUS_2_FMT),
		   "ok", "ok", TEST_DEPLOYMENT_ID2);
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
			       EVP1_DEPLOYMENT_MANIFEST_1);
	agent_register_payload(DEPLOYMENT_MANIFEST_1, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_DEPLOYMENT_MANIFEST_1);

	agent_register_payload(DEPLOYMENT_MANIFEST_2, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_DEPLOYMENT_MANIFEST_2);

	agent_register_payload(DEPLOYMENT_MANIFEST_2, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_DEPLOYMENT_MANIFEST_2);

	agent_register_payload(DEPLOYMENT_STATUS_1_FMT, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_DEPLOY_STATUS_1_FMT);
	agent_register_payload(DEPLOYMENT_STATUS_1_FMT, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_DEPLOY_STATUS_1_FMT);

	agent_register_payload(DEPLOYMENT_STATUS_1to2_FMT,
			       EVP_HUB_TYPE_EVP1_TB,
			       EVP1_DEPLOY_STATUS_1to2_FMT);
	agent_register_payload(DEPLOYMENT_STATUS_1to2_FMT,
			       EVP_HUB_TYPE_EVP2_TB,
			       EVP2_DEPLOY_STATUS_1to2_FMT);

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
		cmocka_unit_test(test_deployment_unload_error),
	};

	return cmocka_run_group_tests(tests, setup, teardown);
}
