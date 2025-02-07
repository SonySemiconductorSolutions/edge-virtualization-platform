/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

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
	DEPLOYMENT_STATUS_1,
	DEPLOYMENT_STATUS_2,
	DEPLOYMENT_STATUS_1_FMT,
	DEPLOYMENT_STATUS_2_FMT
};

#define DEPLOYMENT_ID_1 "4fa905ae-e103-46ab-a8b9-73be07599708"
#define DEPLOYMENT_ID_2 "8543e017-2d93-444b-bd4c-bcaa39c46095"

#define INSTANCE1_ID "acb69828-ccd5-47ee-818c-bd6939c8f40f"
#define INSTANCE2_ID "970ea56c-6334-4ad1-96c9-29473cd94f76"
#define MODULE_ID    "b218f90b-9228-423f-8e02-a6d3527bc15d"
#define MODULE_URL   "file://../test_modules/config_echo.wasm"

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
	"                \\\"hash\\\": \\\"\\\""                              \
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
	"                \"hash\": \"\""                                      \
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
	"        },"                                                          \
	"        \\\"modules\\\": {"                                          \
	"        },"                                                          \
	"        \\\"publishTopics\\\": {},"                                  \
	"        \\\"subscribeTopics\\\": {}"                                 \
	"}\""

#define EVP2_DEPLOY_MANIFEST_2                                                \
	"{"                                                                   \
	"        \"deploymentId\": \"" DEPLOYMENT_ID_2 "\","                  \
	"        \"instanceSpecs\": {"                                        \
	"        },"                                                          \
	"        \"modules\": {"                                              \
	"        },"                                                          \
	"        \"publishTopics\": {},"                                      \
	"        \"subscribeTopics\": {}"                                     \
	"}"

/* clang-format off */

#define EVP1_DEPLOY_STATUS_1 \
	"{" \
	"	\"instances\": {" \
	"		\"" INSTANCE1_ID "\": {" \
	"			\"status\": \"ok\"" \
	"		}" \
	"	}," \
	"	\"modules\": {" \
	"		\"" MODULE_ID "\": {" \
	"			\"status\": \"ok\"" \
	"		}" \
	"	}," \
	"	\"deploymentId\": \"" DEPLOYMENT_ID_1 "\"," \
	"	\"reconcileStatus\": \"oks\"" \
	"}"

#define EVP2_DEPLOY_STATUS_1 \
	"{" \
	"	\"deploymentStatus\": {" \
	"		\"instances\": {" \
	"			\"" INSTANCE1_ID "\": {" \
	"				\"status\": \"ok\"," \
	"				\"moduleId\": \"" MODULE_ID "\"" \
	"			}" \
	"		}," \
	"		\"modules\": {" \
	"			\"" MODULE_ID "\": {" \
	"				\"status\": \"ok\"" \
	"			}" \
	"		}," \
	"		\"deploymentId\": \"" DEPLOYMENT_ID_1 "\"," \
	"		\"reconcileStatus\": \"ok\"" \
	"	}" \
	"}"

#define EVP1_DEPLOY_STATUS_2 \
	"{" \
	"	\"instances\": {" \
	"	}," \
	"	\"modules\": {" \
	"	}," \
	"	\"deploymentId\": \"" DEPLOYMENT_ID_2 "\"," \
	"	\"reconcileStatus\": \"oks\"" \
	"}"

#define EVP2_DEPLOY_STATUS_2 \
	"{" \
	"	\"deploymentStatus\": {" \
	"		}," \
	"		\"modules\": {" \
	"		}," \
	"		\"deploymentId\": \"" DEPLOYMENT_ID_2 "\"," \
	"		\"reconcileStatus\": \"ok\"" \
	"	}" \
	"}"

#define EVP1_DEPLOY_STATUS_1_FMT \
	"deploymentStatus=#{" \
		"instances." INSTANCE1_ID ".status=%s," \
		"instances." INSTANCE2_ID ".status=%s," \
		"modules." MODULE_ID ".status=%s," \
		"deploymentId=%s" \
	"}"

#define EVP2_DEPLOY_STATUS_1_FMT \
	"deploymentStatus.instances." INSTANCE1_ID ".status=%s," \
	"deploymentStatus.instances." INSTANCE2_ID ".status=%s," \
	"deploymentStatus.modules." MODULE_ID ".status=%s," \
	"deploymentStatus.deploymentId=%s"

#define EVP1_DEPLOY_STATUS_2_FMT \
	"deploymentStatus=#{" \
		"deploymentId=%s" \
	"}"

#define EVP2_DEPLOY_STATUS_2_FMT "deploymentStatus.deploymentId=%s"

/* clang-format on */

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
test_deployment(void **state)
{
	// start agent
	struct evp_agent_context *ctxt = agent_test_start();

	assert_int_equal(evp_agent_notification_subscribe(
				 ctxt, "deployment/reconcileStatus",
				 on_reconcileStatus, NULL),
			 0);

	// Note: the notification event has to polled before polling the
	// deployment status because the agent generates first the event then
	// the report.

	// test initial deployment (managed object / shared attribute)
	agent_send_initial(ctxt, agent_get_payload(DEPLOYMENT_MANIFEST_1),
			   NULL, NULL);
	agent_poll(verify_contains,
		   "on_reconcileStatus/" DEPLOYMENT_ID_1 "/ok");
	agent_poll(verify_json, agent_get_payload(DEPLOYMENT_STATUS_1_FMT),
		   "ok", "ok", "ok", DEPLOYMENT_ID_1);
	agent_send_deployment(ctxt, agent_get_payload(DEPLOYMENT_MANIFEST_2));
	agent_poll(verify_contains,
		   "on_reconcileStatus/" DEPLOYMENT_ID_2 "/ok");
	agent_poll(verify_json, agent_get_payload(DEPLOYMENT_STATUS_2_FMT),
		   DEPLOYMENT_ID_2);
}

static int
setup(void **state)
{
	agent_test_setup();
	agent_register_payload(DEPLOYMENT_MANIFEST_1, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_DEPLOY_MANIFEST_1);
	agent_register_payload(DEPLOYMENT_MANIFEST_1, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_DEPLOY_MANIFEST_1);
	agent_register_payload(DEPLOYMENT_STATUS_1, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_DEPLOY_STATUS_1);
	agent_register_payload(DEPLOYMENT_STATUS_1, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_DEPLOY_STATUS_1);

	agent_register_payload(DEPLOYMENT_MANIFEST_2, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_DEPLOY_MANIFEST_2);
	agent_register_payload(DEPLOYMENT_STATUS_2, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_DEPLOY_STATUS_2);

	agent_register_payload(DEPLOYMENT_MANIFEST_2, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_DEPLOY_MANIFEST_2);
	agent_register_payload(DEPLOYMENT_STATUS_2, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_DEPLOY_STATUS_2);

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
	return 0;
}

int
main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_deployment),
	};

	return cmocka_run_group_tests(tests, setup, teardown);
}
