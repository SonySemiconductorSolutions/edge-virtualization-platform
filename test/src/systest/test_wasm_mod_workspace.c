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
	DEPLOYMENT_MANIFEST_2,
	DEPLOYMENT_MANIFEST_3,
	EMPTY_DEPLOYMENT_MANIFEST_1,
	INSTANCE_CONFIG_1,
	B64_G_STEP_0_1,
	B64_G_STEP_3_1,
	B64_G_STEP_1000_1,
	B64_ENOENT_1,
	B64_AAAAA_1,
	B64_BBB_1,
};

#define TEST_DEPLOYMENT_ID1       "4fa905ae-e103-46ab-a8b9-73be07599708"
#define TEST_DEPLOYMENT_ID2       "4fa905ae-e103-46ab-a8b9-73be07599710"
#define TEST_DEPLOYMENT_ID3       "4fa905ae-e103-46ab-a8b9-73be07599711"
#define TEST_EMPTY_DEPLOYMENT_ID1 "4fa905ae-e103-46ab-a8b9-73be07599709"
#define TEST_WORKSPACE_A          "workspace-test-A"
#define TEST_WORKSPACE_B          "workspace-test-B"
#define TEST_WORKSPACE_C          "workspace-test-C"

#define B64_G_STEP_0    "Z19zdGVwID0gMA=="
#define B64_G_STEP_3    "Z19zdGVwID0gMw=="
#define B64_G_STEP_1000 "Z19zdGVwID0gMTAwMA=="
#define B64_ENOENT      "RU5PRU5U"
#define B64_AAAAA       "QUFBQUE="
#define B64_BBB         "QkJC"

#define MODULE_PATH_WRITER "../test_modules/file_writer.wasm"
#define MODULE_HASH_WRITER                                                    \
	"579fca500ec9f67a661e8b1a3a59a114a97029c46776d6ad9502fb183f1a1f7d"
#define MODULE_WRITER_ID "writer-wasm"

#define MODULE_PATH_READER "../test_modules/file_reader.wasm"
#define MODULE_HASH_READER                                                    \
	"579fca500ec9f67a661e8b1a3a59a114a97029c46776d6ad9502fb183f1a1f7d"
#define MODULE_READER_ID "reader-wasm"

#define EVP1_DEPLOYMENT_MANIFEST_1                                            \
	"\"{ "                                                                \
	"        \\\"deploymentId\\\": "                                      \
	"\\\"" TEST_DEPLOYMENT_ID1 "\\\","                                    \
	"        \\\"instanceSpecs\\\": {"                                    \
	"            \\\"" TEST_WORKSPACE_A "\\\": {"                         \
	"                \\\"moduleId\\\": "                                  \
	"\\\"" MODULE_WRITER_ID "\\\","                                       \
	"                \\\"entryPoint\\\": \\\"main\\\","                   \
	"                \\\"version\\\": 1,"                                 \
	"                \\\"publish\\\": {},"                                \
	"                \\\"subscribe\\\": {}"                               \
	"            },"                                                      \
	"            \\\"" TEST_WORKSPACE_B "\\\": {"                         \
	"                \\\"moduleId\\\": "                                  \
	"\\\"" MODULE_WRITER_ID "\\\","                                       \
	"                \\\"entryPoint\\\": \\\"main\\\","                   \
	"                \\\"version\\\": 1,"                                 \
	"                \\\"publish\\\": {},"                                \
	"                \\\"subscribe\\\": {}"                               \
	"            },"                                                      \
	"            \\\"" TEST_WORKSPACE_C "\\\": {"                         \
	"                \\\"moduleId\\\": "                                  \
	"\\\"" MODULE_READER_ID "\\\","                                       \
	"                \\\"entryPoint\\\": \\\"main\\\","                   \
	"                \\\"version\\\": 1,"                                 \
	"                \\\"publish\\\": {},"                                \
	"                \\\"subscribe\\\": {}"                               \
	"            }"                                                       \
	"        },"                                                          \
	"        \\\"modules\\\": {"                                          \
	"            \\\"" MODULE_WRITER_ID "\\\": {"                         \
	"                \\\"moduleImpl\\\": \\\"wasm\\\","                   \
	"                \\\"downloadUrl\\\": \\\"file://%s\\\","             \
	"                \\\"hash\\\": \\\"" MODULE_HASH_WRITER "\\\""        \
	"            },"                                                      \
	"            \\\"" MODULE_READER_ID "\\\": {"                         \
	"                \\\"moduleImpl\\\": \\\"wasm\\\","                   \
	"                \\\"downloadUrl\\\": \\\"file://%s\\\","             \
	"                \\\"hash\\\": \\\"" MODULE_HASH_READER "\\\""        \
	"            }"                                                       \
	"        },"                                                          \
	"        \\\"publishTopics\\\": {},"                                  \
	"        \\\"subscribeTopics\\\": {}"                                 \
	"}\""

#define EVP1_DEPLOYMENT_MANIFEST_2                                            \
	"\"{ "                                                                \
	"        \\\"deploymentId\\\": "                                      \
	"\\\"" TEST_DEPLOYMENT_ID2 "\\\","                                    \
	"        \\\"instanceSpecs\\\": {"                                    \
	"            \\\"" TEST_WORKSPACE_A "\\\": {"                         \
	"                \\\"moduleId\\\": "                                  \
	"\\\"" MODULE_READER_ID "\\\","                                       \
	"                \\\"entryPoint\\\": \\\"main\\\","                   \
	"                \\\"version\\\": 2,"                                 \
	"                \\\"publish\\\": {},"                                \
	"                \\\"subscribe\\\": {}"                               \
	"            },"                                                      \
	"            \\\"" TEST_WORKSPACE_B "\\\": {"                         \
	"                \\\"moduleId\\\": "                                  \
	"\\\"" MODULE_READER_ID "\\\","                                       \
	"                \\\"entryPoint\\\": \\\"main\\\","                   \
	"                \\\"version\\\": 2,"                                 \
	"                \\\"publish\\\": {},"                                \
	"                \\\"subscribe\\\": {}"                               \
	"            },"                                                      \
	"            \\\"" TEST_WORKSPACE_C "\\\": {"                         \
	"                \\\"moduleId\\\": "                                  \
	"\\\"" MODULE_READER_ID "\\\","                                       \
	"                \\\"entryPoint\\\": \\\"main\\\","                   \
	"                \\\"version\\\": 2,"                                 \
	"                \\\"publish\\\": {},"                                \
	"                \\\"subscribe\\\": {}"                               \
	"            }"                                                       \
	"        },"                                                          \
	"        \\\"modules\\\": {"                                          \
	"            \\\"" MODULE_WRITER_ID "\\\": {"                         \
	"                \\\"moduleImpl\\\": \\\"wasm\\\","                   \
	"                \\\"downloadUrl\\\": \\\"file://%s\\\","             \
	"                \\\"hash\\\": \\\"" MODULE_HASH_WRITER "\\\""        \
	"            },"                                                      \
	"            \\\"" MODULE_READER_ID "\\\": {"                         \
	"                \\\"moduleImpl\\\": \\\"wasm\\\","                   \
	"                \\\"downloadUrl\\\": \\\"file://%s\\\","             \
	"                \\\"hash\\\": \\\"" MODULE_HASH_READER "\\\""        \
	"            }"                                                       \
	"        },"                                                          \
	"        \\\"publishTopics\\\": {},"                                  \
	"        \\\"subscribeTopics\\\": {}"                                 \
	"}\""

#define EVP1_DEPLOYMENT_MANIFEST_3                                            \
	"\"{ "                                                                \
	"        \\\"deploymentId\\\": "                                      \
	"\\\"" TEST_DEPLOYMENT_ID3 "\\\","                                    \
	"        \\\"instanceSpecs\\\": {"                                    \
	"            \\\"" TEST_WORKSPACE_A "-new\\\": {"                     \
	"                \\\"moduleId\\\": "                                  \
	"\\\"" MODULE_READER_ID "\\\","                                       \
	"                \\\"entryPoint\\\": \\\"main\\\","                   \
	"                \\\"version\\\": 2,"                                 \
	"                \\\"publish\\\": {},"                                \
	"                \\\"subscribe\\\": {}"                               \
	"            },"                                                      \
	"            \\\"" TEST_WORKSPACE_B "\\\": {"                         \
	"                \\\"moduleId\\\": "                                  \
	"\\\"" MODULE_READER_ID "\\\","                                       \
	"                \\\"entryPoint\\\": \\\"main\\\","                   \
	"                \\\"version\\\": 2,"                                 \
	"                \\\"publish\\\": {},"                                \
	"                \\\"subscribe\\\": {}"                               \
	"            },"                                                      \
	"            \\\"" TEST_WORKSPACE_C "\\\": {"                         \
	"                \\\"moduleId\\\": "                                  \
	"\\\"" MODULE_READER_ID "\\\","                                       \
	"                \\\"entryPoint\\\": \\\"main\\\","                   \
	"                \\\"version\\\": 2,"                                 \
	"                \\\"publish\\\": {},"                                \
	"                \\\"subscribe\\\": {}"                               \
	"            }"                                                       \
	"        },"                                                          \
	"        \\\"modules\\\": {"                                          \
	"            \\\"" MODULE_WRITER_ID "\\\": {"                         \
	"                \\\"moduleImpl\\\": \\\"wasm\\\","                   \
	"                \\\"downloadUrl\\\": \\\"file://%s\\\","             \
	"                \\\"hash\\\": \\\"" MODULE_HASH_WRITER "\\\""        \
	"            },"                                                      \
	"            \\\"" MODULE_READER_ID "\\\": {"                         \
	"                \\\"moduleImpl\\\": \\\"wasm\\\","                   \
	"                \\\"downloadUrl\\\": \\\"file://%s\\\","             \
	"                \\\"hash\\\": \\\"" MODULE_HASH_READER "\\\""        \
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
	"	\"configuration/" TEST_WORKSPACE_A "/filename\": "            \
	"\"d29ya3NwYWNlLXRlc3QtZmlsZQ==\","                                   \
	"	\"configuration/" TEST_WORKSPACE_A                            \
	"/data\": \"" EVP1_B64_AAAAA "\","                                    \
	"	\"configuration/" TEST_WORKSPACE_B "/filename\": "            \
	"\"d29ya3NwYWNlLXRlc3QtZmlsZQ==\","                                   \
	"	\"configuration/" TEST_WORKSPACE_B "/data\": \"" EVP1_B64_BBB \
	"\","                                                                 \
	"	\"configuration/" TEST_WORKSPACE_C "/filename\": "            \
	"\"d29ya3NwYWNlLXRlc3QtZmlsZQ==\""                                    \
	"}"

#define EVP2_INSTANCE_CONFIG_1                                                \
	"{"                                                                   \
	"	\"configuration/" TEST_WORKSPACE_A "/filename\": "            \
	"\"d29ya3NwYWNlLXRlc3QtZmlsZQ==\","                                   \
	"	\"configuration/" TEST_WORKSPACE_A                            \
	"/data\": \"" EVP2_B64_AAAAA "\","                                    \
	"	\"configuration/" TEST_WORKSPACE_B "/filename\": "            \
	"\"d29ya3NwYWNlLXRlc3QtZmlsZQ==\","                                   \
	"	\"configuration/" TEST_WORKSPACE_B "/data\": \"" EVP2_B64_BBB \
	"\","                                                                 \
	"	\"configuration/" TEST_WORKSPACE_C "/filename\": "            \
	"\"d29ya3NwYWNlLXRlc3QtZmlsZQ==\""                                    \
	"}"

#define EVP2_DEPLOYMENT_MANIFEST_1                                            \
	"{"                                                                   \
	"        \"deploymentId\": \"" TEST_DEPLOYMENT_ID1 "\","              \
	"        \"instanceSpecs\": {"                                        \
	"            \"" TEST_WORKSPACE_A "\": {"                             \
	"                \"moduleId\": "                                      \
	"\"" MODULE_WRITER_ID "\","                                           \
	"                \"publish\": {},"                                    \
	"                \"subscribe\": {}"                                   \
	"            },"                                                      \
	"            \"" TEST_WORKSPACE_B "\": {"                             \
	"                \"moduleId\": "                                      \
	"\"" MODULE_WRITER_ID "\","                                           \
	"                \"publish\": {},"                                    \
	"                \"subscribe\": {}"                                   \
	"            },"                                                      \
	"            \"" TEST_WORKSPACE_C "\": {"                             \
	"                \"moduleId\": "                                      \
	"\"" MODULE_READER_ID "\","                                           \
	"                \"publish\": {},"                                    \
	"                \"subscribe\": {}"                                   \
	"            }"                                                       \
	"        },"                                                          \
	"        \"modules\": {"                                              \
	"            \"" MODULE_WRITER_ID "\": {"                             \
	"                \"entryPoint\": \"main\","                           \
	"                \"moduleImpl\": \"wasm\","                           \
	"                \"downloadUrl\": "                                   \
	"\"file://%s\","                                                      \
	"                \"hash\": "                                          \
	"\"" MODULE_HASH_WRITER ""                                            \
	"\""                                                                  \
	"            },"                                                      \
	"            \"" MODULE_READER_ID "\": {"                             \
	"                \"entryPoint\": \"main\","                           \
	"                \"moduleImpl\": \"wasm\","                           \
	"                \"downloadUrl\": "                                   \
	"\"file://%s\","                                                      \
	"                \"hash\": "                                          \
	"\"" MODULE_HASH_READER ""                                            \
	"\""                                                                  \
	"            }"                                                       \
	"        },"                                                          \
	"        \"publishTopics\": {},"                                      \
	"        \"subscribeTopics\": {}"                                     \
	"}"

#define EVP2_DEPLOYMENT_MANIFEST_2                                            \
	"{"                                                                   \
	"        \"deploymentId\": \"" TEST_DEPLOYMENT_ID2 "\","              \
	"        \"instanceSpecs\": {"                                        \
	"            \"" TEST_WORKSPACE_A "\": {"                             \
	"                \"moduleId\": "                                      \
	"\"" MODULE_READER_ID "\","                                           \
	"                \"publish\": {},"                                    \
	"                \"subscribe\": {}"                                   \
	"            },"                                                      \
	"            \"" TEST_WORKSPACE_B "\": {"                             \
	"                \"moduleId\": "                                      \
	"\"" MODULE_READER_ID "\","                                           \
	"                \"publish\": {},"                                    \
	"                \"subscribe\": {}"                                   \
	"            },"                                                      \
	"            \"" TEST_WORKSPACE_C "\": {"                             \
	"                \"moduleId\": "                                      \
	"\"" MODULE_READER_ID "\","                                           \
	"                \"publish\": {},"                                    \
	"                \"subscribe\": {}"                                   \
	"            }"                                                       \
	"        },"                                                          \
	"        \"modules\": {"                                              \
	"            \"" MODULE_WRITER_ID "\": {"                             \
	"                \"entryPoint\": \"main\","                           \
	"                \"moduleImpl\": \"wasm\","                           \
	"                \"downloadUrl\": "                                   \
	"\"file://%s\","                                                      \
	"                \"hash\": "                                          \
	"\"" MODULE_HASH_WRITER ""                                            \
	"\""                                                                  \
	"            },"                                                      \
	"            \"" MODULE_READER_ID "\": {"                             \
	"                \"entryPoint\": \"main\","                           \
	"                \"moduleImpl\": \"wasm\","                           \
	"                \"downloadUrl\": "                                   \
	"\"file://%s\","                                                      \
	"                \"hash\": "                                          \
	"\"" MODULE_HASH_READER ""                                            \
	"\""                                                                  \
	"            }"                                                       \
	"        },"                                                          \
	"        \"publishTopics\": {},"                                      \
	"        \"subscribeTopics\": {}"                                     \
	"}"

#define EVP2_DEPLOYMENT_MANIFEST_3                                            \
	"{"                                                                   \
	"        \"deploymentId\": \"" TEST_DEPLOYMENT_ID3 "\","              \
	"        \"instanceSpecs\": {"                                        \
	"            \"" TEST_WORKSPACE_A "-new\": {"                         \
	"                \"moduleId\": "                                      \
	"\"" MODULE_READER_ID "\","                                           \
	"                \"publish\": {},"                                    \
	"                \"subscribe\": {}"                                   \
	"            },"                                                      \
	"            \"" TEST_WORKSPACE_B "\": {"                             \
	"                \"moduleId\": "                                      \
	"\"" MODULE_READER_ID "\","                                           \
	"                \"publish\": {},"                                    \
	"                \"subscribe\": {}"                                   \
	"            },"                                                      \
	"            \"" TEST_WORKSPACE_C "\": {"                             \
	"                \"moduleId\": "                                      \
	"\"" MODULE_READER_ID "\","                                           \
	"                \"publish\": {},"                                    \
	"                \"subscribe\": {}"                                   \
	"            }"                                                       \
	"        },"                                                          \
	"        \"modules\": {"                                              \
	"            \"" MODULE_WRITER_ID "\": {"                             \
	"                \"entryPoint\": \"main\","                           \
	"                \"moduleImpl\": \"wasm\","                           \
	"                \"downloadUrl\": "                                   \
	"\"file://%s\","                                                      \
	"                \"hash\": "                                          \
	"\"" MODULE_HASH_WRITER ""                                            \
	"\""                                                                  \
	"            },"                                                      \
	"            \"" MODULE_READER_ID "\": {"                             \
	"                \"entryPoint\": \"main\","                           \
	"                \"moduleImpl\": \"wasm\","                           \
	"                \"downloadUrl\": "                                   \
	"\"file://%s\","                                                      \
	"                \"hash\": "                                          \
	"\"" MODULE_HASH_READER ""                                            \
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

#define EVP1_B64_G_STEP_0    B64_G_STEP_0
#define EVP1_B64_G_STEP_3    B64_G_STEP_3
#define EVP1_B64_G_STEP_1000 B64_G_STEP_1000
#define EVP1_B64_ENOENT      B64_ENOENT
#define EVP1_B64_AAAAA       B64_AAAAA
#define EVP1_B64_BBB         B64_BBB

#define EVP2_B64_G_STEP_0    "g_step = 0"
#define EVP2_B64_G_STEP_3    "g_step = 3"
#define EVP2_B64_G_STEP_1000 "g_step = 1000"
#define EVP2_B64_ENOENT      "ENOENT"
#define EVP2_B64_AAAAA       "AAAAA"
#define EVP2_B64_BBB         "BBB"

void
test_wasm_mod_workspace(void **state)
{
	const char *step0 = agent_get_payload(B64_G_STEP_0_1);
	const char *step3 = agent_get_payload(B64_G_STEP_3_1);
	const char *step1000 = agent_get_payload(B64_G_STEP_1000_1);
	const char *enoent = agent_get_payload(B64_ENOENT_1);
	const char *bbb = agent_get_payload(B64_BBB_1);
	const char *aaaaa = agent_get_payload(B64_AAAAA_1);

	// start agent
	struct evp_agent_context *ctxt = agent_test_start();
	struct agent_deployment d = {.ctxt = ctxt};

	// Deploy an empty DeploymentManifest, which is a manifest with no
	// module instances or modules.

	// Apply an empty DeploymentManifest
	agent_ensure_deployment(&d,
				agent_get_payload(EMPTY_DEPLOYMENT_MANIFEST_1),
				TEST_EMPTY_DEPLOYMENT_ID1);

	// Launch three module instances.
	// Two writers and one reader.
	// As they are new module instances, their workspaces are all empty.
	agent_send_deployment(ctxt, agent_get_payload(DEPLOYMENT_MANIFEST_1));

	// wait for deployment
	// Check for all module instance status ok
	// Wait the OK status for the modules
	// reader-wasm writer-wasm
	if (EVP_HUB_TYPE_EVP1_TB == agent_test_get_hub_type()) {
		agent_poll(verify_json,
			   "deploymentStatus=#{modules." MODULE_WRITER_ID
			   ".status=%s,"
			   "modules." MODULE_READER_ID ".status=%s,"
			   "instances." TEST_WORKSPACE_A ".status=%s,"
			   "instances." TEST_WORKSPACE_B ".status=%s,"
			   "instances." TEST_WORKSPACE_C ".status=%s,"
			   "deploymentId=%s}",
			   "ok", "ok", "ok", "ok", "ok", TEST_DEPLOYMENT_ID1);
	} else if (EVP_HUB_TYPE_EVP2_TB == agent_test_get_hub_type()) {
		agent_poll(verify_json,
			   "deploymentStatus.modules." MODULE_WRITER_ID
			   ".status=%s,"
			   "deploymentStatus.modules." MODULE_READER_ID
			   ".status=%s,"
			   "deploymentStatus.instances." TEST_WORKSPACE_A
			   ".status=%s,"
			   "deploymentStatus.instances." TEST_WORKSPACE_B
			   ".status=%s,"
			   "deploymentStatus.instances." TEST_WORKSPACE_C
			   ".status=%s,"
			   "deploymentStatus.deploymentId=%s",
			   "ok", "ok", "ok", "ok", "ok", TEST_DEPLOYMENT_ID1);
	} else {
		agent_poll(verify_json,
			   "currentDeployment.modules." MODULE_WRITER_ID
			   ".status=%s,"
			   "currentDeployment.modules." MODULE_READER_ID
			   ".status=%s,"
			   "currentDeployment.instances." TEST_WORKSPACE_A
			   ".status=%s,"
			   "currentDeployment.instances." TEST_WORKSPACE_B
			   ".status=%s,"
			   "currentDeployment.instances." TEST_WORKSPACE_C
			   ".status=%s,"
			   "currentDeployment.deploymentId=%s",
			   "ok", "ok", "ok", "ok", "ok", TEST_DEPLOYMENT_ID1);
	}

	// Wait the OK status for the instances
	// workspace-test-A workspace-test-B workspace-test-C
	agent_poll(verify_json,
		   "state/" TEST_WORKSPACE_A "/status=%s,"
		   "state/" TEST_WORKSPACE_B "/status=%s,"
		   "state/" TEST_WORKSPACE_C "/status=%s",
		   step0, step0, step0);

	// Tell two writers to write data to a file.
	// Give them the same filename but different data to ensure
	// they don't share a single workspace. Tell the reader to
	// read the file It's expected to fail with ENOENT
	agent_send_instance_config(ctxt, agent_get_payload(INSTANCE_CONFIG_1));

	// wait for the three module done
	// The module instance workspace-test-C should get ENOENT
	// because the workspace is empty.
	agent_poll(verify_json,
		   "state/" TEST_WORKSPACE_A "/status=%s,"
		   "state/" TEST_WORKSPACE_B "/status=%s,"
		   "state/" TEST_WORKSPACE_C "/status=%s,"
		   "state/" TEST_WORKSPACE_C "/data=%s",
		   step1000, step1000, step3, enoent);

	// Turn all three module instances to readers.
	// This should preserve their workspaces.
	agent_send_deployment(ctxt, agent_get_payload(DEPLOYMENT_MANIFEST_2));

	// check for all module instance status ok
	// wait for deployment
	// Wait the OK status for the modules
	// reader-wasm writer-wasm
	if (EVP_HUB_TYPE_EVP1_TB == agent_test_get_hub_type()) {
		agent_poll(verify_json,
			   "deploymentStatus=#{"
			   "modules." MODULE_WRITER_ID ".status=%s,"
			   "modules." MODULE_READER_ID ".status=%s,"
			   "instances." TEST_WORKSPACE_A ".status=%s,"
			   "instances." TEST_WORKSPACE_B ".status=%s,"
			   "instances." TEST_WORKSPACE_C ".status=%s,"
			   "deploymentId=%s}",
			   "ok", "ok", "ok", "ok", "ok", TEST_DEPLOYMENT_ID2);
	} else if (EVP_HUB_TYPE_EVP2_TB == agent_test_get_hub_type()) {
		agent_poll(verify_json,
			   "deploymentStatus.modules." MODULE_WRITER_ID
			   ".status=%s,"
			   "deploymentStatus.modules." MODULE_READER_ID
			   ".status=%s,"
			   "deploymentStatus.instances." TEST_WORKSPACE_A
			   ".status=%s,"
			   "deploymentStatus.instances." TEST_WORKSPACE_B
			   ".status=%s,"
			   "deploymentStatus.instances." TEST_WORKSPACE_C
			   ".status=%s,"
			   "deploymentStatus.deploymentId=%s",
			   "ok", "ok", "ok", "ok", "ok", TEST_DEPLOYMENT_ID2);
	} else {
		agent_poll(verify_json,
			   "currentDeployment.modules." MODULE_WRITER_ID
			   ".status=%s,"
			   "currentDeployment.modules." MODULE_READER_ID
			   ".status=%s,"
			   "currentDeployment.instances." TEST_WORKSPACE_A
			   ".status=%s,"
			   "currentDeployment.instances." TEST_WORKSPACE_B
			   ".status=%s,"
			   "currentDeployment.instances." TEST_WORKSPACE_C
			   ".status=%s,"
			   "currentDeployment.deploymentId=%s",
			   "ok", "ok", "ok", "ok", "ok", TEST_DEPLOYMENT_ID2);
	}

	// Updating module instances should preserve their
	// workspaces.

	// Two of them, who were writers in the previous version of
	// the deployment, should see the file they wrote out when
	// they were writers.

	// Wait the OK status for the instances
	// workspace-test-A workspace-test-B workspace-test-C
	agent_poll(verify_json,
		   "state/" TEST_WORKSPACE_A "/status=%s,"
		   "state/" TEST_WORKSPACE_B "/status=%s,"
		   "state/" TEST_WORKSPACE_C "/status=%s,"
		   "state/" TEST_WORKSPACE_A "/data=%s,"
		   "state/" TEST_WORKSPACE_B "/data=%s,"
		   "state/" TEST_WORKSPACE_C "/data=%s",
		   step1000, step1000, step1000, aaaaa, bbb, enoent);

	// Change the name of one of module instances.
	// The name is the identity of the module instance.
	// If it changed, it is not longer the same module instance.
	// Thus, it effectively removes its workspace.
	agent_send_deployment(ctxt, agent_get_payload(DEPLOYMENT_MANIFEST_3));

	// wait for deployment
	// check for all module instance status ok
	// agent_poll(verify_contains, TEST_DEPLOYMENT_ID3);
	// Wait the OK status for the modules
	// reader-wasm writer-wasm
	if (EVP_HUB_TYPE_EVP1_TB == agent_test_get_hub_type()) {
		agent_poll(verify_json,
			   "deploymentStatus=#{"
			   "modules." MODULE_WRITER_ID ".status=%s,"
			   "modules." MODULE_READER_ID ".status=%s,"
			   "instances." TEST_WORKSPACE_A "-new.status=%s,"
			   "instances." TEST_WORKSPACE_B ".status=%s,"
			   "instances." TEST_WORKSPACE_C ".status=%s,"
			   "deploymentId=%s}",
			   "ok", "ok", "ok", "ok", "ok", TEST_DEPLOYMENT_ID3);
	} else if (EVP_HUB_TYPE_EVP2_TB == agent_test_get_hub_type()) {
		agent_poll(verify_json,
			   "deploymentStatus.modules." MODULE_WRITER_ID
			   ".status=%s,"
			   "deploymentStatus.modules." MODULE_READER_ID
			   ".status=%s,"
			   "deploymentStatus.instances." TEST_WORKSPACE_A
			   "-new.status=%s,"
			   "deploymentStatus.instances." TEST_WORKSPACE_B
			   ".status=%s,"
			   "deploymentStatus.instances." TEST_WORKSPACE_C
			   ".status=%s,"
			   "deploymentStatus.deploymentId=%s",
			   "ok", "ok", "ok", "ok", "ok", TEST_DEPLOYMENT_ID3);
	} else {
		agent_poll(verify_json,
			   "currentDeployment.modules." MODULE_WRITER_ID
			   ".status=%s,"
			   "currentDeployment.modules." MODULE_READER_ID
			   ".status=%s,"
			   "currentDeployment.instances." TEST_WORKSPACE_A
			   "-new.status=%s,"
			   "currentDeployment.instances." TEST_WORKSPACE_B
			   ".status=%s,"
			   "currentDeployment.instances." TEST_WORKSPACE_C
			   ".status=%s,"
			   "currentDeployment.deploymentId=%s",
			   "ok", "ok", "ok", "ok", "ok", TEST_DEPLOYMENT_ID3);
	}

	// Rename the module instance back to its original name.
	// It should not restore its workspace.
	agent_send_deployment(ctxt, agent_get_payload(DEPLOYMENT_MANIFEST_2));

	// check for all module instance status ok
	// wait for deployment
	// Wait the OK status for the modules
	// reader-wasm writer-wasm
	if (EVP_HUB_TYPE_EVP1_TB == agent_test_get_hub_type()) {
		agent_poll(verify_json,
			   "deploymentStatus=#{"
			   "modules." MODULE_WRITER_ID ".status=%s,"
			   "modules." MODULE_READER_ID ".status=%s,"
			   "instances." TEST_WORKSPACE_A ".status=%s,"
			   "instances." TEST_WORKSPACE_B ".status=%s,"
			   "instances." TEST_WORKSPACE_C ".status=%s,"
			   "deploymentId=%s}",
			   "ok", "ok", "ok", "ok", "ok", TEST_DEPLOYMENT_ID2);
	} else if (EVP_HUB_TYPE_EVP2_TB == agent_test_get_hub_type()) {
		agent_poll(verify_json,
			   "deploymentStatus.modules." MODULE_WRITER_ID
			   ".status=%s,"
			   "deploymentStatus.modules." MODULE_READER_ID
			   ".status=%s,"
			   "deploymentStatus.instances." TEST_WORKSPACE_A
			   ".status=%s,"
			   "deploymentStatus.instances." TEST_WORKSPACE_B
			   ".status=%s,"
			   "deploymentStatus.instances." TEST_WORKSPACE_C
			   ".status=%s,"
			   "deploymentStatus.deploymentId=%s",
			   "ok", "ok", "ok", "ok", "ok", TEST_DEPLOYMENT_ID2);
	} else {
		agent_poll(verify_json,
			   "currentDeployment.modules." MODULE_WRITER_ID
			   ".status=%s,"
			   "currentDeployment.modules." MODULE_READER_ID
			   ".status=%s,"
			   "currentDeployment.instances." TEST_WORKSPACE_A
			   ".status=%s,"
			   "currentDeployment.instances." TEST_WORKSPACE_B
			   ".status=%s,"
			   "currentDeployment.instances." TEST_WORKSPACE_C
			   ".status=%s,"
			   "currentDeployment.deploymentId=%s",
			   "ok", "ok", "ok", "ok", "ok", TEST_DEPLOYMENT_ID2);
	}

	// Wait the OK status for the instances
	// workspace-test-A workspace-test-B workspace-test-C
	agent_poll(verify_json,
		   "state/" TEST_WORKSPACE_A "/status=%s,"
		   "state/" TEST_WORKSPACE_B "/status=%s,"
		   "state/" TEST_WORKSPACE_C "/status=%s,"
		   "state/" TEST_WORKSPACE_A "/data=%s,"
		   "state/" TEST_WORKSPACE_B "/data=%s,"
		   "state/" TEST_WORKSPACE_C "/data=%s",
		   step1000, step1000, step1000, enoent, bbb, enoent);

	agent_ensure_deployment(&d,
				agent_get_payload(EMPTY_DEPLOYMENT_MANIFEST_1),
				TEST_EMPTY_DEPLOYMENT_ID1);
}

static char *deployment_evp1_1;
static char *deployment_evp1_2;
static char *deployment_evp1_3;
static char *deployment_evp2_1;
static char *deployment_evp2_2;
static char *deployment_evp2_3;

static int
teardown(void **state)
{
	agent_test_exit();
	free(deployment_evp1_1);
	free(deployment_evp1_2);
	free(deployment_evp1_3);
	free(deployment_evp2_1);
	free(deployment_evp2_2);
	free(deployment_evp2_3);
	return 0;
}

static int
setup(void **state)
{
	agent_test_setup();

	char *path_writer = MODULE_PATH_WRITER;
	char *abspath_writer;
	if (*path_writer != '/') {
		abspath_writer = realpath(path_writer, NULL);
	} else {
		abspath_writer = xstrdup(path_writer);
	}

	char *path_reader = MODULE_PATH_READER;
	char *abspath_reader;
	if (*path_reader != '/') {
		abspath_reader = realpath(path_reader, NULL);
	} else {
		abspath_reader = xstrdup(path_reader);
	}

	xasprintf(&deployment_evp1_1, EVP1_DEPLOYMENT_MANIFEST_1,
		  MODULE_PATH_WRITER, MODULE_PATH_READER);
	xasprintf(&deployment_evp1_2, EVP1_DEPLOYMENT_MANIFEST_2,
		  MODULE_PATH_WRITER, MODULE_PATH_READER);
	xasprintf(&deployment_evp1_3, EVP1_DEPLOYMENT_MANIFEST_3,
		  MODULE_PATH_WRITER, MODULE_PATH_READER);

	xasprintf(&deployment_evp2_1, EVP2_DEPLOYMENT_MANIFEST_1,
		  MODULE_PATH_WRITER, MODULE_PATH_READER);
	xasprintf(&deployment_evp2_2, EVP2_DEPLOYMENT_MANIFEST_2,
		  MODULE_PATH_WRITER, MODULE_PATH_READER);
	xasprintf(&deployment_evp2_3, EVP2_DEPLOYMENT_MANIFEST_3,
		  MODULE_PATH_WRITER, MODULE_PATH_READER);

	free(abspath_writer);
	free(abspath_reader);

	// evp1
	agent_register_payload(EMPTY_DEPLOYMENT_MANIFEST_1,
			       EVP_HUB_TYPE_EVP1_TB,
			       EVP1_EMPTY_DEPLOYMENT_MANIFEST_1);
	agent_register_payload(DEPLOYMENT_MANIFEST_1, EVP_HUB_TYPE_EVP1_TB,
			       deployment_evp1_1);
	agent_register_payload(DEPLOYMENT_MANIFEST_2, EVP_HUB_TYPE_EVP1_TB,
			       deployment_evp1_2);
	agent_register_payload(DEPLOYMENT_MANIFEST_3, EVP_HUB_TYPE_EVP1_TB,
			       deployment_evp1_3);
	agent_register_payload(INSTANCE_CONFIG_1, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_INSTANCE_CONFIG_1);
	agent_register_payload(B64_G_STEP_0_1, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_B64_G_STEP_0);
	agent_register_payload(B64_G_STEP_3_1, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_B64_G_STEP_3);
	agent_register_payload(B64_G_STEP_1000_1, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_B64_G_STEP_1000);
	agent_register_payload(B64_ENOENT_1, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_B64_ENOENT);
	agent_register_payload(B64_AAAAA_1, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_B64_AAAAA);
	agent_register_payload(B64_BBB_1, EVP_HUB_TYPE_EVP1_TB, EVP1_B64_BBB);

	// evp2-tb
	agent_register_payload(EMPTY_DEPLOYMENT_MANIFEST_1,
			       EVP_HUB_TYPE_EVP2_TB,
			       EVP2_EMPTY_DEPLOYMENT_MANIFEST_1);
	agent_register_payload(DEPLOYMENT_MANIFEST_1, EVP_HUB_TYPE_EVP2_TB,
			       deployment_evp2_1);
	agent_register_payload(DEPLOYMENT_MANIFEST_2, EVP_HUB_TYPE_EVP2_TB,
			       deployment_evp2_2);
	agent_register_payload(DEPLOYMENT_MANIFEST_3, EVP_HUB_TYPE_EVP2_TB,
			       deployment_evp2_3);
	agent_register_payload(INSTANCE_CONFIG_1, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_INSTANCE_CONFIG_1);
	agent_register_payload(B64_G_STEP_0_1, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_B64_G_STEP_0);
	agent_register_payload(B64_G_STEP_3_1, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_B64_G_STEP_3);
	agent_register_payload(B64_G_STEP_1000_1, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_B64_G_STEP_1000);
	agent_register_payload(B64_ENOENT_1, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_B64_ENOENT);
	agent_register_payload(B64_AAAAA_1, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_B64_AAAAA);
	agent_register_payload(B64_BBB_1, EVP_HUB_TYPE_EVP2_TB, EVP2_B64_BBB);

	return 0;
}

int
main(void)
{
	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_wasm_mod_workspace),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup, teardown);
}
