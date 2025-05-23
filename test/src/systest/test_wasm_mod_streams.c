/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <evp/sdk.h>
#include <parson.h>

#include <internal/util.h>

#include "agent_test.h"
#include "hub.h"
#include "module_instance.h"
#include "mqtt_custom.h"
#include "notification.h"
#include "sdk_agent.h"
#include "sdk_impl.h"
#include "stream/stream.h"

enum test_wasm_config_echo_payloads {
	DEPLOYMENT_MANIFEST_1,
	DEPLOYMENT_MANIFEST_2,
	EMPTY_DEPLOYMENT_MANIFEST_1,
	INSTANCE_CONFIG_1
};

#define TEST_EMPTY_DEPLOYMENT_ID "d2862453-f57e-4ddb-90d2-d470c27f6a92"
#define TEST_DEPLOYMENT_ID1      "f5cb7e2d-4e23-4bc3-bd48-845945de3456"
#define TEST_DEPLOYMENT_ID2      "79e98832-23c7-4733-b656-b49a24e33c89"

#define READER_INSTANCE_ID "1fddfca9-0607-40f6-8e87-661d9f366424"
#define READER_MODULE_ID   "0329dea0-bd16-4e8a-be29-cd415c1a10ff"
#define READER_MODULE_PATH "../test_modules/stream_reader.wasm"
#define READER_MODULE_HASH                                                    \
	"f0464cf80c305261400ebc744571d6cff6968907cc53b24529c1ababfd7aabeb"

#define WRITER_INSTANCE_ID "bc7b3156-5651-4efe-8743-ca763e0f2b15"
#define WRITER_MODULE_ID   "a2f149eb-3c53-4d02-88af-d0838aa12dcb"
#define WRITER_MODULE_PATH "../test_modules/stream_writer.wasm"
#define WRITER_MODULE_HASH                                                    \
	"5b02344d79409668d1da54d50e852380faf98728facbedb0140bb176fe4bdd56"

#define EVP2_DEPLOYMENT_MANIFEST_1                                            \
	"{"                                                                   \
	"    \"deploymentId\": \"" TEST_DEPLOYMENT_ID1 "\","                  \
	"    \"instanceSpecs\": {"                                            \
	"        \"" READER_INSTANCE_ID "\": {"                               \
	"            \"moduleId\": \"" READER_MODULE_ID "\","                 \
	"            \"publish\": {},"                                        \
	"            \"streams\": {"                                          \
	"                \"in-video-stream\": {"                              \
	"                    \"direction\": \"in\","                          \
	"                    \"parameters\": {"                               \
	"                        "                                            \
	"\"hostname\": \"127.0.0.1\","                                        \
	"\"port\": \"0\","                                                    \
	"\"domain\": \"IPv4\","                                               \
	"\"type\": \"tcp\""                                                   \
	"                    },"                                              \
	"                    \"type\": \"posix\""                             \
	"                }"                                                   \
	"            },"                                                      \
	"            \"subscribe\": {}"                                       \
	"        }"                                                           \
	"    },"                                                              \
	"    \"modules\": {"                                                  \
	"        \"" READER_MODULE_ID "\": {"                                 \
	"            \"downloadUrl\": \"file://" READER_MODULE_PATH "\","     \
	"            \"entryPoint\": \"main\","                               \
	"            \"hash\": \"" READER_MODULE_HASH "\","                   \
	"            \"moduleImpl\": \"wasm\""                                \
	"        }"                                                           \
	"    },"                                                              \
	"    \"publishTopics\": {},"                                          \
	"    \"subscribeTopics\": {}"                                         \
	"}"

#define EVP2_DEPLOYMENT_MANIFEST_2                                            \
	"{"                                                                   \
	"    \"deploymentId\": \"" TEST_DEPLOYMENT_ID2 "\","                  \
	"    \"instanceSpecs\": {"                                            \
	"        \"" READER_INSTANCE_ID "\": {"                               \
	"            \"moduleId\": \"" READER_MODULE_ID "\","                 \
	"            \"publish\": {},"                                        \
	"            \"streams\": {"                                          \
	"                \"in-video-stream\": {"                              \
	"                    \"direction\": \"in\","                          \
	"                    \"parameters\": {"                               \
	"                        "                                            \
	"\"hostname\": \"127.0.0.1\","                                        \
	"\"port\": \"0\","                                                    \
	"\"domain\": \"IPv4\","                                               \
	"\"type\": \"tcp\""                                                   \
	"                    },"                                              \
	"                    \"type\": \"posix\""                             \
	"                }"                                                   \
	"            },"                                                      \
	"            \"subscribe\": {}"                                       \
	"        },"                                                          \
	"        \"" WRITER_INSTANCE_ID "\": {"                               \
	"            \"moduleId\": \"" WRITER_MODULE_ID "\","                 \
	"            \"publish\": {},"                                        \
	"            \"streams\": {"                                          \
	"                \"out-video-stream\": {"                             \
	"                    \"direction\": \"out\","                         \
	"                    \"parameters\": {"                               \
	"                        "                                            \
	"\"hostname\": \"127.0.0.1\","                                        \
	"\"port\": \"%hu\","                                                  \
	"\"domain\": \"IPv4\","                                               \
	"\"type\": \"tcp\""                                                   \
	"                    },"                                              \
	"                    \"type\": \"posix\""                             \
	"                }"                                                   \
	"            },"                                                      \
	"            \"subscribe\": {}"                                       \
	"        }"                                                           \
	"    },"                                                              \
	"    \"modules\": {"                                                  \
	"        \"" READER_MODULE_ID "\": {"                                 \
	"            \"downloadUrl\": \"file://" READER_MODULE_PATH "\","     \
	"            \"entryPoint\": \"main\","                               \
	"            \"hash\": \"" READER_MODULE_HASH "\","                   \
	"            \"moduleImpl\": \"wasm\""                                \
	"        },"                                                          \
	"        \"" WRITER_MODULE_ID "\": {"                                 \
	"            \"downloadUrl\": \"file://" WRITER_MODULE_PATH "\","     \
	"            \"entryPoint\": \"main\","                               \
	"            \"hash\": \"" WRITER_MODULE_HASH "\","                   \
	"            \"moduleImpl\": \"wasm\""                                \
	"        }"                                                           \
	"    },"                                                              \
	"    \"publishTopics\": {},"                                          \
	"    \"subscribeTopics\": {}"                                         \
	"}"

#define EVP2_EMPTY_DEPLOYMENT_MANIFEST_1                                      \
	"{"                                                                   \
	"        \"deploymentId\": \"" TEST_EMPTY_DEPLOYMENT_ID "\","         \
	"        \"instanceSpecs\": {},"                                      \
	"        \"modules\": {},"                                            \
	"        \"publishTopics\": {},"                                      \
	"        \"subscribeTopics\": {}"                                     \
	"}"

static int
on_port(const void *args, void *user)
{
	*(struct stream_port *)user = *(const struct stream_port *)args;
	return 0;
}

static void
send_deployment(struct evp_agent_context *ctxt, const char *payload)
{
	static bool init;

	if (!init) {
		agent_send_initial(ctxt, payload, NULL, NULL);
		init = true;
	} else {
		agent_send_deployment(ctxt, payload);
	}
}

static char *evp2_deployment;

static void
test_wasm_mod_streams_posix(void **state)
{
	struct evp_agent_context *ctxt = *state;
	const char *iot = getenv("EVP_IOT_PLATFORM");
	assert_non_null(iot);

	if (!strcmp(iot, "EVP1")) {
		skip();
	}

	struct stream_port p;
	struct notification_entry *e;
	struct notification *n = stream_notification();

	assert_non_null(n);
	assert_int_equal(
		notification_subscribe(n, "init/port", on_port, &p, &e), 0);

	send_deployment(ctxt, agent_get_payload(DEPLOYMENT_MANIFEST_1));

	agent_poll(verify_json,
		   "deploymentStatus.deploymentId=%s,"
		   "deploymentStatus.reconcileStatus=%s",
		   TEST_DEPLOYMENT_ID1, "ok");

	sdk_lock();
	struct EVP_client *h = sdk_handle_from_name(READER_INSTANCE_ID);
	sdk_unlock();

	assert_non_null(h);

	struct stream_impl *si = stream_from_name(h, "in-video-stream");

	assert_non_null(si);
	assert_ptr_equal(si, p.si);

	xasprintf(&evp2_deployment, EVP2_DEPLOYMENT_MANIFEST_2, p.port);

	agent_register_payload(DEPLOYMENT_MANIFEST_2, EVP_HUB_TYPE_EVP2_TB,
			       evp2_deployment);

	agent_send_deployment(ctxt, agent_get_payload(DEPLOYMENT_MANIFEST_2));

	agent_poll(verify_json,
		   "deploymentStatus.deploymentId=%s,"
		   "deploymentStatus.reconcileStatus=%s",
		   TEST_DEPLOYMENT_ID2, "ok");

	agent_poll(verify_contains, "stream-read-ok");
	assert_int_equal(notification_unsubscribe(n, e), 0);

	// send empty deployment
	send_deployment(ctxt, agent_get_payload(EMPTY_DEPLOYMENT_MANIFEST_1));

	agent_poll(verify_json,
		   "deploymentStatus.deploymentId=%s,"
		   "deploymentStatus.reconcileStatus=%s",
		   TEST_EMPTY_DEPLOYMENT_ID, "ok");
}

static int
teardown(void **state)
{
	// wait for agent to finish
	agent_test_exit();

	free(evp2_deployment);
	return 0;
}

static int
setup(void **state)
{
	agent_test_setup();

	struct evp_agent_context *ctxt = agent_test_start();

	if (ctxt == NULL) {
		fprintf(stderr, "%s: agent_test_start failed\n", __func__);
		return -1;
	}

	*state = ctxt;

	agent_register_payload(EMPTY_DEPLOYMENT_MANIFEST_1,
			       EVP_HUB_TYPE_EVP2_TB,
			       EVP2_EMPTY_DEPLOYMENT_MANIFEST_1);

	const char *iot = getenv("EVP_IOT_PLATFORM");

	if (!iot) {
		fprintf(stderr, "%s: unexpected null EVP_IOT_PLATFORM\n",
			__func__);
		return -1;
	}

	if (!strcmp(iot, "EVP1")) {
		return 0;
	}

	agent_register_payload(DEPLOYMENT_MANIFEST_1, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_DEPLOYMENT_MANIFEST_1);
	return 0;
}

int
main(void)
{
	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_wasm_mod_streams_posix),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup, teardown);
}
