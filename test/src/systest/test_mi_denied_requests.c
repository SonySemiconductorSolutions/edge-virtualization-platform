/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <config.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <evp/sdk.h>
#include <parson.h>

#include <internal/util.h>

#include "../sync.h"
#include "agent_test.h"
#include "global.h"
#include "hub.h"
#include "module_instance.h"
#include "mqtt_custom.h"
#include "req.h"
#include "sdk_agent.h"
#include "testlog.h"

struct test_context {
	struct EVP_client *h;
	struct evp_agent_context *agent;
};

enum test_payloads { DEPLOYMENT_MANIFEST_1 };
static struct sync_ctxt sdk_collect_telemetry_sync;
static struct sync_ctxt sdk_complete_collect_telemetry_sync;

#define LOG_INFO "[   INFO   ] "

#define REPORT_STATUS_INTERVAL_MIN 3
#define REPORT_STATUS_INTERVAL_MAX 5

#define TEST_DEPLOYMENT_ID1 "2dc1a1c3-531b-4693-abba-a4a039bb827d"
#define TEST_INSTANCE_ID1   "07fe77d5-7117-4326-9042-47fda5dd9bf5"
#define DEVICE_ID           "10001"
#define MODULE_ID           "b91fe3e8-df6d-41b7-90cb-72f8b92bdf5e"
#define MODULE_NAME         "backdoor-mdc"

#define EVP1_DEPLOYMENT_MANIFEST_1                                            \
	"\"{ "                                                                \
	"        \\\"deploymentId\\\": \\\"" TEST_DEPLOYMENT_ID1 "\\\","      \
	"        \\\"instanceSpecs\\\": {"                                    \
	"            \\\"" TEST_INSTANCE_ID1 "\\\": {"                        \
	"                \\\"moduleId\\\": \\\"" MODULE_ID "\\\","            \
	"                \\\"entryPoint\\\": \\\"" MODULE_NAME "\\\","        \
	"                \\\"version\\\": 1,"                                 \
	"                \\\"publish\\\": {},"                                \
	"                \\\"subscribe\\\": {}"                               \
	"            }"                                                       \
	"        },"                                                          \
	"        \\\"modules\\\": {"                                          \
	"            \\\"" MODULE_ID "\\\": {"                                \
	"                \\\"moduleImpl\\\": \\\"spawn\\\","                  \
	"                \\\"downloadUrl\\\": \\\"\\\","                      \
	"                \\\"hash\\\": \\\"\\\""                              \
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
	"                \"moduleId\": \"" MODULE_ID "\","                    \
	"                \"publish\": {},"                                    \
	"                \"subscribe\": {}"                                   \
	"            }"                                                       \
	"        },"                                                          \
	"        \"modules\": {"                                              \
	"            \"" MODULE_ID "\": {"                                    \
	"                \"entryPoint\": \"" MODULE_NAME "\","                \
	"                \"moduleImpl\": \"spawn\","                          \
	"                \"downloadUrl\": \"\","                              \
	"                \"hash\": \"\""                                      \
	"            }"                                                       \
	"        },"                                                          \
	"        \"publishTopics\": {},"                                      \
	"        \"subscribeTopics\": {}"                                     \
	"}"

#define LOREM_IPSUM                                                           \
	"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do "    \
	"eiusmod tempor incididunt ut labore et dolore magna aliqua. Ipsum "  \
	"dolor sit amet consectetur adipiscing elit ut aliquam. Ullamcorper " \
	"sit amet risus nullam eget felis eget. Egestas congue quisque "      \
	"egestas diam in arcu. Nunc congue nisi vitae suscipit tellus "       \
	"mauris a. Auctor eu augue ut lectus arcu bibendum at varius. Eget "  \
	"mauris pharetra et ultrices neque. Magna ac placerat vestibulum "    \
	"lectus mauris ultrices eros in. Lorem dolor sed viverra ipsum nunc " \
	"aliquet bibendum enim facilisis. Auctor eu augue ut lectus arcu "    \
	"bibendum at varius. Viverra vitae congue eu consequat ac felis "     \
	"donec et odio. Tristique nulla aliquet enim tortor at auctor urna "  \
	"nunc id. Molestie a iaculis at erat pellentesque. In hac habitasse " \
	"platea dictumst vestibulum rhoncus est pellentesque. Justo laoreet " \
	"sit amet cursus sit amet dictum sit amet. Auctor augue mauris "      \
	"augue neque gravida in. Dolor morbi non arcu risus quis varius "     \
	"quam quisque id. Metus vulputate eu scelerisque felis. Mattis "      \
	"vulputate enim nulla aliquet porttitor lacus luctus accumsan "       \
	"tortor."
#define FILENAME "lorem-ipsum"
#define STORAGE_NAME                                                          \
	"Lorem_ipsum_dolor_sit_amet__consectetur_adipiscing_elit__sed_do_"    \
	"eiusmod_tempor_incididunt_ut_labore_et_dolore_magna_aliqua__Elit_"   \
	"pellentesque_habitant_morbi_tristique_senectus_et_netus_et_"         \
	"malesuada__Quam_viverra_orci_sagittis_eu_volutpat_odio_facilisis_"   \
	"mauris__Varius_morbi_enim_nunc_faucibus_a__Est_lorem_ipsum_dolor_"   \
	"sit_amet__Sed_egestas_egestas_fringilla_phasellus_faucibus_"         \
	"scelerisque__Condimentum_vitae_sapien_pellentesque_habitant_morbi_"  \
	"tristique_senectus__Mattis_molestie_a_iaculis_at_erat_pellentesque_" \
	"adipiscing_commodo_elit__Nulla_facilisi_nullam_vehicula_ipsum_a_"    \
	"arcu_cursus_vitae__Sed_odio_morbi_quis_commodo_odio_aenean__Nam_"    \
	"libero_justo_laoreet_sit_amet__Velit_aliquet_sagittis_id_"           \
	"consectetur_purus_ut_faucibus_pulvinar__In_hendrerit_gravida_"       \
	"rutrum_quisque_non__Lectus_quam_id_leo_in_vitae_turpis_massa__Amet_" \
	"justo_donec_enim_diam_vulputate__Faucibus_purus_in_massa_tempor__"   \
	"Dui_faucibus_in_ornare_quam_viverra_orci_sagittis_eu_volutpat__Et_"  \
	"netus_et_malesuada_fames_ac"

void __real_sdk_collect_telemetry(void (*)(const char *,
					   const struct EVP_telemetry_entry *,
					   size_t, void *,
					   struct sdk_event_telemetry *),
				  void *user);
void
__wrap_sdk_collect_telemetry(void (*cb)(const char *,
					const struct EVP_telemetry_entry *,
					size_t, void *,
					struct sdk_event_telemetry *),
			     void *user)
{
	sync_join(&sdk_collect_telemetry_sync);
	__real_sdk_collect_telemetry(cb, user);
}

/*
 * Instance state tests
 */

static void
state_cb(EVP_STATE_CALLBACK_REASON reason, void *userData)
{
	static const char *reasons[] = {
		"EVP_STATE_CALLBACK_REASON_SENT",
		"EVP_STATE_CALLBACK_REASON_OVERWRITTEN",
		"EVP_STATE_CALLBACK_REASON_EXIT",
		"EVP_STATE_CALLBACK_REASON_DENIED",
	};
	info("Got reason %s\n", reasons[reason]);
	check_expected(reason);
	check_expected(userData);
}

void
test_instance_state(void **state)
{
	struct test_context *ctxt = *state;
	const char userdata[] = "user data";
	EVP_RESULT res;

	// Try to send a large state value wich will reach maximum payload
	res = EVP_sendState(ctxt->h, "topic-lorem_ipsum", LOREM_IPSUM,
			    strlen(LOREM_IPSUM), state_cb, (void *)userdata);
	assert_int_equal(res, EVP_OK);

	// Wait for the callback.
	// It is expected that payload of combined states will be
	// superior to EVP_TRANSPORT_QUEUE_LIMIT set in this test setup.
	// An therefore will not be queued for transmission.
	expect_value(state_cb, reason, EVP_STATE_CALLBACK_REASON_DENIED);
	expect_value(state_cb, userData, userdata);

	// Wait at least minimum report interval (3s)
	res = EVP_processEvent(ctxt->h, 4000);
	assert_int_equal(res, EVP_OK);
}

static void
telemetry_cb(EVP_TELEMETRY_CALLBACK_REASON reason, void *userData)
{
	static const char *reasons[] = {
		"EVP_TELEMETRY_CALLBACK_REASON_SENT",
		"EVP_TELEMETRY_CALLBACK_REASON_ERROR",
		"EVP_TELEMETRY_CALLBACK_REASON_EXIT",
		"EVP_TELEMETRY_CALLBACK_REASON_DENIED",
	};
	info("Got reason %s\n", reasons[reason]);
	check_expected(reason);
	check_expected(userData);
}

void
test_telemetry(void **state)
{
	struct test_context *ctxt = *state;
	char userdata[] = "user data";
	EVP_RESULT res;

	// Create a very large entry to make sure we can't enqueue it.
	// The expected payload of this entry will be around 1167 B.
	struct EVP_telemetry_entry entries[] = {
		{
			.key = "lorem-ipsum",
			.value = "{\"text\":\"" LOREM_IPSUM "\"}",
		},
	};

	sync_activate(&sdk_collect_telemetry_sync, 2);

	// send telemetry entries
	res = EVP_sendTelemetry(ctxt->h, entries, __arraycount(entries),
				telemetry_cb, userdata);
	assert_int_equal(res, EVP_OK);

	// Synchronize and start collection
	sync_join(&sdk_collect_telemetry_sync);

	// verify callback
	expect_value(telemetry_cb, reason,
		     EVP_TELEMETRY_CALLBACK_REASON_DENIED);
	expect_memory(telemetry_cb, userData, userdata, sizeof(userdata));

	res = EVP_processEvent(ctxt->h, 1000);
	assert_int_equal(res, EVP_OK);
}

static void
blob_cb(EVP_BLOB_CALLBACK_REASON reason, const void *vp, void *userData)
{
	static const char *reasons[] = {
		"EVP_BLOB_CALLBACK_REASON_DONE",
		"EVP_BLOB_CALLBACK_REASON_EXIT",
		"EVP_BLOB_CALLBACK_REASON_DENIED",
	};
	info("Got reason %s\n", reasons[reason]);
	check_expected(reason);
	check_expected(userData);
}

void
test_blob(void **state)
{
	struct test_context *ctxt = *state;
	char userdata[] = "user data";
	EVP_RESULT res;

	struct EVP_BlobRequestEvpExt request;
	request.remote_name = FILENAME;
	request.storage_name = STORAGE_NAME;

	// make a local store
	struct EVP_BlobLocalStore localStore;
	localStore.filename = FILENAME;

	// the blob operation should fire an mSTP token request
	res = EVP_blobOperation(ctxt->h, EVP_BLOB_TYPE_EVP_EXT,
				EVP_BLOB_OP_PUT, &request, &localStore,
				blob_cb, userdata);
	assert_int_equal(res, EVP_OK);

	// wait for the blob_cb
	expect_value(blob_cb, reason, EVP_BLOB_CALLBACK_REASON_DENIED);
	expect_value(blob_cb, userData, userdata);

	res = EVP_processEvent(ctxt->h, 1000);
	assert_int_equal(res, EVP_OK);
}

void
test_blob_max_ongoing_requests(void **state)
{
	struct test_context *ctxt = *state;
	char userdata[] = "user data";

	for (int i = 0; i < CONFIG_EVP_AGENT_MAX_LIVE_BLOBS_PER_INSTANCE + 1;
	     i++) {
		EVP_RESULT res;

		struct EVP_BlobRequestAzureBlob request = {
			.url = "",
		};

		// make a local store
		struct EVP_BlobLocalStore localStore = {.filename = FILENAME};

		// the blob operation should fire an mSTP token request
		res = EVP_blobOperation(ctxt->h, EVP_BLOB_TYPE_AZURE_BLOB,
					EVP_BLOB_OP_PUT, &request, &localStore,
					blob_cb, userdata);
		if (i < CONFIG_EVP_AGENT_MAX_LIVE_BLOBS_PER_INSTANCE) {
			assert_int_equal(res, EVP_OK);
		} else {
			assert_int_equal(res, EVP_DENIED);
		}
	}

	for (int i = 0; i < CONFIG_EVP_AGENT_MAX_LIVE_BLOBS_PER_INSTANCE;
	     i++) {
		expect_value(blob_cb, reason, EVP_BLOB_CALLBACK_REASON_DONE);
		expect_value(blob_cb, userData, userdata);
		// wait for the blob_cb
		EVP_RESULT res = EVP_processEvent(ctxt->h, 1000);
		assert_int_equal(res, EVP_OK);
	}
}

static void
rpc_response_cb(EVP_RPC_RESPONSE_CALLBACK_REASON reason, void *userData)
{
	check_expected(reason);
	check_expected(userData);
}

void
test_direct_command(void **state)
{
	struct test_context *ctxt = *state;
	const char userdata[] = "user data";
	EVP_RESULT res;

	// direct command response
	EVP_RPC_RESPONSE_STATUS status = EVP_RPC_RESPONSE_STATUS_OK;
	res = EVP_sendRpcResponse(ctxt->h, 543210, "\"" LOREM_IPSUM "\"",
				  status, rpc_response_cb, (void *)userdata);
	assert_int_equal(res, EVP_OK);

	// verify response callback
	expect_value(rpc_response_cb, reason,
		     EVP_RPC_RESPONSE_CALLBACK_REASON_DENIED);
	expect_memory(rpc_response_cb, userData, userdata, sizeof(userdata));
	res = EVP_processEvent(ctxt->h, 1000);
	assert_int_equal(res, EVP_OK);
}

int
setup(void **state)
{
	static struct test_context ctxt;

	putenv("EVP_REPORT_STATUS_INTERVAL_MIN_SEC=3");
	putenv("EVP_TRANSPORT_QUEUE_LIMIT=1024");
	info("Set EVP_TRANSPORT_QUEUE_LIMIT=%s\n",
	     getenv("EVP_TRANSPORT_QUEUE_LIMIT"));

	sync_init(&sdk_collect_telemetry_sync);
	sync_init(&sdk_complete_collect_telemetry_sync);

	agent_register_payload(DEPLOYMENT_MANIFEST_1, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_DEPLOYMENT_MANIFEST_1);
	agent_register_payload(DEPLOYMENT_MANIFEST_1, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_DEPLOYMENT_MANIFEST_1);

	agent_test_setup();

	// start agent
	ctxt.agent = agent_test_start();

	struct agent_deployment d = {.ctxt = ctxt.agent};

	// create backdoor instance
	ctxt.h = evp_agent_add_instance(ctxt.agent, MODULE_NAME);
	assert_non_null(ctxt.h);

	// send deployment manifest
	agent_ensure_deployment(&d, agent_get_payload(DEPLOYMENT_MANIFEST_1),
				TEST_DEPLOYMENT_ID1);

	*state = &ctxt;
	return 0;
}

int
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
		cmocka_unit_test(test_instance_state),
		cmocka_unit_test(test_telemetry),
		cmocka_unit_test(test_blob),
		cmocka_unit_test(test_blob_max_ongoing_requests),
		cmocka_unit_test(test_direct_command),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup, teardown);
}
