/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <unistd.h>

#include "agent_internal.h"
#include "main_loop.h"
#include "path.h"
#include "test_blob_core.h"
#include "timeutil.h"

/*
 * This tests the mSTP cache feature with the following requirements:
 * - storage token response shall contain `responseType` with `multifile` value
 * - storage token response shall contain `expiresAtMilli` with an expiration
 *   timestamp superior to current date timestamp
 *
 */
#define TEST_INSTANCE_ID INSTANCE_ID_BASE "000000000001"

#define MSTP_MATCH_STRING "test.txt"

static void
check_cache_file(const char *fmt, ...)
{
	char *json;
	const char *file = path_get(CACHE_PATH_ID);
	popenf(popen_strcpy, &json, "jq -r '.[0]' %s", file);
	va_list va;
	va_start(va, fmt);
	bool res = verify_json(json, fmt, va);
	va_end(va);
	free(json);
	assert_true(res);
}

static void
craft_cache(struct test_blob_core_context *ctxt, const char *instance,
	    const char *response_type, uint64_t expires_at_ms)
{
	char *pl = agent_get_payload_formatted(
		STP_RESPONSE_FMT, ctxt->port, "", TEST_SAS_PARAMS,
		response_type, expires_at_ms, "0");
	int rv;
	rv = systemf("printf %%s '%s' | jq "
		     "--arg INSTANCE %s "
		     "--arg STORAGE %s "
		     "'["
		     "  {"
		     "    instanceName:$INSTANCE,"
		     "    storageName:$STORAGE"
		     "  } + ."
		     "]' > %s",
		     pl, instance, STORAGE_NAME_DEF, path_get(CACHE_PATH_ID));
	free(pl);
	assert_int_equal(rv, 0);
}

int
setup_test_mstp_cache_load(void **state)
{
	struct test_blob_core_context *ctxt = &g_test_blob_core_context;
	struct test_blob_core_param *param = *state;

	if (!param->n_instances) {
		param->n_instances = 1;
	}

	agent_test_enable_capture_mode();

	JSON_Object *o = manifest_create(NULL, DEPLOYMENT_ID);
	add_deployement(o, param->impl, param->module, param->n_instances);
	add_instances_configs(o, "", param->n_instances);
	manifest_finalize(o);
	char *desired = object_serialize(o);
	object_free(o);
	assert_int_equal(systemf("mkdir -p %s", path_get(TWINS_PATH_ID)), 0);
	assert_int_equal(systemf("printf \"%%s\" '%s' > %s", desired,
				 path_get(DESIRED_TWINS_PATH_ID)),
			 0);
	free(desired);

	craft_cache(ctxt, TEST_INSTANCE_ID, "multifile",
		    gettime_ms() + (3600 * 1000));

	ctxt->agent = agent_test_start();
	main_loop_wakeup("TEST");

	// Initialize
	// agent_send_initial(ctxt->agent, NULL, NULL, NULL);
	print_message("[   INFO   ] Agent started\n");

	return 0;
}

int
teardown_test_mstp_cache_load(void **state)
{
	agent_test_exit();
	return 0;
}

void
test_mstp_cache_store(void **state)
{
	struct test_blob_core_context *ctxt = &g_test_blob_core_context;
	struct test_blob_core_param *param = *state;

	const char *cache = path_get(CACHE_PATH_ID);
	systemf("rm %s", cache);

	// send instance config
	print_message("[   INFO   ] Send instances configs\n");
	char *config = create_instance_config("", param->n_instances);
	agent_send_instance_config(ctxt->agent, config);
	json_free_serialized_string(config);

	// Wait for storage token request
	print_message("[   INFO   ] Wait STP requests\n");
	agent_poll(verify_json, agent_get_payload(VERIFY_STP_REQUEST_JSON_DOT),
		   STORAGE_NAME_DEF, "StorageToken");

	// Send response
	uint64_t expires = gettime_ms() + (1000 * 3600);
	print_message("[   INFO   ] Send STP responses\n");
	send_stp_response(ctxt, "multifile", expires, 0);

	// Verify cache
	char *url, *expiresAtMillis;
	xasprintf(&url, TEST_BASE_URL_FMT "/?" TEST_SAS_PARAMS, ctxt->port);
	xasprintf(&expiresAtMillis, "%lu", expires);
	check_cache_file("instanceName=%s,"
			 "storageName=%s,"
			 "storagetoken-response.URL=%s,"
			 "storagetoken-response.responseType=%s,"
			 "storagetoken-response.expiresAtMillis=%s,"
			 "storagetoken-response.headers.x-ms-blob-type=%s",
			 TEST_INSTANCE_ID, STORAGE_NAME_DEF, url, "multifile",
			 expiresAtMillis, "BlockBlob");
	free(expiresAtMillis);
	free(url);
}

void
test_mstp_cache_load(void **state)
{
	struct test_blob_core_context *ctxt = &g_test_blob_core_context;
	// struct test_blob_core_param *param = *state;

	// Wait for uploads 1 file per second
	print_message("[   INFO   ] Wait for uploads\n");
	agent_poll(verify_contains, "[WEBSRV] PUT");

	// Compare assets blob with uploaded blob to webserver workspace
	print_message("[   INFO   ] Check uploads\n");
	int rv;
	int cnt = -1;
	rv = popenf(popen_parse_int, &cnt, "ls -1 %s/www/%s | wc -l",
		    ctxt->workspace, MSTP_MATCH_STRING);
	assert_int_equal(rv, 0);
	assert_true(cnt >= 1);
}

int
setup_suite_blob_mstp_cache(void **state)
{
	// mSTP cache feature unsuported by EVP1
	if (agent_test_get_hub_type() == EVP_HUB_TYPE_EVP1_TB) {
		fprintf(stderr,
			"[   SKIP   ] Feature not supported by EVP1\n");
		exit(0);
	}

	g_test_blob_core_context.match_stp_prefix_fmt = MSTP_MATCH_STRING;

	return setup_suite_blob_core(state);
}
