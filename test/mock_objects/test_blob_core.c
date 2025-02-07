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
#include "evp/sdk.h"
#include "hub.h"
#include "module_instance.h"
#include "mqtt_custom.h"
#include "parson.h"
#include "path.h"
#include "req.h"
#include "test_blob_core_defs.h"
#include "websrv/proxy.h"
#include "websrv/websrv.h"

struct test_blob_core_context g_test_blob_core_context = {
	.workspace = TEST_WORKSPACE_TEMPLATE,
	.match_stp_prefix_fmt = BLOB_NAME_FMT,
};

int
add_instance_config(JSON_Object *o, int i, const char *name, const char *fmt,
		    ...)
{
	char *key = NULL;
	char *value = NULL;
	int rv, err = 0;

	rv = asprintf(&key, "configuration/" INSTANCE_ID_FMT "/%s", i, name);
	if (rv < 0) {
		err = rv;
		goto done;
	}

	va_list va;
	va_start(va, fmt);
	rv = vasconfigf(&value, fmt, va);
	va_end(va);
	if (rv < 0) {
		err = rv;
		goto done;
	}
	json_object_set_string(o, key, value);
done:
	free(value);
	free(key);
	return err;
}

int
add_instances_configs(JSON_Object *o, const char *prefix, int n)
{
	for (int i = 1; i <= n; i++) {
		add_instance_config(o, i, "instance_name", "test-module-%d",
				    i);
		add_instance_config(o, i, "upload", "%s" BLOB_NAME_FMT, prefix,
				    i);
		add_instance_config(o, i, "local_file", FILE_UPLOAD_NAME);
		add_instance_config(o, i, "storage_name_def",
				    STORAGE_NAME_DEF);
	}
	return 0;
}

char *
create_instance_config(const char *prefix, int n)
{
	JSON_Value *v = json_value_init_object();
	assert_non_null(v);
	JSON_Object *o = json_value_get_object(v);
	assert_non_null(o);

	add_instances_configs(o, prefix, n);

	char *s = json_serialize_to_string(v);
	assert_non_null(s);

	char *out = strdup(s);
	json_free_serialized_string(s);
	json_value_free(v);
	return out;
}

#define IMPL_TUPLE(Symb, Name, Ext) {Name, Ext},
static const struct {
	const char *name;
	const char *ext;
} g_impls[] = {MODULE_IMPLS(IMPL_TUPLE)};

static char *
make_hash(enum test_impl impl, const char *module)
{
	char *hash;
	int rv = popenf(popen_strcpy, &hash,
			"sha256sum %s/%s.%s | awk '{ print $1 }'", MODULE_DIR,
			module, g_impls[impl].ext);
	assert_int_equal(rv, 0);
	return hash;
}

static char *
make_url(enum test_impl impl, const char *module)
{
	char *url;
	xasprintf(&url, "file://%s/%s.%s", MODULE_DIR, module,
		  g_impls[impl].ext);
	return url;
}

int
add_deployement(JSON_Object *o, enum test_impl impl, const char *module, int n)
{
	assert_true(impl < TEST_IMPL_END);

	// Add instances
	for (int i = 1; i <= n; i++) {
		char *name;
		xasprintf(&name, INSTANCE_ID_FMT, i);
		manifest_add_instance_spec(o, name, MODULE_ID, "main", 1);
		free(name);
	}

	// Add module
	if (module) {
		char *hash = make_hash(impl, module);
		char *url = make_url(impl, module);
		JSON_Object *mo;
		mo = manifest_add_module_spec(o, MODULE_ID, g_impls[impl].name,
					      hash, url, "main");
		free(url);
		free(hash);
		assert_non_null(mo);
	}
	return 0;
}

char *
craft_deployement(enum test_impl impl, const char *deploy, const char *module,
		  int n)
{
	JSON_Object *o = manifest_create(NULL, deploy);
	add_deployement(o, impl, module, n);
	manifest_finalize(o);
	// TODO: ultimately send the whole crafted message instead of the
	// payload.
	// Currently `agent_send_deployment` wraps payload with
	// `{"deployment":PAYLOAD}`
	char *out = manifest_serialize_deployment(o);
	object_free(o);
	return out;
}

static void
deploy(struct agent_deployment *d, enum test_impl impl, const char *module,
       int n)
{
	print_message("[   INFO   ] Deploying with module %s\n", module);
	char *payload;
	payload = craft_deployement(impl, DEPLOYMENT_ID, module, n);
	agent_ensure_deployment(d, payload, DEPLOYMENT_ID);
	free(payload);
	print_message("[   INFO   ] Deployed %s\n", DEPLOYMENT_ID);
}

static void
undeploy(struct agent_deployment *d)
{
	print_message("[   INFO   ] Undeploying\n");
	char *payload = craft_deployement(0, DEPLOYMENT_ID_EMPTY, NULL, 0);
	agent_ensure_deployment(d, payload, DEPLOYMENT_ID_EMPTY);
	free(payload);
	print_message("[   INFO   ] Undeployed\n");
}

int
teardown_suite_blob_core(void **state)
{
	print_message("[   INFO   ] Tearing down suite\n");
	proxy_stop();
	websrv_stop();
	websrv_teardown();
	return 0;
}

static void
cleanup_workspace(void)
{
	// Ensure data dir is present and pristine
	const char *mi_path = path_get(MODULE_INSTANCE_PATH_ID);
	systemf("rm -rf %s/*/default_workspace", mi_path);
}

static void
init_workspace(struct test_blob_core_context *ctxt)
{
	// Ensure workspace tree is created
	systemf("mkdir -p %s/assets", ctxt->workspace);
	systemf("mkdir -p %s/www", ctxt->workspace);
	for (int i = 1; i <= TEST_N_INSTANCES; i++) {
		systemf("%s > " ASSETS_BLOB_FMT, FILE_BLOB_GEN_CMD,
			ctxt->workspace, i);
	}
}

void
init_instance_workspace_upload_file(struct test_blob_core_context *ctxt, int i)
{
	// This creates the file to upload in the
	// `<EVP_DATA_DIR>/instance/<INSTANCE_ID>/default_workspace/` dir
	const char *mi_path = path_get(MODULE_INSTANCE_PATH_ID);
	assert_int_equal(systemf("cp " ASSETS_BLOB_FMT " %s/" INSTANCE_ID_FMT
				 "/default_workspace/%s",
				 ctxt->workspace, i, mi_path, i,
				 FILE_UPLOAD_NAME),
			 0);
}

static int
on_put_blob_data(const struct http_payload *p, struct http_response *r,
		 void *user)
{
	const char *workspace = user ? user : ".";
	static const char str[] =
		"webclient still needs a body for some reason";

	print_message("[   INFO   ] Got PUT %s to %s/www%s\n", p->resource,
		      workspace, p->resource);

	*r = (struct http_response){.status = p->expect_continue
						      ? HTTP_STATUS_CONTINUE
						      : HTTP_STATUS_OK,
				    .buf.ro = str,
				    .n = strlen(str)};

	// Copy file to web server workspace
	systemf("mkdir -p $(dirname %s/www%s)", workspace, p->resource);
	int rv = systemf("cp %s %s/www%s", p->u.put.tmpname, workspace,
			 p->resource);
	if (rv) {
		return rv;
	}

	char *data;
	xasprintf(&data, "[WEBSRV] PUT %s", p->resource);
	agent_write_to_pipe(data);
	free(data);
	return 0;
}

static void
setup_websrv(struct test_blob_core_context *ctxt)
{
	unsigned short backend_port;

	putenv("EVP_HTTPS_CA_CERT=certs/ca-cert.pem");
	assert_non_null(mkdtemp(ctxt->workspace));

	assert_int_equal(websrv_setup(TEST_HTTP_SERVER_PORT), 0);
	assert_int_equal(websrv_add_route("/blob_data_1", HTTP_OP_GET,
					  on_get_user_string,
					  "Content blob_data_1"),
			 0);
	assert_int_equal(websrv_add_route("/blob_data_2", HTTP_OP_GET,
					  on_get_user_string,
					  "Content blob_data_2"),
			 0);
	assert_int_equal(websrv_add_route("/blob_data_3", HTTP_OP_GET,
					  on_get_user_string,
					  "Content blob_data_3"),
			 0);
	assert_int_equal(websrv_add_route("/*", HTTP_OP_PUT, on_put_blob_data,
					  ctxt->workspace),
			 0);
	assert_int_equal(websrv_get_port(&backend_port), 0);

	struct proxy_cfg proxy_cfg = {
		.backend_port = backend_port,
		.frontend_port = TEST_PROXY_FRONTEND_PORT,
	};
	assert_int_equal(proxy_start(&proxy_cfg), 0);
	ctxt->port = proxy_cfg.frontend_port;
	assert_int_equal(websrv_start(), 0);
}

static void
setup_payloads(void)
{
	// STP response
	agent_register_payload(STP_RESPONSE_FMT, EVP_HUB_TYPE_EVP1_TB,
			       EVP1_STP_RESPONSE_FMT);
	agent_register_payload(STP_RESPONSE_FMT, EVP_HUB_TYPE_EVP2_TB,
			       EVP2_STP_RESPONSE_FMT);

	// Verify the STP request
	agent_register_payload(VERIFY_STP_REQUEST_JSON_DOT,
			       EVP_HUB_TYPE_EVP1_TB,
			       "params.storageName=%s,"
			       "method=%s");
	agent_register_payload(VERIFY_STP_REQUEST_JSON_DOT,
			       EVP_HUB_TYPE_EVP2_TB,
			       "params.storagetoken-request.key=%s");
}

int
setup_suite_blob_core(void **state)
{
	struct test_blob_core_context *ctxt = &g_test_blob_core_context;
	print_message("[   INFO   ] Setting up suite\n");

	agent_test_setup();
	setup_payloads();
	setup_websrv(ctxt);
	cleanup_workspace();
	init_workspace(ctxt); // Prepare test workspace with blob assets
	return 0;
}

int
setup_test_blob_core(void **state)
{
	struct test_blob_core_context *ctxt = &g_test_blob_core_context;
	struct test_blob_core_param *param = *state;

	ctxt->agent = agent_test_start();

	if (ctxt->agent == NULL) {
		fprintf(stderr, "%s: agent_test_start failed\n", __func__);
		return -1;
	}

	ctxt->deployment = (struct agent_deployment){.ctxt = ctxt->agent};

	// Initialize
	agent_ensure_deployment(&ctxt->deployment, NULL, NULL);
	print_message("[   INFO   ] Agent started\n");

	cleanup_workspace();

	if (!param->n_instances) {
		param->n_instances = TEST_N_INSTANCES;
	}
	deploy(&ctxt->deployment, param->impl, param->module,
	       param->n_instances);
	return 0;
}

int
teardown_test_blob_core(void **state)
{
	struct test_blob_core_context *ctxt = &g_test_blob_core_context;
	// Undeploy
	undeploy(&ctxt->deployment);

	// wait for agent to finish
	agent_test_exit();
	return 0;
}

void
check_blob_upload(struct test_blob_core_context *ctxt, int i)
{
	// Compare assets blob with uploaded blob to webserver workspace
	assert_int_equal(systemf("cmp " ASSETS_BLOB_FMT
				 " %s/www/" BLOB_NAME_FMT,
				 ctxt->workspace, i, ctxt->workspace, i),
			 0);
}

void
send_stp_response(struct test_blob_core_context *ctxt,
		  const char *response_type, unsigned long expires_at_ms,
		  int i)
{
	struct test_st_req *req = &g_test_blob_core_context.stp_reqs[i];
	char *reqid;
	xasprintf(&reqid, "%lu", req->reqid);
	const char *params = TEST_SAS_PARAMS;

	char *remote_name;
	if (strcmp(response_type, "multifile")) {
		int rv;
		rv = popenf(popen_strcpy, &remote_name,
			    "jq -rn --arg x '%s' '$x|@uri'", req->remote_name);
		assert_int_equal(rv, 0);
	} else {
		remote_name = strdup("");
	}
	// send the hub response with the sas
	char *pl = agent_get_payload_formatted(
		STP_RESPONSE_FMT, ctxt->port, remote_name, params,
		response_type, expires_at_ms, reqid);
	agent_send_storagetoken_response(ctxt->agent, pl, reqid);
	free(remote_name);
	free(pl);
	free(reqid);
}

void
send_stp_responses(struct test_blob_core_context *ctxt,
		   const char *response_type, unsigned long expires_at_ms)
{
	for (size_t i = 0; i < __arraycount(ctxt->stp_reqs); i++) {
		send_stp_response(ctxt, response_type, expires_at_ms, i);
	}
}

static void
wait_step(int step)
{
	char *status;
	asconfigf(&status, "g_step = %d", step);
	struct multi_check *set =
		xcalloc(sizeof(set[0]), TEST_N_INSTANCES + 1);
	for (int i = 0; i < TEST_N_INSTANCES; i++) {
		xasprintf(&set[i].value_rw,
			  "\"state/" INSTANCE_ID_FMT "/status\":\"%s\"", i + 1,
			  status);
	}
	print_message("[   INFO   ] Wait for step %d (status='%s')\n", step,
		      status);
	free(status);

	agent_poll(verify_contains_in_unordered_set, set);

	for (int i = 0; i < TEST_N_INSTANCES; i++) {
		free(set[i].value_rw);
	}
	free(set);
}

void
test_upload_http_file(void **state)
{
	struct test_blob_core_context *ctxt = &g_test_blob_core_context;
	struct test_blob_core_param *param = *state;

	// Verify module is ready
	wait_step(0);

	// Prepare files to upload
	for (size_t i = 1; i <= param->n_instances; i++) {
		init_instance_workspace_upload_file(ctxt, i);
	}

	// send instance config
	char *host;
	xasprintf(&host, TEST_BASE_URL_FMT "/", ctxt->port);
	char *config = create_instance_config(host, param->n_instances);
	agent_send_instance_config(ctxt->agent, config);
	json_free_serialized_string(config);
	free(host);

	// Verify PUT operations are sent
	{
		struct multi_check *set =
			xcalloc(sizeof(set[0]), param->n_instances + 1);
		for (size_t i = 0; i < param->n_instances; i++) {
			xasprintf(&set[i].value_rw,
				  "[WEBSRV] PUT /" BLOB_NAME_FMT, i + 1);
		}

		agent_poll(verify_contains_in_unordered_set, set);

		for (size_t i = 0; i < param->n_instances; i++) {
			free(set[i].value_rw);
		}
		free(set);
	}

	// check that the module completed its actions
	wait_step(1000);

	// check uploaded blobs
	for (size_t i = 0; i < param->n_instances; i++) {
		check_blob_upload(ctxt, i + 1);
	}
}
void
test_upload_evp_file(void **state)
{
	struct test_blob_core_context *ctxt = &g_test_blob_core_context;
	struct test_blob_core_param *param = *state;

	// Verify module is ready
	wait_step(0);

	// Prepare file to upload
	print_message("[   INFO   ] Prepare files in workspaces\n");
	// This creates the file to upload in the
	// `<EVP_DATA_DIR>/instance/<INSTANCE_ID>/default_workspace/`
	// dir
	for (size_t i = 1; i <= param->n_instances; i++) {
		init_instance_workspace_upload_file(ctxt, i);
	}

	// send instance config
	print_message("[   INFO   ] Send instances configs\n");
	char *config = create_instance_config("", param->n_instances);
	agent_send_instance_config(ctxt->agent, config);
	json_free_serialized_string(config);
	// Not check configuration done, because the module may send the rpc
	// request before sending the new state

	// At this point the module calls EVP_blobOperation and the agent will
	// send a storage token request

	// check ST request has been sent (it should contains the storage name
	// "storage_def")
	// check that the module completed its actions

	// Check request payload
	print_message("[   INFO   ] Wait STP requests\n");
	for (size_t i = 1; i <= param->n_instances; i++) {
		agent_poll(verify_json,
			   agent_get_payload(VERIFY_STP_REQUEST_JSON_DOT),
			   STORAGE_NAME_DEF, "StorageToken");
	}

	print_message("[   INFO   ] Send STP responses\n");
	send_stp_responses(ctxt, "singlefile", 0);

	// check that the module completed its actions
	wait_step(1000);

	// check uploaded blobs
	print_message("[   INFO   ] Check uploaded blobs\n");
	for (size_t i = 1; i <= param->n_instances; i++) {
		check_blob_upload(ctxt, i);
	}
}
