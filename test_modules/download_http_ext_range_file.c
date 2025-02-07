/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE /* asprintf */
#include <sys/stat.h>

#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "blob_config.h"
#include "evp/sdk.h"
#include "log.h"

typedef enum {

	/* Wait TOPIC_LOCAL_FILE configuration */
	STEP_WAIT_CONFIG = 0,

	/* Wait TOPIC_DOWNLOAD configuration. start downloading the given url
	 */
	STEP_DOWNLOAD = 1,

	/* Wait for the download completion. */
	STEP_DOWNLOAD_WAIT = 2,

	STEP_END_TEST = 3,

	STEP_END_TEST_FAIL = 999,
	STEP_END_TEST_OK = 1000,

} steps_t;

typedef struct {
	char *instance_name;
	struct EVP_BlobLocalStore localStore;
	char *filename;
	char *abs_filename;
	steps_t step;

	char *download;
} module_vars_t;

typedef struct {
	module_vars_t *ctx;
	char *blob_url;
} blob_cb_data_t;

struct state_cb_data {
	char *blob;
};

static const char *module_name = "DOWNLOAD-HTTP-EXT-RANGE-FILE";

static void
fsm_step(module_vars_t *vars, bool resultOk)
{

	steps_t prev_step = vars->step;
	steps_t new_step = STEP_END_TEST_FAIL;

	switch (prev_step) {

	case STEP_WAIT_CONFIG:
	case STEP_DOWNLOAD:
	case STEP_DOWNLOAD_WAIT:
		new_step = prev_step + 1;
		break;

	case STEP_END_TEST:
		new_step = STEP_END_TEST_OK;
		break;

	case STEP_END_TEST_FAIL:
	case STEP_END_TEST_OK:
		/* Wait in this step. Module has to be stopped externally */
		break;

	default:
		log_module(vars->instance_name, "FATAL: Invalid step %i\n",
			   prev_step);
		assert(0);
	}

	if (!resultOk)
		new_step = STEP_END_TEST_FAIL;

	vars->step = new_step;
	log_module(vars->instance_name, "Step %i ==> %i\n", prev_step,
		   new_step);
}

static void
config_cb(const char *topic, const void *config, size_t configlen,
	  void *userData)
{

	module_vars_t *vars = (module_vars_t *)userData;
	char **varp;

	log_module(vars->instance_name,
		   "Received Configuration (topic=%s, value=%.*s, size=%zu)\n",
		   topic, (int)configlen, (char *)config, configlen);

	if (!strcmp(topic, TOPIC_INSTANCE_NAME)) {
		varp = &vars->instance_name;
	} else if (!strcmp(topic, TOPIC_LOCAL_FILE)) {
		varp = &vars->filename;
	} else if (!strcmp(topic, TOPIC_DOWNLOAD)) {
		varp = &vars->download;
	} else {
		log_module(vars->instance_name,
			   "Ignoring Configuration with unknown topic "
			   "(topic=%s, size=%zu)\n",
			   topic, configlen);
		return;
	}

	/* Free previous configuration if it was not used.
	 * Note: The previous memory allocated is freed in blob_cb after use
	 * it.
	 */
	free(*varp);
	*varp = malloc(configlen + 1);
	assert(*varp != NULL);
	memcpy(*varp, config, configlen);
	(*varp)[configlen] = 0;
}

static void
state_cb(EVP_STATE_CALLBACK_REASON reason, void *userData)
{
	assert(userData != NULL);
	struct state_cb_data *d = userData;
	assert(d->blob != NULL);
	free(d->blob);
	free(d);
}

static void
blob_cb(EVP_BLOB_CALLBACK_REASON reason, const void *vp, void *userData)
{
	assert(userData != NULL);
	const struct EVP_BlobResultHttp *result;

	blob_cb_data_t *cb_data = (blob_cb_data_t *)userData;
	module_vars_t *module_vars = cb_data->ctx;

	switch (reason) {
	case EVP_BLOB_CALLBACK_REASON_DONE:
		result = vp;
		struct stat st;
		stat(module_vars->abs_filename, &st);

		fprintf(stderr,
			"EVP_BLOB_CALLBACK_REASON_DONE result=%u "
			"http_status=%u error=%d size=%llu\n",
			result->result, result->http_status, result->error,
			(unsigned long long)st.st_size);

		assert(st.st_size == 100);

		fsm_step(module_vars,
			 result->result == EVP_BLOB_RESULT_SUCCESS);
		break;
	case EVP_BLOB_CALLBACK_REASON_EXIT:
		assert(vp == NULL);
		log_module(module_vars->instance_name,
			   "EVP_BLOB_CALLBACK_REASON_EXIT\n");
		fsm_step(module_vars, false);
		break;
	default:
		assert(0);
	}

	/* After blob operation free memory used to pass url to request. It has
	 * to be handled here to avoid conifg_cb call free memory while sdk is
	 * using it. SDK can call config_cb at any moment (inclusive with any
	 * change in configuration) */
	free(cb_data->blob_url);
	cb_data->blob_url = NULL;
}

int
main(void)
{
	/* Init vars */
	module_vars_t module_vars = {
		.download = NULL,
		.filename = NULL,
		.localStore.filename = NULL,
		.localStore.io_cb = 0,
		.localStore.blob_len = 0,
		.step = STEP_WAIT_CONFIG,
		.instance_name = strdup(module_name),
		.abs_filename = NULL,
	};

	steps_t reported_step = -1;
	/* Data used for blob_cb to share instance context and current url
	 * used, and free configuration after use it */
	blob_cb_data_t cb_data = {
		.blob_url = NULL,
		.ctx = &module_vars,

	};

	struct EVP_client *h = EVP_initialize();

	EVP_setConfigurationCallback(h, config_cb, (void *)&module_vars);

	for (;;) {
		EVP_RESULT result;

		result = EVP_processEvent(h, 1000);
		if (result == EVP_SHOULDEXIT) {
			/* free buffers */
			free(module_vars.instance_name);
			free(module_vars.filename);
			free(module_vars.download);
			free(module_vars.abs_filename);
			break;
		}

		if (module_vars.filename != NULL &&
		    module_vars.step == STEP_WAIT_CONFIG) {

			const char *workspace = EVP_getWorkspaceDirectory(
				h, EVP_WORKSPACE_TYPE_DEFAULT);

			int ret = asprintf(&module_vars.abs_filename, "%s/%s",
					   workspace, module_vars.filename);
			assert((0 < ret) && (ret < PATH_MAX));

			log_module(module_vars.instance_name,
				   "The blob will be downloaded to: %s\n",
				   module_vars.abs_filename);

			fsm_step(&module_vars, true);
		}

		if (module_vars.download != NULL &&
		    module_vars.step == STEP_DOWNLOAD) {

			log_module(module_vars.instance_name,
				   "Scheduling a download\n");

			struct EVP_BlobRequestHttpExt *request =
				EVP_BlobRequestHttpExt_initialize();
			cb_data.blob_url = module_vars.download;
			EVP_BlobRequestHttpExt_setUrl(request,
						      module_vars.download);
			EVP_BlobRequestHttpExt_addHeader(request, "Range",
							 "bytes=0-99");
			EVP_BlobRequestHttpExt_addAzureHeader(request);
			module_vars.download = NULL;
			module_vars.localStore.filename =
				module_vars.abs_filename;

			result = EVP_blobOperation(h, EVP_BLOB_TYPE_HTTP_EXT,
						   EVP_BLOB_OP_GET, request,
						   &module_vars.localStore,
						   blob_cb, &cb_data);

			EVP_BlobRequestHttpExt_free(request);

			assert(result == EVP_OK);

			fsm_step(&module_vars, true);
		}

		if (module_vars.step == STEP_END_TEST) {

			log_module(module_vars.instance_name, "SUCCESS!\n");
			fsm_step(&module_vars, true);
		}

		if (reported_step != module_vars.step) {

			const char *topic = "status";
			struct state_cb_data *d = malloc(sizeof(*d));
			assert(d != NULL);
			int ret = asprintf(&d->blob, "g_step = %u",
					   module_vars.step);
			assert(ret != -1);
			size_t blob_len = ret;
			log_module(module_vars.instance_name,
				   "Sending State (topic=%s, size=%zu)\n",
				   topic, blob_len);
			result = EVP_sendState(h, topic, d->blob, blob_len,
					       state_cb, d);
			assert(result == EVP_OK);
			reported_step = module_vars.step;
		}
	}
	return 0;
}
