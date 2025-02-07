/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE /* asprintf */
#include <sys/stat.h>

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
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

	/* Wait TOPIC_UPLOAD configuration. start uploading the given url */
	STEP_UPLOAD = 1,

	/* Wait for the upload completion. */
	STEP_UPLOAD_WAIT = 2,

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

	char *upload;
	char *blob_buff;      /* buffer for blob actions over memory */
	int blob_buff_size;   /* Max buffer size */
	int blob_buff_offset; /* Current buff size used */
	char *storage_name;
	FILE *f;
	off_t size;
} module_vars_t;

typedef struct {
	module_vars_t *ctx;
	char *blob_url;
} blob_cb_data_t;

struct state_cb_data {
	char *blob;
};

static const char *module_name = "UPLOAD-EVP-MEMORY";

static void
fsm_step(module_vars_t *vars, bool resultOk)
{

	steps_t prev_step = vars->step;
	steps_t new_step = STEP_END_TEST_FAIL;

	switch (prev_step) {

	case STEP_WAIT_CONFIG:
	case STEP_UPLOAD:
	case STEP_UPLOAD_WAIT:
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
	} else if (!strcmp(topic, TOPIC_UPLOAD)) {
		varp = &vars->upload;
	} else if (!strcmp(topic, TOPIC_STORAGE_NAME_DEF)) {
		varp = &vars->storage_name;
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

static EVP_BLOB_IO_RESULT
blob_io_cb(void *buf, size_t buflen, void *userData)
{
	blob_cb_data_t *cb = userData;
	const module_vars_t *ctx = cb->ctx;
	FILE *f = ctx->f;

	if (!fread(buf, buflen, 1, f)) {
		log_module(module_name,
			   "%s: fread(3) failed, ferror=%d, feof=%d\n",
			   __func__, ferror(f), feof(f));
		return EVP_BLOB_IO_RESULT_ERROR;
	}

	return EVP_BLOB_IO_RESULT_SUCCESS;
}

static void
blob_cb(EVP_BLOB_CALLBACK_REASON reason, const void *vp, void *userData)
{
	assert(userData != NULL);
	const struct EVP_BlobResultEvp *result;

	blob_cb_data_t *cb_data = (blob_cb_data_t *)userData;
	module_vars_t *module_vars = cb_data->ctx;

	switch (reason) {
	case EVP_BLOB_CALLBACK_REASON_DONE:
		result = vp;
		log_module(module_vars->instance_name,
			   "EVP_BLOB_CALLBACK_REASON_DONE result=%u "
			   "http_status=%u error=%d\n",
			   result->result, result->http_status, result->error);

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

static int
filesz(FILE *f, off_t *out)
{
	int fd = fileno(f);
	struct stat sb;

	if (fd < 0) {
		log_module(module_name, "%s: fileno(3): %s\n", __func__,
			   strerror(errno));
		return -1;
	}

	if (fstat(fd, &sb)) {
		log_module(module_name, "%s: fstat(2): %s\n", __func__,
			   strerror(errno));
		return -1;
	}

	*out = sb.st_size;
	return 0;
}

int
main(void)
{
	module_vars_t module_vars;

	/* Init vars */
	module_vars.upload = NULL;
	module_vars.filename = NULL;
	module_vars.localStore.filename = NULL;
	module_vars.localStore.io_cb = 0;
	module_vars.localStore.blob_len = 0;
	module_vars.step = STEP_WAIT_CONFIG;
	module_vars.instance_name = strdup(module_name);
	module_vars.abs_filename = NULL;
	module_vars.storage_name = NULL;

	module_vars.blob_buff_size = 0;
	module_vars.blob_buff_offset = 0;
	module_vars.blob_buff = NULL;

	steps_t reported_step = -1;
	/* Data used for blob_cb to share instance context and current url
	 * used, and free configuration after use it */
	blob_cb_data_t cb_data;
	cb_data.blob_url = NULL;
	cb_data.ctx = &module_vars;

	struct EVP_client *h = EVP_initialize();

	EVP_setConfigurationCallback(h, config_cb, (void *)&module_vars);

	for (;;) {
		EVP_RESULT result;

		result = EVP_processEvent(h, 1000);
		if (result == EVP_SHOULDEXIT) {
			/* free buffers */
			free(module_vars.instance_name);
			free(module_vars.filename);
			free(module_vars.upload);
			free(module_vars.abs_filename);
			free(module_vars.blob_buff);
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
				   "Load file %s and upload it via blob "
				   "memory operations.\n",
				   module_vars.abs_filename);

			FILE *f = fopen(module_vars.abs_filename, "rb");

			if (!f) {
				log_module(module_name,
					   "%s: fopen(3) %s: %s\n", __func__,
					   module_vars.abs_filename,
					   strerror(errno));
				return EXIT_FAILURE;
			}

			off_t size;

			if (filesz(f, &size)) {
				log_module(module_name, "%s: filesz failed\n",
					   __func__);
				return EXIT_FAILURE;
			}

			if (size > INT_MAX) {
				fprintf(stderr,
					"%s: size %jd exceeds maximum size "
					"%d\n",
					__func__, (intmax_t)size, INT_MAX);
				return EXIT_FAILURE;
			}

			/* Check the file size is smaller than local buffer */
			log_module(module_vars.instance_name,
				   "Test file size is %jd, and we do not give "
				   "a damn about the max\n",
				   (intmax_t)size);

			/* Copy data to local buffer */
			module_vars.f = f;
			module_vars.blob_buff_size = size;
			module_vars.blob_buff_offset = 0;
			module_vars.blob_buff = NULL;
			fsm_step(&module_vars, true);
		}

		if (module_vars.upload != NULL &&
		    module_vars.storage_name != NULL &&
		    module_vars.step == STEP_UPLOAD) {

			log_module(module_vars.instance_name,
				   "Scheduling an upload from memory.\n");

			struct EVP_BlobRequestEvpExt request;
			request.remote_name = cb_data.blob_url =
				module_vars.upload;
			request.storage_name = module_vars.storage_name;
			module_vars.upload = NULL;
			module_vars.localStore.filename = NULL;
			module_vars.localStore.io_cb = blob_io_cb;
			module_vars.localStore.blob_len =
				module_vars.blob_buff_size;

			result = EVP_blobOperation(h, EVP_BLOB_TYPE_EVP_EXT,
						   EVP_BLOB_OP_PUT, &request,
						   &module_vars.localStore,
						   blob_cb, &cb_data);

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
