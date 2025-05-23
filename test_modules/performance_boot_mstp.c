/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE /* asprintf */
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "blob_config.h"
#include "evp/sdk.h"
#include "log.h"

#define FILE_SIZE (4096)

typedef struct {
	char *instance_name;
	struct EVP_BlobLocalStore localStore;
	char *filename;
	char *abs_filename;

	char *storage_name;

	struct EVP_client *h;

	bool upload_requested;
	bool upload_done;

} module_vars_t;

static const char *module_name = "PERFORMANCE-BOOT_MSTP";

static void
config_cb(const char *topic, const void *config, size_t configlen,
	  void *userData)
{

	module_vars_t *vars = userData;
	char **varp;

	log_module(vars->instance_name,
		   "Received Configuration (topic=%s, value=%.*s, size=%zu)\n",
		   topic, (int)configlen, (char *)config, configlen);

	if (!strcmp(topic, TOPIC_INSTANCE_NAME)) {
		varp = &vars->instance_name;
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
blob_cb(EVP_BLOB_CALLBACK_REASON reason, const void *vp, void *userData)
{
	assert(userData != NULL);
	const struct EVP_BlobResultEvp *result;

	module_vars_t *module_vars = (module_vars_t *)userData;

	switch (reason) {
	case EVP_BLOB_CALLBACK_REASON_DONE:
		result = vp;
		log_module(module_vars->instance_name,
			   "EVP_BLOB_CALLBACK_REASON_DONE result=%u "
			   "http_status=%u error=%d\n",
			   result->result, result->http_status, result->error);
		break;
	case EVP_BLOB_CALLBACK_REASON_EXIT:
		assert(vp == NULL);
		log_module(module_vars->instance_name,
			   "EVP_BLOB_CALLBACK_REASON_EXIT\n");
		break;
	default:
		assert(0);
	}

	module_vars->upload_done = true;
	log_module(module_vars->instance_name,
		   "Delete file after upload it\n");
	int ret = unlink(module_vars->localStore.filename);
	assert(ret == 0);
}

static int
create_local_file(module_vars_t *module_vars)
{
	int ret;

	// Local file
	const char *workspace = EVP_getWorkspaceDirectory(
		module_vars->h, EVP_WORKSPACE_TYPE_DEFAULT);
	log_module(module_vars->instance_name, "The default workspace: %s\n",
		   workspace);

	ret = asprintf(&module_vars->abs_filename, "%s/%s", workspace,
		       module_vars->filename);

	if ((ret < 0) || (ret > PATH_MAX)) {
		log_module(module_vars->instance_name,
			   "ERROR: It is not possible to create the filename. "
			   "err %d\n",
			   ret);
		goto end;
	}

	if (access(module_vars->abs_filename, F_OK) == 0) {
		log_module(module_vars->instance_name,
			   "The file %s already exists. It will be reused.",
			   module_vars->abs_filename);
		ret = 0;
		goto end;
	}

	log_module(module_vars->instance_name,
		   "The file %s will be generated\n",
		   module_vars->abs_filename);

	FILE *fp = fopen(module_vars->abs_filename, "w");
	if (fp == NULL) {
		ret = errno;
		log_module(module_vars->instance_name,
			   "Failed to open %s with errno %d\n",
			   module_vars->abs_filename, ret);
		goto end;
	}

	char buff[128];
	memset(buff, 'k', sizeof(buff));
	for (int i = 0; i < (FILE_SIZE / sizeof(buff)); i++) {
		size_t nobj = fwrite(buff, sizeof(buff), 1, fp);
		if (nobj != 1) {
			log_module(module_vars->instance_name,
				   "ERROR: Error writing to the file. nobj is "
				   "%zu\n",
				   nobj);
			ret = EIO;
			goto end;
		}
	}

	ret = fclose(fp);
	if (ret != 0) {
		log_module(module_vars->instance_name,
			   "ERROR: Error closing file");
		goto end;
	}

	log_module(module_vars->instance_name,
		   "The file %s has been generated correctly\n",
		   module_vars->abs_filename);

	return 0;

end:
	free(module_vars->abs_filename);
	module_vars->abs_filename = NULL;
	return ret;
}

int
main(void)
{
	/* Init vars */
	int ret = 0;
	module_vars_t module_vars = {.filename = "test.txt",
				     .instance_name = strdup(module_name)};

	struct EVP_client *h = EVP_initialize();
	if (h == NULL) {
		log_module(module_vars.instance_name,
			   "Error initializing the instance. Aborting.");
		exit(1);
	}
	module_vars.h = h;

	EVP_setConfigurationCallback(h, config_cb, (void *)&module_vars);

	for (;;) {
		EVP_RESULT result;

		result = EVP_processEvent(h, 1000);
		if (result == EVP_SHOULDEXIT) {
			break;
		}

		/* Generate the file (if it doesn't already exist) */
		if (module_vars.abs_filename == NULL) {
			log_module(module_vars.instance_name,
				   "Creating the upload file\n");
			if (create_local_file(&module_vars) != 0) {
				log_module(module_vars.instance_name,
					   "ERROR: Error creating the new "
					   "file. Exiting\n");
				ret = 1;
				break;
			}
		}

		if (module_vars.abs_filename != NULL &&
		    module_vars.storage_name != NULL &&
		    !module_vars.upload_requested) {
			module_vars.upload_requested = true;

			log_module(module_vars.instance_name,
				   "Uploading a blob\n");

			struct EVP_BlobRequestEvpExt request;
			request.remote_name = module_vars.filename;
			request.storage_name = module_vars.storage_name;

			module_vars.localStore.filename =
				module_vars.abs_filename;

			result = EVP_blobOperation(h, EVP_BLOB_TYPE_EVP_EXT,
						   EVP_BLOB_OP_PUT, &request,
						   &module_vars.localStore,
						   blob_cb, &module_vars);

			if (result != EVP_OK) {
				log_module(module_vars.instance_name,
					   "ERROR: Error %d in blob "
					   "operation. Exiting\n",
					   result);
				ret = result;
				break;
			}
		}
	}

	/* free buffers */
	free(module_vars.instance_name);
	free(module_vars.abs_filename);
	free(module_vars.storage_name);
	return ret;
}
