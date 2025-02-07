/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE /* asprintf */
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "evp/sdk.h"
#include "log.h"

/* some data shared with main and callbacks */
struct context {
	char *filename;
	char *data;
	int step;
};

static const char *module_name = "FILE-WRITER";

struct state_cb_data {
	char *blob;
};

static void
config_cb(const char *topic, const void *config, size_t configlen,
	  void *userData)
{
	log_module(module_name,
		   "%s: Received Configuration (topic=%s, size=%zu)\n",
		   module_name, topic, configlen);

	char **varp;
	struct context *ctx = userData;

	if (!strcmp(topic, "filename")) {
		varp = &ctx->filename;
	} else if (!strcmp(topic, "data")) {
		varp = &ctx->data;
	} else {
		log_module(module_name,
			   "%s: Ignoring Configuration with unknown topic "
			   "(topic=%s, size=%zu)\n",
			   module_name, topic, configlen);
		return;
	}

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

int
main(void)
{
	struct context ctx;

	EVP_RESULT result;
	ctx.filename = NULL;
	ctx.data = NULL;
	ctx.step = 0;
	int reported_step = -1;

	struct EVP_client *h = EVP_initialize();
	result = EVP_setConfigurationCallback(h, config_cb, &ctx);
	assert(result == EVP_OK);
	const char *workspace =
		EVP_getWorkspaceDirectory(h, EVP_WORKSPACE_TYPE_DEFAULT);
	assert(workspace != NULL);
	log_module(module_name, "%s: the default workspace: %s\n", module_name,
		   workspace);

	/*
	 * g_step = 0: wait for Configurations
	 * g_step = 1000: success
	 */

	for (;;) {
		result = EVP_processEvent(h, 1000);
		if (result == EVP_SHOULDEXIT) {
			/*
			 * free the context
			 */
			free(ctx.filename);
			free(ctx.data);
			break;
		}
		assert(result == EVP_OK || result == EVP_TIMEDOUT);
		if (ctx.filename != NULL && ctx.data != NULL &&
		    ctx.step == 0) {
			char local_filename[PATH_MAX];
			snprintf(local_filename, sizeof(local_filename),
				 "%s/%s", workspace, ctx.filename);
			log_module(module_name, "%s: local_filename: %s\n",
				   module_name, local_filename);
			FILE *fp = fopen(local_filename, "w");
			assert(fp != NULL);
			size_t nobj =
				fwrite(ctx.data, strlen(ctx.data), 1, fp);
			assert(nobj == 1);
			int ret = fclose(fp);
			assert(ret == 0);
			log_module(module_name, "%s: SUCCESS!\n", module_name);
			ctx.step = 1000;
		}
		if (reported_step != ctx.step) {
			const char *topic = "status";
			struct state_cb_data *d = malloc(sizeof(*d));
			assert(d != NULL);
			int ret = asprintf(&d->blob, "g_step = %u", ctx.step);
			assert(ret != -1);
			size_t blob_len = ret;
			log_module(module_name,
				   "%s: Sending State (topic=%s, size=%zu)\n",
				   module_name, topic, blob_len);
			result = EVP_sendState(h, topic, d->blob, blob_len,
					       state_cb, d);
			assert(result == EVP_OK);
			reported_step = ctx.step;
		}
	}
	return 0;
}
