/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE /* asprintf */
#include <assert.h>
#include <errno.h>
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
	size_t datalen;
	int step;
};

static const char *module_name = "FILE-READER";

struct state_cb_data {
	char *blob;
	struct context *ctx;
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

	struct context *ctx = d->ctx;
	if (ctx != NULL) {
		assert(ctx->step == 3);
		ctx->step = 4;
	}

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
	 * g_step = 2: finished reading the file. (success or ENOENT)
	 * g_step = 3: reporting data (EVP_sendState called)
	 * g_step = 4: reporting data (completed)
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
		if (ctx.filename != NULL && ctx.step == 0) {
			char local_filename[PATH_MAX];
			snprintf(local_filename, sizeof(local_filename),
				 "%s/%s", workspace, ctx.filename);
			log_module(module_name, "%s: local_filename: %s\n",
				   module_name, local_filename);
			const size_t max_size = 1000; /* enough for testing */
			ctx.data = malloc(max_size);
			assert(ctx.data != NULL);
			FILE *fp = fopen(local_filename, "r");
			if (fp == NULL) {
				free(ctx.data);
				if (errno == ENOENT
#if defined(__NuttX__) || defined(__wasm__)
				    || errno == EBADF /* hostfs for NuttX */
#endif
				) {
					log_module(module_name,
						   "%s: errno %d\n",
						   module_name, errno);
					const char *msg = "ENOENT";
					ctx.data = strdup(msg);
					assert(ctx.data != NULL);
					ctx.datalen = strlen(msg);
				} else {
					log_module(module_name,
						   "%s: unexpected errno %d\n",
						   module_name, errno);
					return 1;
				}
			} else {
				assert(fp != NULL);
				size_t nobj = fread(ctx.data, 1, max_size, fp);
				assert(nobj <= max_size);
				assert(nobj > 0);
				ctx.datalen = nobj;
				int ret = fclose(fp);
				assert(ret == 0);
			}
			ctx.step = 2;
		}
		if (ctx.step == 2) {
			const char *topic = "data";
			struct state_cb_data *d = malloc(sizeof(*d));
			assert(d != NULL);
			d->ctx = &ctx;
			d->blob = ctx.data;
			ctx.data = NULL;
			size_t blob_len = ctx.datalen;
			log_module(module_name,
				   "%s: Sending State (topic=%s, size=%zu)\n",
				   module_name, topic, blob_len);
			result = EVP_sendState(h, topic, d->blob, blob_len,
					       state_cb, d);
			assert(result == EVP_OK);
			ctx.step = 3;
		}
		if (ctx.step == 4) {
			log_module(module_name, "%s: SUCCESS!\n", module_name);
			ctx.step = 1000;
		}
		if (reported_step != ctx.step) {
			const char *topic = "status";
			struct state_cb_data *d = malloc(sizeof(*d));
			assert(d != NULL);
			d->ctx = NULL;
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
