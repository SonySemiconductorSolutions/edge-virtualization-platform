/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "evp/sdk.h"
#include "log.h"

static char *g_topic = NULL;
static void *g_blob = NULL;
static size_t g_blob_len;

static const char *module_name = "CONFIG-ECHO";

struct data {
	char *topic;
	void *blob;
};

static void
config_cb(const char *topic, const void *config, size_t configlen,
	  void *userData)
{
	log_module(module_name,
		   "%s: Received Configuration (topic=%s, size=%zu)\n",
		   module_name, topic, configlen);

	free(g_blob);
	free(g_topic);

	/* Note: +1 to avoid 0-sized malloc */
	g_blob = malloc(configlen + 1);
	assert(g_blob != NULL);
	memcpy(g_blob, config, configlen);
	g_topic = strdup(topic);
	assert(g_topic != NULL);
	g_blob_len = configlen;
}

static void
state_cb(EVP_STATE_CALLBACK_REASON reason, void *userData)
{
	log_module(module_name, "%s: state_cb called reason=%u\n", module_name,
		   (unsigned int)reason);
	assert(userData != NULL);
	struct data *d = userData;
	assert(d->topic != NULL);
	assert(d->blob != NULL);
	free(d->topic);
	free(d->blob);
	free(d);
}

int
main(void)
{
	log_module(module_name, "%s: started!\n", module_name);
	struct EVP_client *h = EVP_initialize();
	EVP_setConfigurationCallback(h, config_cb, (void *)0x1234);

	for (;;) {
		log_module(module_name, "%s: main loop\n", module_name);
		EVP_RESULT result;

		result = EVP_processEvent(h, 1000);
		log_module(module_name, "EVP_processEvent returned %u\n",
			   result);
		if (result == EVP_SHOULDEXIT) {
			log_module(module_name, "%s: exiting the main loop\n",
				   module_name);
			free(g_topic);
			free(g_blob);
			g_topic = NULL;
			g_blob = NULL;
			break;
		}

		if (g_blob) {
			struct data *d = malloc(sizeof(*d));
			assert(d != NULL);
			d->topic = g_topic;
			d->blob = g_blob;
			log_module(module_name,
				   "%s: Sending State (topic=%s, size=%zu)\n",
				   module_name, g_topic, g_blob_len);
			result = EVP_sendState(h, g_topic, g_blob, g_blob_len,
					       state_cb, d);
			assert(result == EVP_OK);
			g_topic = NULL;
			g_blob = NULL;
		}
	}
	return 0;
}
