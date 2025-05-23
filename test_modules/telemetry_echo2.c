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
static char *g_blob_str = NULL;
static size_t g_blob_len;

struct telemetry_data {
	struct EVP_telemetry_entry entries[1];
};

static const char *module_name = "TELEMETRY-ECHO";

static void
config_cb(const char *topic, const void *config, size_t configlen,
	  void *userData)
{
	log_module(module_name,
		   "Received Configuration (topic=%s, "
		   "size=%zu)\n",
		   topic, configlen);

	free(g_blob_str);
	free(g_topic);

	g_blob_str = malloc(configlen + 1);
	assert(g_blob_str != NULL);
	memcpy(g_blob_str, config, configlen);
	g_blob_str[configlen] = '\0';
	g_topic = strdup(topic);
	assert(g_topic != NULL);
	g_blob_len = configlen;
}

static void
telemetry_cb(EVP_TELEMETRY_CALLBACK_REASON reason, void *userData)
{
	assert(userData != NULL);
	struct telemetry_data *d = userData;
	assert(d->entries[0].key != NULL);
	assert(d->entries[0].value != NULL);
	free((void *)d->entries[0].key);   /* discard const */
	free((void *)d->entries[0].value); /* discard const */
	free(d);

	char *reasonText;
	switch (reason) {
	case EVP_TELEMETRY_CALLBACK_REASON_SENT:
		reasonText = "SENT";
		break;
	case EVP_TELEMETRY_CALLBACK_REASON_ERROR:
		reasonText = "ERROR";
		break;
	case EVP_TELEMETRY_CALLBACK_REASON_EXIT:
		reasonText = "EXIT";
		break;
	default:
		assert(0);
	}
	log_module(module_name, "Telemetry Sent (reason=%s)\n", reasonText);
}

int
main(void)
{
	struct EVP_client *h = EVP_initialize();
	EVP_setConfigurationCallback(h, config_cb, (void *)0x1234);

	for (;;) {
		EVP_RESULT result;

		result = EVP_processEvent(h, 1000);
		if (result == EVP_SHOULDEXIT) {
			free(g_topic);
			free(g_blob_str);
			g_topic = NULL;
			g_blob_str = NULL;
			break;
		}

		if (g_blob_str) {
			log_module(module_name,
				   "Sending Telemetry "
				   "(key=%s, value=%s)\n",
				   g_topic, g_blob_str);

			struct telemetry_data *d = malloc(sizeof(*d));
			assert(d != NULL);
			d->entries[0].key = g_topic;
			d->entries[0].value = g_blob_str;
			result = EVP_sendTelemetry(h, d->entries, 1,
						   telemetry_cb, d);
			assert(result == EVP_OK);
			g_topic = NULL;
			g_blob_str = NULL;
		}
	}
	return 0;
}
