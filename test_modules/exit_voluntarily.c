/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "evp/sdk.h"
#include "log.h"

static const char *module_name = "exit-voluntarily";

struct data {
	bool config_received;
	bool state_sent;
	char *topic;
	void *blob;
	size_t bloblen;
};

static void
config_cb(const char *topic, const void *config, size_t configlen,
	  void *userData)
{
	char *topicdup = NULL;
	void *blobdup = NULL;
	struct data *d = userData;

	log_module(module_name,
		   "%s: Received Configuration (topic=%s, size=%zu)\n",
		   module_name, topic, configlen);

	topicdup = strdup(topic);
	if (topicdup == NULL) {
		log_module(module_name, "%s: strdup(3): %s\n", __func__,
			   strerror(errno));
		goto failure;
	}

	blobdup = malloc(configlen);
	if (blobdup == NULL) {
		log_module(module_name, "%s: malloc(3): %s\n", __func__,
			   strerror(errno));
		goto failure;
	}

	memcpy(blobdup, config, configlen);

	*d = (struct data){.blob = blobdup,
			   .topic = topicdup,
			   .bloblen = configlen,
			   .config_received = true};

	return;

failure:
	free(blobdup);
	free(topicdup);
}

static void
free_data(struct data *d)
{
	if (d == NULL)
		return;

	free(d->blob);
	free(d->topic);
}

static void
state_cb(EVP_STATE_CALLBACK_REASON reason, void *userData)
{
	struct data *d = userData;

	log_module(module_name, "%s:%d, reason=%d, userData=%p\n", __func__,
		   __LINE__, reason, userData);
	free_data(d);
	d->state_sent = true;
}

int
main(void)
{
	struct data d = {0};
	struct EVP_client *h = EVP_initialize();
	EVP_setConfigurationCallback(h, config_cb, &d);

	for (;;) {
		EVP_RESULT result;

		result = EVP_processEvent(h, 1000);
		if (result == EVP_SHOULDEXIT) {
			free_data(&d);
			break;
		} else if (d.state_sent) {
			/* exit voluntarily */
			break;
		} else if (d.config_received) {
			result = EVP_sendState(h, d.topic, d.blob, d.bloblen,
					       state_cb, &d);
			assert(result == EVP_OK);
		}
	}
	return 0;
}
