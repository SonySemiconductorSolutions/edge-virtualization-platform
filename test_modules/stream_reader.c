/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "evp/sdk.h"
#include "log.h"

static bool got_response, finished;

static const char *module_name = "STREAM-READER";

static void
read_cb(EVP_STREAM_PEER_ID id, const void *buf, size_t n, void *userdata)
{
	log_module(module_name, "id=%lx: %.*s\n", id, (int)n,
		   (const char *)buf);
	got_response = true;
}

static void
state_cb(EVP_STATE_CALLBACK_REASON reason, void *userData)
{
	if (reason != EVP_STATE_CALLBACK_REASON_SENT) {
		log_module(module_name, "%s: unexpected reason %d\n", __func__,
			   reason);
	}

	finished = true;
}

int
main(void)
{
	int ret = EXIT_FAILURE;
	EVP_RESULT result;
	EVP_STREAM stream = -1;
	struct EVP_client *h = EVP_initialize();

	if (h == NULL) {
		log_module(module_name, "EVP_initialize failed\n");
		goto end;
	}

	result = EVP_streamInputOpen(h, "in-video-stream", read_cb, NULL,
				     &stream);
	if (result != EVP_OK) {
		log_module(module_name,
			   "EVP_streamInputOpen failed with error %d\n",
			   result);
		goto end;
	}

	for (;;) {
		EVP_RESULT result = EVP_processEvent(h, 1000);

		if (result == EVP_SHOULDEXIT) {
			break;
		} else if (finished) {
			break;
		} else if (got_response) {
			static const char state[] = "stream-read-ok";

			got_response = false;
			result = EVP_sendState(h, "done", state, strlen(state),
					       state_cb, NULL);
			if (result != EVP_OK) {
				fprintf(stderr,
					"EVP_sendState failed with error %d\n",
					result);
				goto end;
			}
		}
	}

	ret = EXIT_SUCCESS;

end:
	log_module(module_name, "Exiting module\n");

	if (stream >= 0) {
		result = EVP_streamClose(h, stream);
		if (result != EVP_OK) {
			fprintf(stderr,
				"EVP_streamClose failed with error %d\n",
				result);
			ret = EXIT_FAILURE;
		}
	}

	return ret;
}
