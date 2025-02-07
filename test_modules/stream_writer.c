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

static const char *module_name = "STREAM-WRITER";

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

	result = EVP_streamOutputOpen(h, "out-video-stream", &stream);
	if (result != EVP_OK) {
		log_module(module_name,
			   "EVP_streamOutputOpen failed with error %d\n",
			   result);
		goto end;
	}

	for (;;) {
		EVP_RESULT result = EVP_processEvent(h, 1000);

		if (result == EVP_SHOULDEXIT) {
			break;
		}

		if (result == EVP_TIMEDOUT) {
			static const char buf[] = "test\n";

			result = EVP_streamWrite(h, stream, buf, strlen(buf));
			if (result != EVP_OK) {
				fprintf(stderr,
					"EVP_streamWrite failed with error "
					"%d\n",
					result);
			} else {
				break;
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
