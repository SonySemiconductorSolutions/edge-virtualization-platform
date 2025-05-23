/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE

#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "evp/sdk.h"
#include "log.h"

#define MESSAGE_SIZE      (2048)
#define MESSAGE_PERIOD_MS (100)

struct tm_ms {
	char buf[sizeof "00:00:00.000"];
};

static char stream_buffer[MESSAGE_SIZE];
static const char *module_name = "STREAM-WRITER-LARGE";

static int
fmt_time_ms(struct tm_ms *t)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_REALTIME, &ts)) {
		log_module(module_name, "%s: clock_gettime failed\n",
			   __func__);
		return -1;
	}

	const struct tm *tm = localtime(&ts.tv_sec);
	size_t n = strftime(t->buf, sizeof(t->buf), "%H:%M:%S", tm);
	if (!n) {
		log_module(module_name, "%s: strftime(3) failed\n", __func__);
		return -1;
	}

	long ms = ts.tv_nsec / 1000000l;
	int nn = snprintf(&t->buf[n], sizeof(t->buf) - n, ".%03ld", ms);
	if (nn < 0 || nn >= sizeof(t->buf) - n) {
		log_module(module_name, "%s: snprintf(3) failed with %d\n",
			   __func__, nn);
		return -1;
	}
	return 0;
}

static int
print_msg(size_t sz)
{
	struct tm_ms t;
	if (fmt_time_ms(&t)) {
		log_module(module_name, "%s: fmt_time_ms failed\n", __func__);
		return -1;
	}

	log_module(module_name, "[%s]: sent %zu bytes\n", t.buf, sz);
	return 0;
}

int
main(void)
{
	int sent_messages = 0;
	int ret = EXIT_FAILURE;
	EVP_RESULT result;
	EVP_STREAM stream = -1;
	struct EVP_client *h = EVP_initialize();

	srand(time(NULL));

	if (h == NULL) {
		log_module(module_name, "EVP_initialize failed\n");
		goto terminate;
	}

	do {
		result = EVP_streamOutputOpen(h, "out-video-stream", &stream);
		if (result != EVP_OK) {
			const int retry_seconds = 2;
			fprintf(stderr,
				"EVP_streamOutputOpen failed with error %d. "
				"Trying again in %d seconds.\n",
				result, retry_seconds);

			result = EVP_processEvent(h, retry_seconds * 1000);
			if (result == EVP_SHOULDEXIT) {
				goto terminate;
			}
			log_module(module_name, "Reconnecting...\n");
		}

	} while (result != EVP_OK);

	for (;;) {
		EVP_RESULT result = EVP_processEvent(h, MESSAGE_PERIOD_MS);

		if (result == EVP_SHOULDEXIT) {
			break;
		}

		if (result == EVP_TIMEDOUT) {

			for (size_t i = 0; i < sizeof(stream_buffer) /
						       sizeof(*stream_buffer);
			     i++) {
				stream_buffer[i] = rand() % (UCHAR_MAX + 1);
			}

			result = EVP_streamWrite(h, stream, stream_buffer,
						 sizeof(stream_buffer));
			if (result != EVP_OK) {
				fprintf(stderr,
					"EVP_streamWrite failed with error "
					"%d\n",
					result);
				goto close;
			}

			if (print_msg(sizeof(stream_buffer))) {
				log_module(module_name, "print_msg failed\n");
				goto close;
			}

			sent_messages++;
		}
	}

	ret = EXIT_SUCCESS;

close:
	if (stream >= 0) {
		result = EVP_streamClose(h, stream);
		if (result != EVP_OK) {
			fprintf(stderr,
				"EVP_streamClose failed with error %d\n",
				result);
			ret = EXIT_FAILURE;
		}
	}

terminate:
	log_module(module_name, "Exiting module with exit status %d\n", ret);
	log_module(module_name, "Sent %d messages\n", sent_messages);
	return ret;
}
