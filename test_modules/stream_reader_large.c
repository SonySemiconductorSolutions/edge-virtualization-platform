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
#include <time.h>
#include <unistd.h>

#include "evp/sdk.h"
#include "log.h"

#define MODULE_NAME "STREAM-READER-LARGE"

static bool got_response, finished;

struct tm_ms {
	char buf[sizeof "00:00:00.000"];
};

static int
fmt_time_ms(struct tm_ms *t)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_REALTIME, &ts)) {
		log_module(MODULE_NAME, "%s: clock_gettime failed\n",
			   __func__);
		return -1;
	}

	const struct tm *tm = localtime(&ts.tv_sec);
	size_t n = strftime(t->buf, sizeof(t->buf), "%H:%M:%S", tm);
	if (!n) {
		log_module(MODULE_NAME, "%s: strftime(3) failed\n", __func__);
		return -1;
	}

	long ms = ts.tv_nsec / 1000000l;
	int nn = snprintf(&t->buf[n], sizeof(t->buf) - n, ".%03ld", ms);
	if (nn < 0 || nn >= sizeof(t->buf) - n) {
		log_module(MODULE_NAME, "%s: snprintf(3) failed with %d\n",
			   __func__, nn);
		return -1;
	}
	return 0;
}

static void
read_cb(EVP_STREAM_PEER_ID id, const void *buf, size_t n, void *userdata)
{
	int *received_messages = userdata;
	struct tm_ms t;
	if (fmt_time_ms(&t)) {
		log_module(MODULE_NAME, "%s: fmt_time_ms failed\n", __func__);
		return;
	}

	log_module(MODULE_NAME, "[%s]: id=%lx,buf=%p,n=%zu\n", t.buf, id, buf,
		   n);
	(*received_messages)++;

#ifdef STREAM_READER_PRINT_MSG_CONTENTS
	log_module(module_name, "id=%lx:\n{", id);

	for (size_t i = 0; i < n; i++) {
		log_module(module_name, "%#hhx", ((const char *)buf)[i]);
		if (i + 1 < n) {
			puts(", ");
			printf
		}
	}

	puts("}\n");
#endif
	got_response = true;
}

static void
state_cb(EVP_STATE_CALLBACK_REASON reason, void *userData)
{
	if (reason != EVP_STATE_CALLBACK_REASON_SENT) {
		log_module(MODULE_NAME, "%s: unexpected reason %d\n", __func__,
			   reason);
	}

	finished = true;
}

int
main(void)
{
	int received_messages = 0;
	int ret = EXIT_FAILURE;
	EVP_RESULT result;
	EVP_STREAM stream = -1;
	struct EVP_client *h = EVP_initialize();

	if (h == NULL) {
		log_module(MODULE_NAME, "EVP_initialize failed\n");
		goto end;
	}

	result = EVP_streamInputOpen(h, "in-video-stream", read_cb,
				     &received_messages, &stream);
	if (result != EVP_OK) {
		log_module(MODULE_NAME,
			   "EVP_streamInputOpen failed with error %d\n",
			   result);
		goto end;
	}

	for (;;) {
		EVP_RESULT result = EVP_processEvent(h, 100);

		if (result == EVP_SHOULDEXIT) {
			break;
		} else if (finished) {
			;
		} else if (got_response) {
			static const char state[] = "stream-read-ok";

			got_response = false;
			result = EVP_sendState(h, "done", state, strlen(state),
					       state_cb, NULL);
			if (result != EVP_OK) {
				log_module(
					MODULE_NAME,
					"EVP_sendState failed with error %d\n",
					result);
				goto end;
			}
		}
	}

	ret = EXIT_SUCCESS;

end:
	if (stream >= 0) {
		result = EVP_streamClose(h, stream);
		if (result != EVP_OK) {
			log_module(MODULE_NAME,
				   "EVP_streamClose failed with error %d\n",
				   result);
			ret = EXIT_FAILURE;
		}
	}

	log_module(MODULE_NAME, "Exiting module with exit status %d\n", ret);
	log_module(MODULE_NAME, "Received %d messages\n", received_messages);
	return ret;
}
