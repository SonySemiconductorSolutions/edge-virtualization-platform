/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "evp/sdk.h"
#include "log.h"

static const char *module_name = "THREADING";
static const char chunk[] = "bye";

struct telemetry_data {
	struct EVP_telemetry_entry entries[1];
};

struct thread_args {
	pthread_mutex_t mutex;
	char buffer[128];
};

static void *
thread_routine(void *arg)
{
	struct thread_args *a = arg;
	int error = pthread_mutex_lock(&a->mutex);

	if (error != 0) {
		log_module(module_name, "%s: pthread_mutex_lock: %s\n",
			   __func__, strerror(error));
		return NULL;
	}

	log_module(module_name, "Enter thread\n");
	log_module(module_name, "buffer before '%s'\n", a->buffer);
	strcat(a->buffer, chunk);
	log_module(module_name, "buffer after '%s'\n", a->buffer);

	error = pthread_mutex_unlock(&a->mutex);

	if (error != 0) {
		log_module(module_name, "%s: pthread_mutex_unlock: %s\n",
			   __func__, strerror(error));
		return NULL;
	}

	return a->buffer;
}

static void
telemetry_cb(EVP_TELEMETRY_CALLBACK_REASON reason, void *userData)
{
	assert(userData != NULL);
	struct telemetry_data *d = userData;
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
	log_module(module_name, "telemetry-echo: Telemetry Sent (reason=%s)\n",
		   reasonText);
}

int
main(void)
{
	EVP_RESULT result;

	/* wasm-micro-runtime assigns a hardcoded limit of maximum
	 * threads per cluster, namely CLUSTER_MAX_THREAD_NUM.
	 * As of the time of this writing, it is limited to 4.
	 * Apparently, the main thread is not included. */
	pthread_t tid[4];
	bool tid_init[sizeof(tid) / sizeof(*tid)] = {0};

	struct thread_args args = {.mutex = PTHREAD_MUTEX_INITIALIZER};

	int ret = EXIT_FAILURE;

	log_module(module_name, "%s: started!\n", module_name);
	struct EVP_client *h = EVP_initialize();

	if (h == NULL) {
		log_module(module_name, "%s: EVP_initialize failed\n",
			   module_name);
		goto end;
	}

	for (size_t i = 0; i < sizeof(tid) / sizeof(*tid); i++) {
		pthread_attr_t attr;
		int rc = pthread_attr_setstacksize(&attr, 8192);
		if (rc != 0) {
			log_module(module_name,
				   "pthread_attr_setstack returned: %d\n", rc);
			goto end;
		}
		int error =
			pthread_create(&tid[i], &attr, thread_routine, &args);

		if (error) {
			log_module(module_name,
				   "%s: pthread_create thread %zu: %s\n",
				   module_name, i, strerror(error));
			goto end;
		}

		tid_init[i] = true;
	}

	log_module(module_name, "%s: exiting the main loop\n", module_name);

	for (size_t i = 0; i < sizeof(tid) / sizeof(*tid); i++) {
		void *buf;
		int error = pthread_join(tid[i], &buf);

		if (error) {
			log_module(module_name,
				   "%s: pthread_join thread %zu: %s\n",
				   module_name, i, strerror(error));
			goto end;
		}
	}

	log_module(module_name, "string is: '%s'\n", args.buffer);

	for (size_t i = 0; i < sizeof(tid) / sizeof(*tid); i++) {
		size_t len = strlen(chunk);
		if (strncmp(args.buffer, chunk, len)) {
			log_module(module_name, "%s: expected %s, got %.*s\n",
				   module_name, chunk, (int)len, args.buffer);
			goto end;
		}
	}

	// Send telemetry to notify the result
	struct telemetry_data *d = malloc(sizeof(*d));

	*d = (struct telemetry_data){
		.entries[0] = {.key = "test", .value = "31337"}};

	EVP_sendTelemetry(h, d->entries, 1, telemetry_cb, d);

	result = EVP_processEvent(h, 10000);
	log_module(module_name, "EVP_processEvent returned %u\n", result);

	log_module(module_name, "Exit\n");
	ret = EXIT_SUCCESS;

end:

	for (size_t i = 0; i < sizeof(tid) / sizeof(*tid); i++) {
		if (!tid_init[i])
			continue;

		int error = pthread_mutex_destroy(&args.mutex);

		if (error != 0) {
			fprintf(stderr,
				"%s: pthread_mutex_destroy thread "
				"%zu: %s\n",
				module_name, i, strerror(error));
			ret = EXIT_FAILURE;
		}
	}

	return ret;
}
