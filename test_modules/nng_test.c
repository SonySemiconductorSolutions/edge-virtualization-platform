/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <nng/nng.h>
#include <nng/protocol/pipeline0/pull.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "evp/sdk.h"

int
main(void)
{
	int ret = EXIT_FAILURE;
	int error;
	nng_socket s = {0};
	nng_listener l = {0};
	struct EVP_client *h = EVP_initialize();

	if (h == NULL) {
		log_module(module_name, "EVP_initialize failed\n");
		goto end;
	}

	error = nng_pull0_open(&s);
	if (error != 0) {
		log_module(module_name, "nng_pull0_open failed: %s\n",
			   nng_strerror(error));
		goto end;
	}

	error = nng_listener_create(&l, s, "tcp://127.0.0.1:9090");
	if (error != 0) {
		log_module(module_name, "nng_dialer_create failed: %s\n",
			   nng_strerror(error));
		goto end;
	}

	error = nng_listener_start(l, 0);
	if (error != 0) {
		log_module(module_name, "nng_listener_create failed: %s\n",
			   nng_strerror(error));
		goto end;
	}

	for (;;) {
		EVP_RESULT result = EVP_processEvent(h, 1000);

		if (result == EVP_SHOULDEXIT) {
			break;
		}
	}

	ret = EXIT_SUCCESS;

end:
	if (l.id != 0) {
		error = nng_listener_close(l);
		if (error != 0) {
			log_module(module_name,
				   "nng_listener_close failed: %s\n",
				   nng_strerror(error));
			ret = EXIT_FAILURE;
		}
	}

	if (s.id != 0) {
		error = nng_close(s);
		if (error != 0) {
			log_module(module_name, "nng_close failed: %s\n",
				   nng_strerror(error));
			ret = EXIT_FAILURE;
		}
	}

	return ret;
}
