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

static const char *module_name = "ZOMBIE";

int
main(void)
{
	log_module(module_name, "%s: started!\n", module_name);
	struct EVP_client *h = EVP_initialize();

	for (;;) {
		log_module(module_name, "%s: main loop\n", module_name);
		EVP_RESULT result;

		result = EVP_processEvent(h, 1000);
		log_module(module_name, "EVP_processEvent returned %u\n",
			   result);
		if (result == EVP_SHOULDEXIT) {
			log_module(module_name,
				   "%s: received exit request. But ignoring "
				   "for 2 min :evil:\n",
				   module_name);
			sleep(120);
			break;
		}
	}
	return 0;
}
