/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MODELS_MSTP_H__
#define MODELS_MSTP_H__

#include <stddef.h>

#include "../certificates.h"
#include "evp/sdk_types.h"

enum storagetoken_response_type {
	STORAGETOKEN_RESPONSE_TYPE_SINGLE_FILE,
	STORAGETOKEN_RESPONSE_TYPE_MULTI_FILE,
};

struct storagetoken_response {
	int status;  /* Response ok is 0, otherwise the error code */
	char *error; /* only valid if status !0 */

	/* Fields below are only valid if status == 0 */
	char *url;
	char **headers;
	unsigned int headers_len;
	uint64_t expiration_ms;
	enum storagetoken_response_type resp_type;
};

void storagetoken_response_ctor(struct storagetoken_response *data, int status,
				const char *error, const char *url,
				uint64_t expiration_ms,
				enum storagetoken_response_type resp_type);

void storagetoken_response_dtor(struct storagetoken_response *data);

int storagetoken_response_add_header(struct storagetoken_response *data,
				     const char *name, const char *value);

#endif
