/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <string.h>

#include <evp/sdk.h>
#include <evp/sdk_sys.h>

#include "../xlog.h"
#include "sys_common.h"

static const enum SYS_result table[] = {
	[EVP_OK] = SYS_RESULT_OK,
	[EVP_SHOULDEXIT] = SYS_RESULT_SHOULD_EXIT,
	[EVP_TIMEDOUT] = SYS_RESULT_TIMEDOUT,
	[EVP_ERROR] = SYS_RESULT_ERROR_BAD_PARAMS,
	[EVP_INVAL] = SYS_RESULT_ERROR_BAD_PARAMS,
	[EVP_NOMEM] = SYS_RESULT_ERROR_NO_MEM,
	[EVP_TOOBIG] = SYS_RESULT_ERROR_BAD_PARAMS,
	[EVP_AGAIN] = SYS_RESULT_ERROR_BAD_PARAMS,
	[EVP_AGENT_PROTOCOL_ERROR] = SYS_RESULT_ERROR_BAD_PARAMS,
	[EVP_EXIST] = SYS_RESULT_ERROR_ALREADY_REGISTERED,
	[EVP_FAULT] = SYS_RESULT_ERROR_BAD_PARAMS,
	[EVP_DENIED] = SYS_RESULT_ERROR_BAD_PARAMS,
	[EVP_NOTSUP] = SYS_RESULT_ERROR_BAD_PARAMS,
};

enum SYS_result
sys_to_sys_result(EVP_RESULT result)
{
	return table[result];
}

int
sys_add_headers(struct EVP_BlobRequestHttpExt *req,
		const struct SYS_http_header *headers)
{
	for (const struct SYS_http_header *h = headers;
	     h && h->key && h->value; h++) {

		EVP_RESULT result = EVP_BlobRequestHttpExt_addHeader(
			req, h->key, h->value);

		if (result != EVP_OK) {
			xlog_error("EVP_BlobRequestHttpExt_addHeader failed "
				   "with %u",
				   (unsigned int)result);
			return -1;
		}
	}
	return 0;
}
