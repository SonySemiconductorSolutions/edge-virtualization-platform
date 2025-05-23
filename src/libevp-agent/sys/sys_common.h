/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SYS_COMMON_H_
#define SYS_COMMON_H_

#include <stdbool.h>
#include <stddef.h>

#include <evp/sdk.h>
#include <evp/sdk_sys.h>

enum SYS_result sys_to_sys_result(EVP_RESULT result);

int sys_add_headers(struct EVP_BlobRequestHttpExt *req,
		    const struct SYS_http_header *headers);
#endif
