/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mbedtls/error.h>
#include <mbedtls/version.h>
#include <mbedtls/x509_crt.h>

#include <internal/evp_config.h>

#include "blob.h"
#include "blob_http.h"
#include "blob_type_azure_blob.h"
#include "https_ssl_config.h"
#include "tls.h"
#include "xlog.h"

static unsigned int
azure_http_get(struct blob_work *wk, int fd)
{
	return blob_http_get(wk, fd, NULL, 0, https_ssl_config());
}

static unsigned int
azure_http_put(struct blob_work *wk, int fd)
{
	const char *const headers[] = {
		"x-ms-blob-type: BlockBlob",
	};

	return blob_http_put(wk, fd, headers, 1, https_ssl_config());
}

unsigned int
blob_type_azure_blob_get(struct blob_work *wk)
{
	return blob_get(wk, azure_http_get);
}

unsigned int
blob_type_azure_blob_put(struct blob_work *wk)
{
	return blob_put(wk, azure_http_put);
}
