/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if !defined(__SDK_BLOB_HTTP_H__)
#define __SDK_BLOB_HTTP_H__

#if defined(__cplusplus)
extern "C" {
#endif

/** @file */

/**
 * @brief A blob operation request for ordinary HTTP server.
 */
struct EVP_BlobRequestHttp {
	/**
	 * URL for the blob.
	 */
	const char *url;
};

/**
 * @brief A blob operation result for HTTP server.
 */
struct EVP_BlobResultHttp {
	/**
	 * The result of the blob operation.
	 */
	EVP_BLOB_RESULT result;

	/**
	 * An HTTP status code.
	 */
	unsigned int http_status;

	/**
	 * An errno value.
	 * Only valid for @ref EVP_BLOB_RESULT_ERROR.
	 */
	int error;
};

#if defined(__cplusplus)
} /* extern "C" */
#endif

#endif /* !defined(__SDK_BLOB_HTTP_H__) */
