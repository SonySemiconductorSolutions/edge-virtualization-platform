/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if !defined(__SDK_BLOB_EVP_H__)
#define __SDK_BLOB_EVP_H__

#if defined(__cplusplus)
extern "C" {
#endif

/** @file */

/**
 * @brief [deprecated] A blob operation request for EVP Storage Provider.
 */
struct EVP_BlobRequestEvp {
	/**
	 * The unique string to identify this blob.
	 *
	 * Consult the documentation of the EVP Storage Provider
	 * how this string is actually used.
	 */
	const char *remote_name;
};

/**
 * @brief A blob operation request for EVP Storage Provider.
 */
struct EVP_BlobRequestEvpExt {
	/**
	 * The unique string to identify file name to upload.
	 *
	 * Consult the documentation of the EVP Storage Provider
	 * how this string is actually used.
	 */
	const char *remote_name;
	/**
	 * The unique string to identify the blob storage based on data type.
	 *
	 * This parameter must be NULL to use the default STP or the same
	 * string as configuring to EVP hub when user create storage.
	 *
	 * When this parameter is NULL, a file will be uploaded to the default
	 * EVP storage. This will be same behavior as EVP_BLOB_TYPE_EVP.
	 *
	 * Consult the documentation of the EVP Storage Provider
	 * how this string is actually used.
	 *
	 * Note: This member corresponds to the `key` field of the target STP
	 * configured in the Cloud API.
	 */
	const char *storage_name;
};

/**
 * @brief A blob operation result for EVP Storage Provider.
 */
struct EVP_BlobResultEvp {
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

#endif /* !defined(__SDK_BLOB_EVP_H__) */
