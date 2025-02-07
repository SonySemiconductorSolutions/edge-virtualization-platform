/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if !defined(__SDK_BLOB_H__)
#define __SDK_BLOB_H__

#if defined(__cplusplus)
extern "C" {
#endif

/** @file sdk_blob.h
 *
 *  Definitions for handling blobs.
 */

/**
 * @brief An integer constant for specifying the type of storage service.
 */
typedef enum {
	/**
	 * A blob stored in an Azure storage container.
	 */
	EVP_BLOB_TYPE_AZURE_BLOB = 0,

	/**
	 * [deprecated] A blob stored in the EVP storage provider.
	 * EVP_BLOB_TYPE_EVP_EXT can be used instead of this type.
	 */
	EVP_BLOB_TYPE_EVP = 1,

	/**
	 * A blob provided by an ordinary HTTP server.
	 * Only EVP_BLOB_OP_GET operation is supported.
	 */
	EVP_BLOB_TYPE_HTTP = 2,

	/**
	 * A blob stored in the EVP storage provider.
	 * User can select the storage based on data type.
	 */
	EVP_BLOB_TYPE_EVP_EXT = 3,

	/**
	 * A blob provided by an ordinary HTTP server.
	 * Only EVP_BLOB_OP_GET operation is supported.
	 * Allows to pass extra headers for the HTTP
	 * request.
	 */
	EVP_BLOB_TYPE_HTTP_EXT = 4,

#if !defined(DOXYGEN)
	/**
	 * A placeholder to ensure the enum size.
	 */
	_EVP_BLOB_TYPE_dummy = 0x3fffffff,
#endif
} EVP_BLOB_TYPE;

EVP_CTASSERT(sizeof(EVP_BLOB_TYPE) == sizeof(int));

/**
 * @brief An integer constant for specifying the blob operation.
 */
typedef enum {
	/**
	 * Operation GET a blob from the storage service.
	 */
	EVP_BLOB_OP_GET = 0,

	/**
	 * Operation PUT a blob into the storage service.
	 */
	EVP_BLOB_OP_PUT = 1,

#if !defined(DOXYGEN)
	/**
	 * A placeholder to ensure the enum size.
	 */
	_EVP_BLOB_OPERATION_dummy = 0x3fffffff,
#endif
} EVP_BLOB_OPERATION;

EVP_CTASSERT(sizeof(EVP_BLOB_OPERATION) == sizeof(int));

/**
 * @brief The type to represent an outcome of a blob IO callback.
 */
typedef enum {
	/**
	 * The operation completed successfully.
	 */
	EVP_BLOB_IO_RESULT_SUCCESS = 0,

	/**
	 * The operation failed.
	 */
	EVP_BLOB_IO_RESULT_ERROR = 1,

#if !defined(DOXYGEN)
	/**
	 * A placeholder to ensure the enum size.
	 */
	_EVP_BLOB_IO_RESULT_dummy = 0x3fffffff,
#endif
} EVP_BLOB_IO_RESULT;

/** @brief Function prototype for the callback passed to
 *         @ref EVP_BlobLocalStore
 *
 *  @param buf        The buffer with the contents.
 *  @param buflen     The length of the buffer.
 *  @param userData   The userData value specified for @ref EVP_blobOperation.
 */
typedef EVP_BLOB_IO_RESULT (*EVP_BLOB_IO_CALLBACK)(void *buf, size_t buflen,
						   void *userData);

/**
 * @brief A blob operation local store: file or memory
 */
struct EVP_BlobLocalStore {
	/**
	 * An absolute path of a local file to operate on.
	 * There are restrictions on the filename:
	 * - It should be in the workspace directory
	 *   for the module instance
	 *   with type @ref EVP_WORKSPACE_TYPE_DEFAULT.
	 * - It shouldn't contain parent directory
	 *   references. ("..")
	 * - It shouldn't involve symbolic links.
	 * - It shouldn't end with a slash.
	 * - It shouldn't contain redundant consecutive slashes.
	 *   (E.g. "//path///like////this")
	 */
	const char *filename;

	/**
	 * Callback to process partial IO data.
	 *
	 * \verbatim embed:rst:leading-asterisk
	 * .. warning::
	 *      This functionality is provided as a solution for a particular
	 *      use case.
	 *
	 * .. warning::
	 *      Right now, this functionality is available only for NuttX.
	 * \endverbatim
	 *
	 * This field is ignored if `filename` is not NULL.
	 *
	 * The callback is invoked for each chunk in the blob.
	 * The chunk sizes are decided by the SDK automatically.
	 * The callback should not assume any specific sizes.
	 *
	 * The callback is called sequentionally from the start of the blob
	 * (smaller offset) to the end of the blob.
	 * If a callback needs to know the current offset in the blob,
	 * the callback should keep track of it by itself, probably using
	 * `userData`.
	 *
	 * \verbatim embed:rst:leading-asterisk
	 * .. warning::
	 *      The callback should return as soon as possible because
	 *      otherwise it would interfere the entire device, not only the
	 *      calling module instance.
	 *      It's recommended for the callback to copy the data to some
	 *      application specific buffer and return without any extra
	 *      processing.
	 * \endverbatim
	 */
	EVP_BLOB_IO_CALLBACK io_cb;

	/**
	 * The length of the blob to upload
	 * This field is only used when all conditions below are satisfied:
	 * 	- filename is NULL
	 * 	- PUT operations (type = EVP_BLOB_OP_PUT)
	 */
	size_t blob_len;
};

/**
 * @brief The type to represent an outcome of a blob operation.
 */
typedef enum {
	/**
	 * The operation completed successfully.
	 */
	EVP_BLOB_RESULT_SUCCESS = 0,

	/**
	 * The operation failed.
	 */
	EVP_BLOB_RESULT_ERROR = 1,

	/**
	 * The operation failed with a valid HTTP status.
	 */
	EVP_BLOB_RESULT_ERROR_HTTP = 2,

#if !defined(DOXYGEN)
	/**
	 * A placeholder to ensure the enum size.
	 */
	_EVP_BLOB_RESULT_dummy = 0x3fffffff,
#endif
} EVP_BLOB_RESULT;

EVP_CTASSERT(sizeof(EVP_BLOB_RESULT) == sizeof(int));

/**
 * @brief The type to represent the reason of the callback invocation.
 */
typedef enum {
	/**
	 * I/O completion, either success or error.
	 */
	EVP_BLOB_CALLBACK_REASON_DONE = 0,

	/**
	 * Cancelled or rejected because the requesting Module Instance is
	 * going to exit.
	 * Users must not send any more requests to the agent when this code is
	 * received, and instead users must call \ref EVP_processEvent until
	 * all events are flushed.
	 */
	EVP_BLOB_CALLBACK_REASON_EXIT = 1,

	/**
	 * A request was denied for transmission. This means the agent could
	 * not enqueue the request due to a full queue.
	 */
	EVP_BLOB_CALLBACK_REASON_DENIED = 2,

#if !defined(DOXYGEN)
	/**
	 * A placeholder to ensure the enum size.
	 */
	_EVP_BLOB_CALLBACK_REASON_dummy = 0x3fffffff,
#endif
} EVP_BLOB_CALLBACK_REASON;

EVP_CTASSERT(sizeof(EVP_BLOB_CALLBACK_REASON) == sizeof(int));

/** @brief Function prototype for the callback passed to the function
 *         @ref EVP_blobOperation.
 *
 *  @param reason     One of @ref EVP_BLOB_CALLBACK_REASON values.
 *  @param result     The result of the operation.
 *                    Valid only when `reason` is @ref
 *                    EVP_BLOB_CALLBACK_REASON_DONE.
 *                    The type of the `result` depends on the
 *                    request's `type` and `op`.
 *                    It is a pointer to @ref EVP_BlobResultAzureBlob
 *                    for @ref EVP_BLOB_TYPE_AZURE_BLOB.
 *                    It is a pointer to @ref EVP_BlobResultEvp
 *                    for @ref EVP_BLOB_TYPE_EVP.
 *                    It is a pointer to @ref EVP_BlobResultEvp
 *                    for @ref EVP_BLOB_TYPE_EVP_EXT.
 *  @param userData   The userData value specified for @ref EVP_blobOperation.
 */
typedef void (*EVP_BLOB_CALLBACK)(EVP_BLOB_CALLBACK_REASON reason,
				  const void *result, void *userData);

/** @brief Schedule a blob operation
 *
 * Enqueues the specified  operation `op` on a blob of the given `type`
 * which is described by `request`, linking it to the given data specified
 * by `localStore`
 *
 * @param h           struct EVP_client *.
 * @param type        @ref EVP_BLOB_TYPE_AZURE_BLOB or @ref EVP_BLOB_TYPE_EVP
 *                    or @ref EVP_BLOB_TYPE_EVP_EXT
 * @param op          Whether to GET or PUT the blob.
 * @param request     A pointer to a structure to specify request parameters.
 *                    if `type` is @ref EVP_BLOB_TYPE_AZURE_BLOB, it is
 *                    @ref EVP_BlobRequestAzureBlob.
 *                    if `type` is @ref EVP_BLOB_TYPE_EVP, it is
 *                    @ref EVP_BlobRequestEvp.
 *                    if `type` is @ref EVP_BLOB_TYPE_EVP_EXT, it is
 *                    @ref EVP_BlobRequestEvpExt.
 *                    if `type` is @ref EVP_BLOB_TYPE_HTTP, it is
 *                    @ref EVP_BlobRequestHttp.
 *                    if `type` is @ref EVP_BLOB_TYPE_HTTP_EXT, it is
 *                    @ref EVP_BlobRequestHttpExt.
 * @param localStore  The info about the local store for the data.
 *                    The pointed info is copied as needed, so it is
 *                    responsibility of the caller to free it.
 * @param cb          The callback function. It can not be NULL.
 * @param userData    The SDK passes this value to the callback as it is.
 *                    The SDK doesn't care if it's a valid pointer.
 *
 * @return @ref EVP_OK Success.
 */
EVP_RESULT EVP_blobOperation(struct EVP_client *h, EVP_BLOB_TYPE type,
			     EVP_BLOB_OPERATION op, const void *request,
			     struct EVP_BlobLocalStore *localStore,
			     EVP_BLOB_CALLBACK cb, void *userData);

/** @brief  Get the upload URL
 *  This API is only available from native.
 *  It cannot be used from the WASM module.
 *
 * WARNING: This is an experimental option and will be
 *          removed in future releases.
 *
 * @param h               struct EVP_client *.
 * @param storageName     The unique string to identify the blob storage based
 *                        on data type.
 * @param remoteName      The unique string to identify file name to upload.
 *                        Set "" to get container UploadURL.
 *                        Set other than "" to get Blob UploadURL.
 *
 * @param cb              The callback function. It can not be NULL.
 * @param userData        The SDK passes this value to the callback as it is.
 *                        The SDK doesn't care if it's a valid pointer.
 *
 * @return @ref EVP_OK Success.
 */

EVP_RESULT EVP_blobGetUploadURL(struct EVP_client *h, const char *storageName,
				const char *remoteName, EVP_BLOB_CALLBACK cb,
				void *userData);

#include "sdk_blob_azure.h"
#include "sdk_blob_evp.h"
#include "sdk_blob_http.h"
#include "sdk_blob_http_ext.h"

#if defined(__cplusplus)
} /* extern "C" */
#endif

#endif /* !defined(__SDK_BLOB_H__) */
