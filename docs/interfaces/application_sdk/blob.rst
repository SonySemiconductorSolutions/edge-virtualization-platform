.. SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
..
.. SPDX-License-Identifier: Apache-2.0

Blob
####

Types
*****

Enumerates
==========

.. c:type:: EVP_BLOB_TYPE
        
    An integer constant for specifying the type of storage service.

    :values:
        
        .. c:enumerator:: EVP_BLOB_TYPE_AZURE_BLOB
            
            :value: 0

            A blob stored in an Azure storage container.

        .. c:enumerator:: EVP_BLOB_TYPE_EVP

            :value: 1

            [deprecated] A blob stored in the EVP storage provider.
            EVP_BLOB_TYPE_EVP_EXT can be used instead of this type.

        .. c:enumerator:: EVP_BLOB_TYPE_HTTP
            
            :value: 2

            A blob provided by an ordinary HTTP server.
            Only EVP_BLOB_OP_GET operation is supported.

        .. c:enumerator:: EVP_BLOB_TYPE_EVP_EXT
            
            :value: 3

            A blob stored in the EVP storage provider.
            User can select the storage based on data type.

        .. c:enumerator:: EVP_BLOB_TYPE_HTTP_EXT
            
            :value: 4

            A blob provided by an ordinary HTTP server.
            Only EVP_BLOB_OP_GET operation is supported.
            Allows to pass extra headers for the HTTP
            request.

.. c:type:: EVP_BLOB_OPERATION

    An integer constant for specifying the blob operation.

    :values:

        .. c:enumerator:: EVP_BLOB_OP_GET
            
            :value: 0

            Operation GET a blob from the storage service.

        .. c:enumerator:: EVP_BLOB_OP_PUT
            
            :value: 1

            Operation PUT a blob into the storage service.

.. c:type:: EVP_BLOB_IO_RESULT

    The type to represent an outcome of a blob IO callback.

    :values:

        .. c:enumerator:: EVP_BLOB_IO_RESULT_SUCCESS
            
            :value: 0

        The operation completed successfully.

        .. c:enumerator:: EVP_BLOB_IO_RESULT_ERROR
            
            :value: 1

        The operation failed.

.. c:type:: EVP_BLOB_RESULT

    The type to represent an outcome of a blob operation.

    :values:
        
        .. c:enumerator:: EVP_BLOB_RESULT_SUCCESS
            
            :value: 0

            The operation completed successfully.

        .. c:enumerator:: EVP_BLOB_RESULT_ERROR
            
            :value: 1

            The operation failed.

        .. c:enumerator:: EVP_BLOB_RESULT_ERROR_HTTP
            
            :value: 2

            The operation failed with a valid HTTP status.

.. c:type:: EVP_BLOB_CALLBACK_REASON

    The type to represent the reason of the callback invocation.

    :values:

        .. c:enumerator:: EVP_BLOB_CALLBACK_REASON_DONE
            
            :value: 0

            I/O completion, either success or error.

        .. c:enumerator:: EVP_BLOB_CALLBACK_REASON_EXIT
            
            :value: 1

            Cancelled or rejected because the requesting Module Instance is
            going to exit.
            Users must not send any more requests to the agent when this code is
            received, and instead users must call \ref EVP_processEvent until
            all events are flushed.

        .. c:enumerator:: EVP_BLOB_CALLBACK_REASON_DENIED
            
            :value: 2

            A request was denied for transmission. This means the agent could
            not enqueue the request due to a full queue.

Structures
==========

.. c:struct:: EVP_BlobLocalStore

    A blob operation local store: file or memory

    .. c:member:: const char *filename
        
        An absolute path of a local file to operate on.
        There are restrictions on the filename:

        - It should be in the workspace directory
          for the module instance
          with type :c:enumerator:`~EVP_BLOB_TYPE.EVP_WORKSPACE_TYPE_DEFAULT`.
        - It shouldn't contain parent directory
          references. (``..``)
        - It shouldn't involve symbolic links.
        - It shouldn't end with a slash.
        - It shouldn't contain redundant consecutive slashes.
          (E.g. ``//path///like////this``)

    .. c:member:: EVP_BLOB_IO_CALLBACK io_cb

        Callback to process partial IO data.

        .. warning::

            This functionality is provided as a solution for a particular
            use case.

        .. warning::

            Right now, this functionality is available only for NuttX.

        This field is ignored if `filename` is not NULL.

        The callback is invoked for each chunk in the blob.
        The chunk sizes are decided by the SDK automatically.
        The callback should not assume any specific sizes.

        The callback is called sequentionally from the start of the blob
        (smaller offset) to the end of the blob.
        If a callback needs to know the current offset in the blob,
        the callback should keep track of it by itself, probably using
        `userData`.

        .. warning::

            The callback should return as soon as possible because
            otherwise it would interfere the entire device, not only the
            calling module instance.
            It's recommended for the callback to copy the data to some
            application specific buffer and return without any extra
            processing.

    .. c:member:: size_t blob_len

        The length of the blob to upload
        This field is only used when all conditions below are satisfied:
    
        - filename is NULL
        - PUT operations (type = EVP_BLOB_OP_PUT)

Azure blobs
-----------

.. c:struct:: EVP_BlobRequestAzureBlob

    A blob operation request for Azure Blob Storage.

    .. c:member:: const char *url

        Shared Access Signature URL for the blob.
    
        - :c:enumerator:`~EVP_BLOB_OP.EVP_BLOB_OP_GET`
          requires `Read (r)` permission.
        - :c:enumerator:`~EVP_BLOB_OP.EVP_BLOB_OP_PUT`
          requires `Create (c)` and/or `Write (w)` permission.
    
        See `Create Storage Service`_.

.. c:struct:: EVP_BlobResultAzureBlob

    A blob operation result for Azure Blob Storage.
    
    .. c:member:: EVP_BLOB_RESULT result
        
        The result of the blob operation.

    .. c:member:: unsigned int http_status

        An HTTP status code.

    .. c:member:: int error

        An errno value.
        Only valid for :c:enumerator:`~EVP_BLOB_RESULT.EVP_BLOB_RESULT_ERROR`.

EVP blobs
---------

.. c:struct:: EVP_BlobRequestEvp

    .. deprecated:: 1.0.0
        
    A blob operation request for EVP Storage Provider.

    .. c:member:: const char *remote_name
        
        The unique string to identify this blob.
        
        Consult the documentation of the EVP Storage Provider
        how this string is actually used.
    
.. c:struct:: EVP_BlobRequestEvpExt
    
    A blob operation request for EVP Storage Provider.

    .. c:member::  const char *remote_name

        The unique string to identify file name to upload.
        
        Consult the documentation of the EVP Storage Provider
        how this string is actually used.
        
    .. c:member:: const char *storage_name
        
        The unique string to identify
        the blob storage based on data type.
        
        This parameter must be :c:var:`NULL`
        to use the default STP or the same string
        as configured in EVP Hub
        when user create storage.
        
        When this parameter is :c:var:`NULL`,
        a file will be uploaded
        to the default EVP storage.
        This will be same behavior as
        :c:enumerator:`~EVP_BLOB_TYPE.EVP_BLOB_TYPE_EVP`.
        
        Consult the documentation of the EVP Storage Provider
        how this string is actually used.
        
        .. note::
            
            This member corresponds to the :c:var:`key` field of the target STP
            configured in the Cloud API.
        

.. c:struct:: EVP_BlobResultEvp
        
    A blob operation result for EVP Storage Provider.

    .. c:member:: EVP_BLOB_RESULT result

        The result of the blob operation.
    
    .. c:member:: unsigned int http_status
    
        An HTTP status code.

    .. c:member:: int error
    
        An errno value.
        Only valid for
        :c:enumerator:`~EVP_BLOB_RESULT.EVP_BLOB_RESULT_ERROR`.

HTTP blobs
----------

.. c:struct:: EVP_BlobRequestHttp

    A blob operation request for ordinary HTTP server.

    .. c:member:: const char *url
        
        URL for the blob.

.. c:struct:: EVP_BlobResultHttp

    A blob operation result for HTTP server.
    
    .. c:member:: EVP_BLOB_RESULT result
    
        The result of the blob operation.

    .. c:member:: unsigned int http_status
    
        An HTTP status code.
    
    .. c:member:: int error

        An errno value.
        Only valid for
        :c:enumerator:`~EVP_BLOB_RESULT.EVP_BLOB_RESULT_ERROR`.
    

HTTP Extended blobs
-------------------



.. c:struct:: EVP_BlobRequestHttpExt

    A blob operation request for ordinary HTTP server, supporting extra
    headers.


.. c:struct:: EVP_BlobResultHttpExt
    
    A blob operation result for HTTP server.
    
    .. c:member:: EVP_BLOB_RESULT result
    
        The result of the blob operation.

    .. c:member:: unsigned int http_status
    
        An HTTP status code.

    .. c:member:: int error
    
        An errno value.
        Only valid for
        :c:enumerator:`~EVP_BLOB_RESULT.EVP_BLOB_RESULT_ERROR`.
    

Callbacks
=========

.. c:type:: EVP_BLOB_IO_RESULT (*EVP_BLOB_IO_CALLBACK)(void *buf, size_t buflen, void *userData)

    Function prototype for the callback passed to
            :c:struct:`EVP_BlobLocalStore`

    **parameters**:

        - **buf** -        The buffer with the contents.
        - **buflen** -     The length of the buffer.
        - **userData** -   The userData value specified for :c:func:`EVP_blobOperation`.


.. c:type:: void (*EVP_BLOB_CALLBACK)(EVP_BLOB_CALLBACK_REASON reason, const void *result, void *userData)

    Function prototype for the callback passed to the function
    :c:func:`EVP_blobOperation`.

    **parameters**:

        - **reason** - One of :c:enum:`EVP_BLOB_CALLBACK_REASON` values.
        - **result** - The result of the operation.
            Valid only when :c:var:`reason` is :c:enumerator:`~EVP_BLOB_CALLBACK_REASON.EVP_BLOB_CALLBACK_REASON_DONE`.
            The type of the :c:var:`result` depends on the
            request's :c:var:`type` and :c:var:`op`.

            It is a pointer to:
            
            - :c:struct:`EVP_BlobResultAzureBlob` for
              :c:enumerator:`~EVP_BLOB_TYPE.EVP_BLOB_TYPE_AZURE_BLOB`.
            - :c:struct:`EVP_BlobResultEvp` for
              :c:enumerator:`~EVP_BLOB_TYPE.EVP_BLOB_TYPE_EVP`.
            - :c:struct:`EVP_BlobResultEvp` for
              :c:enumerator:`~EVP_BLOB_TYPE.EVP_BLOB_TYPE_EVP_EXT`.
        - **userData** - The userData value specified for :c:func:`EVP_blobOperation`.

Functions
*********

.. c:function:: EVP_RESULT EVP_blobOperation(struct EVP_client *h, EVP_BLOB_TYPE type, EVP_BLOB_OPERATION op, const void *request, struct EVP_BlobLocalStore *localStore, EVP_BLOB_CALLBACK cb, void *userData)

    Schedule a blob operation

    Enqueues the specified  operation :c:var:`op` on a blob of the given :c:var:`type`
    which is described by :c:var:`request`, linking it to the given data specified
    by :c:var:`localStore`

    :param h: Client object pointer.
    :param type: Blob type
    :param op: Whether to GET or PUT the blob.
    :param request: A pointer to a structure to specify request parameters.

        It is a pointer to:

        - :c:struct:`EVP_BlobRequestAzureBlob` for
          :c:enumerator:`~EVP_BLOB_TYPE.EVP_BLOB_TYPE_AZURE_BLOB`
        - :c:struct:`EVP_BlobRequestEvp` for
          :c:enumerator:`~EVP_BLOB_TYPE.EVP_BLOB_TYPE_EVP`
        - :c:struct:`EVP_BlobRequestEvpExt` for
          :c:enumerator:`~EVP_BLOB_TYPE.EVP_BLOB_TYPE_EVP_EXT`
        - :c:struct:`EVP_BlobRequestHttp` for
          :c:enumerator:`~EVP_BLOB_TYPE.EVP_BLOB_TYPE_HTTP`
        - :c:struct:`EVP_BlobRequestHttpExt` for
          :c:enumerator:`~EVP_BLOB_TYPE.EVP_BLOB_TYPE_HTTP_EXT`
    :param localStore:  The info about the local store for the data.
        The pointed info is copied as needed, so it is
        responsibility of the caller to free it.
    :param cb: The callback function. It can not be :c:var:`NULL`.
    :param userData: The SDK passes this value to the callback as it is.
        The SDK doesn't care if it's a valid pointer.

    :returns: :c:enumerator:`~EVP_RESULT.EVP_OK` Success.

.. c:function:: EVP_RESULT EVP_blobGetUploadURL(struct EVP_client *h, const charstorageName, const charremoteName, EVP_BLOB_CALLBACK cb, void *userData)

    Get the upload URL
    This API is only available from native.
    It cannot be used from the WASM module.

    .. warning::
        
        This is an experimental option and will be
        removed in future releases.

    :param h: struct EVP_client.
    :param storageName: The unique string to identify the blob storage based
        on data type.
    :param remoteName: The unique string to identify file name to upload.
        Set "" to get container UploadURL.
        Set other than "" to get Blob UploadURL.

    :param cb: The callback function. It can not be NULL.
    :param userData: The SDK passes this value to the callback as it is.
        The SDK doesn't care if it's a valid pointer.

    :returns: :c:enumerator:`~EVP_RESULT.EVP_OK` Success.

HTTP Extended
=============

.. c:function:: struct EVP_BlobRequestHttpExt *EVP_BlobRequestHttpExt_initialize(void)

    Initializes an :c:struct:`EVP_BlobRequestHttpExt`

    This function must be called when instantiating an  :c:struct:`EVP_BlobRequestHttpExt`.
    It returns a pointer to a new request that must be later freed using
    :c:func:`EVP_BlobRequestHttpExt_free`

    :returns: Pointer to a newly allocated request struct. :c:var:`NULL` on failure.

.. c:function:: void EVP_BlobRequestHttpExt_free(struct EVP_BlobRequestHttpExt *request)

    Frees an  :c:struct:`EVP_BlobRequestHttpExt`

    This function must be called when freeing an :c:struct:`EVP_BlobRequestHttpExt`

    :param request: A pointer to a  :c:struct:`EVP_BlobRequestHttpExt` structure.

.. c:function:: EVP_RESULT EVP_BlobRequestHttpExt_addHeader(struct EVP_BlobRequestHttpExt *request, const char *name, const char *value)

    Inserts an extra header to  :c:struct:`EVP_BlobRequestHttpExt`

    This helper function inserts an extra header into the request.

    :param request: A pointer to a  :c:struct:`EVP_BlobRequestHttpExt` structure.
    :param name: A pointer to a null-terminated string containing the
        name of the header.
    :param value: A pointer to a null-terminated string containing the value
        of the header.

    :returns: :c:enumerator:`~EVP_RESULT.EVP_OK` Success.

.. c:function:: EVP_RESULT EVP_BlobRequestHttpExt_addAzureHeader(struct EVP_BlobRequestHttpExt *request)

    Inserts an extra header to :c:struct:`EVP_BlobRequestHttpExt`

    This helper function inserts the azure specific headers in the request.

    :param request: A pointer to a :c:struct:`EVP_BlobRequestHttpExt` structure.

    :returns: :c:enumerator:`~EVP_RESULT.EVP_OK` Success.

.. c:function:: EVP_RESULT EVP_BlobRequestHttpExt_setUrl(struct EVP_BlobRequestHttpExt *request, char *url)

    Sets the url of :c:struct:`EVP_BlobRequestHttpExt`

    This function sets the url of the request.

    :param request: A pointer to a :c:struct:`EVP_BlobRequestHttpExt` structure.
    :param url: The destination URL of the request.

    :returns: :c:enumerator:`~EVP_RESULT.EVP_OK` Success.


-------

.. _Create Storage Service: https://docs.microsoft.com/en-us/rest/api/storageservices/create-service-sas