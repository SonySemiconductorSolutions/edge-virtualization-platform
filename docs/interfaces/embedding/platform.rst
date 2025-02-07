.. SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
..
.. SPDX-License-Identifier: Apache-2.0

.. c:struct:: evp_agent_platform

    .. topic:: Logging
            
        .. c:member:: void *user

            A user data that will be passed to :c:func:`dlog` as user param.

        .. c:member:: void (*dlog)(int lvl, const char *file, int line, const char *fmt, va_list ap)

            Platform function to handle log outputs.

            **Parameters**:
                - `lvl`: Log level.
                - `file`: Current file of log call.
                - `line`: Current line of log call.
                - `fmt`: printf-like format string.
                - `ap`: Variadic parameter list.

    .. topic:: WASM memory management

        .. c:member:: void *(*wasm_mem_read)(void *handle, void *to, size_t siz, const void *from)

            Platform function to perform memory read from WASM module.

            **Parameters**:
                - `handle`: WASM module instance handle.
                - `to`: output buffer to read to.
                - `siz`: size of memory to read.
                - `from`: buffer to read from module.

        .. c:member:: void *(*wasm_mem_write)(void *handle, const void *from, size_t siz, void *to)

            Platform function to perform memory write to WASM module.

            **Parameters**:
                - `handle`: WASM module instance handle.
                - `from`: input buffer to write from.
                - `siz`: size of memory to read.
                - `to`: output buffer to write to module.

        .. c:member:: void *(*wasm_stack_mem_alloc)(size_t size)

            Platform function to allocate memory for a WASM module.

            **Parameters**:
                - `siz`: size of memory block to allocate.

        .. c:member:: void (*wasm_stack_mem_free)(void *ptr)

            Platform function to free memory allocated with :c:func:`wasm_stack_mem_alloc`.

            **Parameters**:
                - `ptr`: Pointer to the allocated memory

        .. c:member:: size_t (*wasm_strlen)(void *handle, const char *s)

            Platform function to get string length.

            **Parameters**:
                - `handle`: WASM module instance handle.
                - `s`: String.

    .. topic:: Module File System management

        .. c:member:: int (*mod_fs_sink)(unsigned http_status, char **buffer, int offset, int datend, int *buflen, void *arg)

            Platform function to receive stream of data from http.

            **Parameters**:
                - `http_status`: HTTP response status.
                - `buffer`: Output buffer pointer.
                - `offset`: Offset of stream data to copy into sink.
                - `datend`: Index of the end of buffer.
                - `buflen`: Output buffer length.
                - `arg`: User argument.

        .. c:member:: struct mod_fs_mmap_handle *(*mod_fs_file_mmap)(struct module *module, const void **data, size_t *size, bool exec, int *error)

            Platform function to map
            a module file into the memory.

            This function should try
            to load the module pointed to
            by :c:var:`module`,
            and should return a non-null handle
            to be passed to
            :c:var:`mod_fs_file_munmap` later.
            It should set :c:var:`error`
            to :c:var:`ENOENT` in
            case the file is not found,
            and to something else different than
            zero if there is some other error.
            Not being able to find the file is fine,
            as it is going to be downloaded later.
            The function may not set
            the error to 0 in case of success,
            this means that
            :c:var:`error` myst be set to zero before
            this function is called.

            **Parameters**:
                - `module`:
                  Opaque pointer to a module
                - `data`:
                  Output pointer to the memory
                  where the module has been mapped.
                - `size`:
                  Output pointer to the size
                  of the mapped file in
                  memory module that
                  has been mapped.
                - `exec`:
                  if true, the file should be mapped
                  to Instruction bus or
                  have executable permissions.
                  If false, memory should be mapped
                  to Data bus.
                - `error`:
                  Output pointer to an int
                  that represents the error number.
                  The function must set this error
                  to ENOENT in case the file is not found,
                  or some other error.
                  The function does not need
                  to set this to zero
                  in case of success.

            **Returns**: a handle that can be passed to mod_fs_file_munmap

        .. c:member:: int (*mod_fs_file_munmap)(struct mod_fs_mmap_handle *handle)

            Platform function to unmap a module file from the memory

            This function should unload the module loaded in the handle.

            **Parameters**:
                - `handle`: A handle that was returned by `mod_fs_file_mmap`

            **Returns**: zero in case of success or anything in case of
                error.

        .. c:member:: int (*mod_fs_file_unlink)(struct module *module)

            Platform function to unlink (delete) a module from storage

            This function should delete the module from local storage.

            **Parameters**:
                - `module`: Opaque pointer to a module

            **Returns**: zero in case of success or anything in case of error.

        .. c:member:: int (*mod_fs_download_finished)(struct module *module, struct blob_work *wk)

            Callback for download finished

            This function will be called when the download succesfully finished,
            cancelled or errored.

            **Parameters**:
                - `module``: Opaque pointer to a module
                - `wk``: Pointer to the blob worker

            **Returns**: zero in case of success or anything in case of error.

        .. c:member:: int (*mod_fs_handle_custom_protocol)(struct module *module, const char *downloadUrl)

            Custom protocol module downloadUrl handler

            This function is used to handle other protocols than http or https.

            **Parameters**:
                - `module`: Opaque pointer to a module
                - `downloadUrl`: The URL set in the module.

            **Returns**: Returns zero in case of success or anything in case of error.

        .. c:member:: void (*mod_fs_init)(void)

            Initialize module storage

            This function will be called when the agent starts, to initialize
            the module storage.

        .. c:member:: void (*mod_fs_prune)(void)

            Cleanup module storage

            This function is used to delete all unused modules from the storage.

    .. topic:: Memory allocation management

        .. c:member:: void (*out_of_memory)(const char *, int, const char *, size_t)

        .. c:member:: void *(*secure_malloc)(size_t size)

            Secure malloc

            This function should allocate memory in the secure or internal heap.

            It has the same semantics as malloc(3).

            **Parameters**:
                - `size`: The size in bytes to allocate.

            **Returns**: a pointer to the allocated memory or NULL in case of failure.

        .. c:member:: void (*secure_free)(void *ptr)

            Secure free

            This function should free allocated memory in the secure or internal
            heap.

            It has the same semantics as free(3).

            **Parameters**:
                - `ptr`: The pointer to the memory to be deallocated.

    .. topic:: Module utils

        .. c:member:: char *(*mod_mem_mng_strdup)(const char *)

        .. c:member:: int (*mod_check_hash)(struct module *module, const unsigned char *ref, size_t ref_len, char **result)

.. c:function:: int evp_agent_platform_register(struct evp_agent_context *ctxt, const struct evp_agent_platform *p)

    Set the platform methods.

    This method can be called only before :c:func:`evp_agent_start`.

    :param ctxt: Opaque pointer to internal agent-related data.
    :param p: pointer to platform methods.
    :returns: Returns zero on success, non-zero otherwise.
