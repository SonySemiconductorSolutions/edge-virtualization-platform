.. SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
..
.. SPDX-License-Identifier: Apache-2.0

Base
####

Types
*****

.. c:struct:: EVP_client

    An opaque structure
    to represent an EVP client.

    This client is used
    by EVP module instances
    to communicate with
    the EVP agent running locally
    on the same device.

    An EVP module instance
    can obtain the pointer
    to the client
    by calling :c:func:`EVP_initialize`.

    The majority of SDK API functions
    take a pointer to this structure.


.. c:type:: EVP_RESULT

    The type to represent either
    a success or an error.
    Used as the return value of
    several of the functions in this SDK.

    :values:

        .. c:enumerator:: EVP_OK

            :value: 0

            At least one event has been processed.

        .. c:enumerator:: EVP_SHOULDEXIT

            :value: 1

            The module instance is requested to stop.
            It should exit performing cleanup
            as soon as possible.

        .. c:enumerator:: EVP_TIMEDOUT

            :value: 2

            The specified period has elapsed without any events.

        .. c:enumerator:: EVP_ERROR

            :value: 3

            An error ocurred.

        .. c:enumerator:: EVP_INVAL

            :value: 4

            Invalid parameter.

        .. c:enumerator:: EVP_NOMEM

            :value: 5

            Memory allocation failed.

        .. c:enumerator:: EVP_TOOBIG

            :value: 6

            Too big payload.

        .. c:enumerator:: EVP_AGAIN

            :value: 7

            Failure because of temporary conditions.

        .. c:enumerator:: EVP_AGENT_PROTOCOL_ERROR

            :value: 8

            Protocol error when communicating with the agent.

        .. c:enumerator:: EVP_EXIST

            :value: 9

            The request failed bacause of
            conflicting existing entries.


        .. c:enumerator:: EVP_FAULT

            :value: 10

            Invalid address was detected.

            .. note:: 
              
                An application should not rely on such a detection.
                It's the responsibility of applications to always specify
                vaild addresses.

        .. c:enumerator:: EVP_DENIED

            :value: 11

            A request was denied.
            It could mean the agent cannot be
            transmitting due to a full queue.


        .. c:enumerator:: EVP_NOTSUP

            :value: 12

            The request is still not supported by
            the implementation.

.. c:type:: uint64_t EVP_RPC_ID

    The integer request ID used for RPCs.

Reasons
=======

Each callback type have its associated
``EVP_*_CALLBACK_REASON`` enum.

They share some common definitions:

.. c:enumerator:: CALLBACK_REASON_SENT

    The request has been received by
    the next hop entity.
    (Typically the agent within the device. 
    It will try its best to
    deliver the State to
    the Cloud reliably.)

    .. note::
      
        This doesn't mean the State has reached the Cloud.

.. c:enumerator:: CALLBACK_REASON_EXIT

    The request has been cancelled because
    the module instance is going to exit.
    This gives the module instance
    a chance to cleanup
    the associated resources before exiting.

    Users must not send any more requests
    to the agent when this code is received,
    and instead must call
    :c:func:`EVP_processEvent` until
    all events are flushed.

.. c:enumerator:: CALLBACK_REASON_ERROR

    The request has not been processed
    because it is invalid.

.. c:enumerator:: CALLBACK_REASON_DENIED

    A request was denied for transmission.
    This means the agent could not enqueue
    the request due to a full queue.

.. c:type:: EVP_STATE_CALLBACK_REASON

    The type to represent the reason of the callback invocation.

    :values:

        .. c:enumerator:: EVP_STATE_CALLBACK_REASON_SENT

            :value: 0

            See :c:enumerator:`CALLBACK_REASON_SENT`.

        .. c:enumerator:: EVP_STATE_CALLBACK_REASON_OVERWRITTEN

            :value: 1

            The State has been overwritten by
            another :c:func:`EVP_sendState` call with
            the same topic.
            
            .. note::
              
                The SDK only cares about
                the latest State for a topic.

        .. c:enumerator:: EVP_STATE_CALLBACK_REASON_EXIT

            :value: 2

            See :c:enumerator:`CALLBACK_REASON_EXIT`.

        .. c:enumerator:: EVP_STATE_CALLBACK_REASON_DENIED

            :value: 3

            See :c:enumerator:`CALLBACK_REASON_DENIED`.

.. c:type:: EVP_MESSAGE_SENT_CALLBACK_REASON

    The type to represent the reason of the callback invocation.

    :values:

        .. c:enumerator:: EVP_MESSAGE_SENT_CALLBACK_REASON_SENT

            :value: 0

            See :c:enumerator:`CALLBACK_REASON_SENT`.

        .. c:enumerator:: EVP_MESSAGE_SENT_CALLBACK_REASON_ERROR

            :value: 1

            See :c:enumerator:`CALLBACK_REASON_ERROR`.


        .. c:enumerator:: EVP_MESSAGE_SENT_CALLBACK_REASON_EXIT

            :value: 2

            See :c:enumerator:`CALLBACK_REASON_EXIT`.

.. c:type:: EVP_TELEMETRY_CALLBACK_REASON

    The type to represent the reason of the callback invocation.

    :values:

        .. c:enumerator:: EVP_TELEMETRY_CALLBACK_REASON_SENT

            :value: 0

            See :c:enumerator:`CALLBACK_REASON_SENT`.

        .. c:enumerator:: EVP_TELEMETRY_CALLBACK_REASON_ERROR

            :value: 1

            See :c:enumerator:`CALLBACK_REASON_ERROR`.

        .. c:enumerator:: EVP_TELEMETRY_CALLBACK_REASON_EXIT

            :value: 2

            See :c:enumerator:`CALLBACK_REASON_EXIT`.

        .. c:enumerator:: EVP_TELEMETRY_CALLBACK_REASON_DENIED

            :value: 3

            See :c:enumerator:`CALLBACK_REASON_DENIED`.

.. c:type:: EVP_RPC_RESPONSE_CALLBACK_REASON

    The type to represent the reason of the callback invocation.

    :values:

        .. c:enumerator:: EVP_RPC_RESPONSE_CALLBACK_REASON_SENT

            :value: 0

            See :c:enumerator:`CALLBACK_REASON_SENT`.

        .. c:enumerator:: EVP_RPC_RESPONSE_CALLBACK_REASON_ERROR

            :value: 1

            See :c:enumerator:`CALLBACK_REASON_ERROR`.

        .. c:enumerator:: EVP_RPC_RESPONSE_CALLBACK_REASON_EXIT

            :value: 2

            See :c:enumerator:`CALLBACK_REASON_EXIT`.

        .. c:enumerator:: EVP_RPC_RESPONSE_CALLBACK_REASON_DENIED

            :value: 3

            See :c:enumerator:`CALLBACK_REASON_DENIED`.


.. c:type:: EVP_RPC_RESPONSE_STATUS

    The type to specify a status condition for a RPC response to the Hub.

    :values:

        .. c:enumerator:: EVP_RPC_RESPONSE_STATUS_OK

            :value: 0

            The RPC request executed successfully and the response
            contains the results of the execution.

        .. c:enumerator:: EVP_RPC_RESPONSE_STATUS_METHOD_NOT_FOUND

            :value: 1

            The originating RPC request specified a method that is not
            implemented, so it is reported back as not found.

        .. c:enumerator:: EVP_RPC_RESPONSE_STATUS_ERROR

            :value: 2

            The RPC request executed with error and the response
            contains the error message

.. c:type:: EVP_WORKSPACE_TYPE


    The type to represent a workspace type.

    :values:

        .. c:enumerator:: EVP_WORKSPACE_TYPE_DEFAULT

            :value: 0

            Default type of Workspace.

.. c:type:: int EVP_STREAM

    The type used to represent a stream.

.. c:type:: unsigned long EVP_STREAM_PEER_ID

    The type used to represent a peer identifier.

Callbacks
=========

.. c:type:: void (*EVP_CONFIGURATION_CALLBACK)(const char *topic, const void *config, size_t configlen, void *userData)

    Function prototype for the callback passed to the function
    :c:func:`EVP_setConfigurationCallback`.

    **Parameters**:
      - **topic** - Destination topic.
      - **config** - The buffer to pass as configuration.
      - **configlen** - The size of the configuration data for sending.
      - **userData** - An arbitrary blob of data to pass to the callback.

.. c:type:: void (*EVP_STATE_CALLBACK)(EVP_STATE_CALLBACK_REASON reason, void *userData)

    Function prototype for the callback passed to State message-dealing
    functions such as :c:func:`EVP_sendState`.

    **Parameters**:
      - **reason** - The cause code for executing the callback.
      - **userData** - An arbitrary blob of data to pass to the callback.

.. c:type:: void (*EVP_MESSAGE_SENT_CALLBACK)(EVP_MESSAGE_SENT_CALLBACK_REASON reason, void *userData)

    Function prototype for the callback passed to generic message-dealing
    functions such as :c:func:`EVP_sendMessage`.

    **Parameters**:
      - **reason** - The cause code for executing the callback.
      - **userData** - An arbitrary blob of data to pass to the callback.

.. c:type:: void (*EVP_MESSAGE_RECEIVED_CALLBACK)(const char *topic, const void *msgPayload, size_t msgPayloadLen, void *userData)

    Function prototype for the callback passed to the function
    :c:func:`EVP_setMessageCallback`.  Executed when a message is received
    on the configured ``topic``.

    **Parameters**:
      - **topic** - Destination topic.
      - **msgPayload** - The buffer to pass as configuration.
      - **msgPayloadLen** - The size of the configuration data for sending.
      - **userData** - An arbitrary blob of data to pass to the callback.

.. c:type:: void (*EVP_TELEMETRY_CALLBACK)(EVP_TELEMETRY_CALLBACK_REASON reason, void *userData)

    Function prototype for the callback passed to :c:func:`EVP_sendTelemetry`.

    **Parameters**:
      - **reason** - The cause code for executing the callback.
      - **userData** - An arbitrary blob of data to pass to the callback.

.. c:type:: void (*EVP_RPC_REQUEST_CALLBACK)(EVP_RPC_ID id, const char *methodName, const char *params, void *userData)

    Function prototype for the callback passed to :c:func:`EVP_setRpcCallback`.

    **Parameters**:
      - **id** - The request Id for :c:func:`EVP_sendRpcResponse`.
      - **methodName** - The name of method.
      - **params** - The call parameters. A string representation of
                        a JSON value.

.. c:type:: void (*EVP_RPC_RESPONSE_CALLBACK)(EVP_RPC_RESPONSE_CALLBACK_REASON reason, void *userData)

    Function prototype for the callback passed to :c:func:`EVP_sendRpcResponse`.

    **Parameters**:
      - **reason** - The cause code for executing the callback.
      - **userData** - An arbitrary blob of data to pass to the callback.

.. c:type:: void (*EVP_STREAM_READ_CALLBACK)(EVP_STREAM_PEER_ID id, const void *buf, size_t n, void *userData)

    The callback type used to represent a read-available stream
    operation.

    **Parameters**:
      - **id** - Peer identifier. Whereas this remains as an
        opaque type, applications can rely on
        different identifiers meaning different connections to a given stream.
      - **buf** - Buffer containing the input data.
      - **n** - Buffer length.
      - **userData** - An opaque pointer to user-defined data,
        as defined by :c:func:`EVP_streamInputOpen` .

Functions
*********

.. c:function:: struct EVP_client *EVP_initialize(void)

    Initialize the SDK.

    Performs the required initialization operations
    for the module instance.

    This should be called by the main thread
    of the module instance.
    Otherwise, the behaviour is undefined.

    This should not be called more than once
    for a module instance.
    Otherwise, the behaviour is undefined.

    :returns: Client object pointer for the calling module instance.

.. c:function:: const char EVP_getWorkspaceDirectory(struct EVP_client *h, EVP_WORKSPACE_TYPE type)

    Returns the absolute path of the workspace directory
    for the calling Module Instance.

    The workspace directory with the default type
    (:c:enumerator:`~EVP_WORKSPACE_TYPE.EVP_WORKSPACE_TYPE_DEFAULT`)
    has the following characteristics:

    - Initially, the workspace directory is empty.

    - The workspace directory is left intact
      across a reboot of the Module
      Instace and/or the device.
      It can contain the contents left by the
      Module Instance before a reboot.

    - The Module Instance has an exclusive access
      to its workspace directory
      during its lifetime.

    - The Module Instance can access
      the workspace directory directly,
      using the OS interfaces like
      :c:func:`open` and :c:func:`mkdir`.

    - The Module Instance can request file operations
      on the workspace directory via the SDK.
      For example,
      upload from/download to a file
      on the workspace directory.

    - The Module Instance should only use
      regular files and directories on
      the workspace directory.
      If it attempts to create other file types,
      the behavior is undefined.

    - The agent will remove files
      in the workspace directory after
      the corresponding Module Instance has gone away.
      That is,
      at some point
      after a successful deployment
      of a new Deployment which doesn't contain
      the Module Instance anymore.

    :param h: Client object pointer.
    :param type: Workspace type

    :returns: The absolute path to the workspace directory.

.. c:function:: EVP_RESULT EVP_setConfigurationCallback(struct EVP_client *h, EVP_CONFIGURATION_CALLBACK cb, void *userData)

    Register a callback function for Configuration.

    This should not be called more than once for
    a :c:struct:`EVP_client` object.
    Otherwise, the behaviour is undefined.

    The callback :c:var:`cb` will be called in
    the context of this function or of
    :c:func:`EVP_processEvent`.

    The callback will be called
    on the following events at least:

    - When the callback function is registered.
    - When the SDK received the latest Configuration.

    The SDK might coalesce multiple events into one.
    In that case,
    the callback will be called with
    the latest Configuration.

    The SDK might choose to invoke
    this callback more frequently than necessary.
    The callback function should not assume that
    the given Configuration was updated.

    All pointers given to the callback,
    including topic and Configuration,
    are only valid until the callback function returns.
    The callback function should make a copy if necessary.

    :param h: Client object pointer.
    :param cb: User callback function.
    :param userData: The SDK passes this value to the callback as it is.
       The SDK doesn't care if it's a valid pointer.

    :returns: :c:enumerator:`~EVP_RESULT.EVP_OK` on Success.

.. c:function:: EVP_RESULT EVP_sendState(struct EVP_client *h, const char *topic, const void *state, size_t statelen, EVP_STATE_CALLBACK cb, void *userData)

    Schedule to send the specified State for the specified topic.

    The callback :c:var:`cb` will be called
    in the context of this function or of
    :c:func:`EVP_processEvent`,
    when the request has been sent or cancelled.
    It will be invoked with one of
    the reasons defined by
    :c:enum:`EVP_STATE_CALLBACK_REASON`.

    .. warning::
          
        It's the caller's responsibility
        to keep the specified :c:var:`topic` and :c:var:`state`
        valid until the callback is called.
        Otherwise, the behaviour is undefined.
        (The SDK implementation might choose
        to keep pointers of them
        without making copies.)

    :param h: Client object pointer.
    :param topic: Destination topic.
    :param state: State data.
    :param statelen: State size in bytes.
    :param cb: User callback function.
    :param userData: The SDK passes this value to the callback as it is.
      The SDK doesn't care if it's a valid pointer.

    :returns: :c:enumerator:`~EVP_RESULT.EVP_OK` Success.

.. c:function:: EVP_RESULT EVP_sendMessage(struct EVP_client *h, const char *topic, const void *state, size_t statelen, EVP_MESSAGE_SENT_CALLBACK cb, void *userData)

    Schedule to send the specified message.

    The callback will be called
    in the context of this function or of
    :c:func:`EVP_processEvent`,
    when the request has been sent or cancelled.
    It will be invoked with one of
    the reasons defined by
    :c:enum:`EVP_MESSAGE_SENT_CALLBACK_REASON`.

    .. warning::
          
        It's the caller's responsibility
        to keep the specified :c:var:`topic` and :c:var:`state`
        valid until the callback is called.
        Otherwise, the behaviour is undefined.
        (The SDK implementation might choose
        to keep pointers of them
        without making copies.)

    :param h: Client object pointer.
    :param topic: Destination topic.
    :param state: State data.
    :param statelen: State size in bytes.
    :param cb: User callback function.
    :param userData: The SDK passes this value to the callback as it is.
      The SDK doesn't care if it's a valid pointer.

    :returns: :c:enumerator:`~EVP_RESULT.EVP_OK` Success.


.. c:struct:: EVP_telemetry_entry

    Describe a telemetry data

    A Key-Value pair to be sent as a telemetry.
    Both of the key and value should be a valid UTF-8 string.
    The value should be a string representation of a valid JSON value.

    .. c:member:: const char *key
        
        A key
        
    .. c:member:: const char *value
        
        A JSON value

.. c:function:: EVP_RESULT EVP_sendTelemetry(struct EVP_client *h, const struct EVP_telemetry_entry *entries, size_t nentries, EVP_TELEMETRY_CALLBACK cb, void *userData)

    Schedule to send the telemetry.

    The callback will be called
    in the context of this function or of
    :c:func:`EVP_processEvent`,
    when the request has been sent or cancelled.
    It will be invoked with one
    of the reasons defined by
    :c:enum:`EVP_TELEMETRY_CALLBACK_REASON`.

    .. warning::
        
        It's the caller's responsibility
        to keep the specified :c:var:`entries`
        valid until the callback is called.
        Otherwise, the behaviour is undefined.
        (The SDK implementation might choose
        to keep pointers of them
        without making copies.)

    :param h: Client object pointer.
    :param entries: The array of the telemetry data.
    :param nentries: The size of the array.
    :param cb: User callback function.
    :param userData: The SDK passes this value to the callback as it is.
      The SDK doesn't care if it's a valid pointer.

    :returns: :c:enumerator:`~EVP_RESULT.EVP_OK` Success.

.. c:function:: EVP_RESULT EVP_processEvent(struct EVP_client *h, int timeout_ms)

    Wait for an event and process it.

    This function is intended to be called in the main loop of
    the module instance.
    It waits for an event (e.g. Configuration update) and process it.
    It processes one pending event per call.

    :param h: Client object pointer.

    :param milliseconds:
      - 0 means immediate.
      - -1 means forever.

    :returns:

        - :c:enumerator:`~EVP_RESULT.EVP_OK`
          When at least one event has been processed.
        - :c:enumerator:`~EVP_RESULT.EVP_TIMEDOUT`
          When the period specified by `timeout_ms`
          has elapsed without any events.
        - :c:enumerator:`~EVP_RESULT.EVP_SHOULDEXIT`
          When the module instance is requested to stop
          and all events have been already dispatched.
          It should exit performing cleanup as soon as
          possible.

    See
    :c:enumerator:`~EVP_STATE_CALLBACK_REASON.EVP_STATE_CALLBACK_REASON_EXIT`,
    :c:enumerator:`~EVP_MESSAGE_SENT_CALLBACK_REASON.EVP_MESSAGE_SENT_CALLBACK_REASON_EXIT`,
    :c:enumerator:`~EVP_TELEMETRY_CALLBACK_REASON.EVP_TELEMETRY_CALLBACK_REASON_EXIT`,
    :c:enumerator:`~EVP_RPC_RESPONSE_CALLBACK_REASON.EVP_RPC_RESPONSE_CALLBACK_REASON_EXIT`,
    :c:enumerator:`~EVP_BLOB_CALLBACK_REASON.EVP_BLOB_CALLBACK_REASON_EXIT`

.. c:function:: EVP_RESULT EVP_setMessageCallback(struct EVP_client *h, EVP_MESSAGE_RECEIVED_CALLBACK incoming_cb, void *userData)

    Specifies a callback to invoke
    on every incoming message.

    This should not be called more than once
    for a :c:struct:`EVP_client`.
    Otherwise, the behaviour is undefined.

    The callback will be called
    in the context of :c:func:`EVP_processEvent`,
    upon reception of a message
    on any of the subscribed topics.

    .. note::

        Messages which have arrived
        before a successful call to
        this function might or might not be
        delivered to the specified callback.

    :param h: Client object pointer.
    :param incoming_cb: User callback function.
    :param userData: The SDK passes this value to the callback as it is.
      The SDK doesn't care if it's a valid pointer.

    :returns: :c:enumerator:`~EVP_RESULT.EVP_OK` Success.

.. c:function:: EVP_RESULT EVP_setRpcCallback(struct EVP_client *h, EVP_RPC_REQUEST_CALLBACK cb, void *userData)

    Specifies a callback to invoke on every incoming RPC call.

    This should not be called more than once for a :c:struct:`EVP_client`.
    Otherwise, the behaviour is undefined.

    The callback will be called
    in the context of :c:func:`EVP_processEvent`,
    upon reception of a RPC request.

    .. note::

        RPC calls which have arrived
        before a successful call of
        this function might or might not be delivered
        to the specified callback.

    For each invocation of the specified callback,
    :c:func:`EVP_sendRpcResponse` should be called
    exactly once with the ID given by the callback
    and Client object pointer specified to
    this function.
    It's the caller's responsibility to ensure that.
    Otherwise, the behaviour is undefined.

    :param h: Client object pointer.
    :param cb: User callback function.
    :param userData: The SDK passes this value to the callback as it is.
      The SDK doesn't care if it's a valid pointer.

    :returns: :c:enumerator:`~EVP_RESULT.EVP_OK` Success.

.. c:function:: EVP_RESULT EVP_sendRpcResponse(struct EVP_client *h, EVP_RPC_ID id, const char *response, EVP_RPC_RESPONSE_STATUS status, EVP_RPC_RESPONSE_CALLBACK cb, void *userData)

    Schedule to send the specified RPC response.

    This function can be used within the context of
    :c:type:`EVP_RPC_REQUEST_CALLBACK`.

    The callback will be called
    in the context of this function or
    of :c:func:`EVP_processEvent`,
    when the request has been sent or cancelled.
    It will be invoked with one
    of the reasons defined by
    :c:enum:`EVP_RPC_RESPONSE_CALLBACK_REASON`.

    For implementing named methods,
    the SDK provides a method-not-found response
    by setting the status flag to
    :c:enumerator:`~EVP_RPC_RESPONSE_STATUS.EVP_RPC_RESPONSE_STATUS_METHOD_NOT_FOUND`.
    In that case,
    the value of :c:var:`response`
    will be ignored.

    See the entire set of values
    of :c:enum:`EVP_RPC_RESPONSE_STATUS`
    to use in other situations.

    It's the caller's responsibility
    to keep the specified parameters valid
    until the callback is called.
    Otherwise, the behavior is undefined
    (The SDK implementation might choose
    to keep pointers of them
    without making copies).

    :param h: Client object pointer.
    :param id: The request ID from :c:enum:`EVP_RPC_REQUEST_CALLBACK`,
      to which you want to reply.
    :param response: The response.
      It should be a string representation of
      a valid JSON value.
    :param status: Response status.
    :param cb: User callback function.
    :param userData: The SDK passes this value to the callback as it is.
      The SDK doesn't care if it's a valid pointer.

    :returns:
    
      - :c:enumerator:`~EVP_RESULT.EVP_OK`
        in case of success.
      - :c:enumerator:`~EVP_RESULT.EVP_TOOBIG`
        when the payload is larger than the agent
        can handle (i.e. due to device constraints).
      - :c:enumerator:`~EVP_RESULT.EVP_INVAL`
        if the response is NULL.

.. c:function:: EVP_RESULT EVP_streamOutputOpen(struct EVP_client *h, const char *name, EVP_STREAM *stream)

    Opens an output stream.

    Streams allow for device-to-device
    and module-to-module communication,
    using an interface somewhat similar
    to BSD sockets.
    However, the actual implementation depends on
    which stream type has been selected
    from the deployment manifest.

    :param h: Client object pointer.
    :param name: Null-terminated string with the stream name.
      This must match the name of one
      of the streams defined on the deployment manifest.
    :param stream: *[OUT]* 
      On success, it shall be assigned to a non-negative integer.
      Otherwise, it shall be assigned to a negative integer.

    :returns:
    
      - :c:enumerator:`~EVP_RESULT.EVP_OK` Success.
      - :c:enumerator:`~EVP_RESULT.EVP_INVAL`
        if the stream was not defined by the
        deployment manifest or the stream was not defined for output.
      - :c:enumerator:`~EVP_RESULT.EVP_EXIST`
        if a stream with the same :c:var:`name` has already been opened.
      - :c:enumerator:`~EVP_RESULT.EVP_NOMEM`
        if memory could not be allocated.
      - :c:enumerator:`~EVP_RESULT.EVP_ERROR`
        if an unexpected error occurred.

Streams
=======

.. c:function:: EVP_RESULT EVP_streamInputOpen(struct EVP_client *h, const char *name, EVP_STREAM_READ_CALLBACK cb, void *userData, EVP_STREAM *stream)

    Opens an input stream.

    Streams allow for device-to-device
    and module-to-module communication,
    using an interface somewhat similar
    to BSD sockets.
    However, the actual implementation depends on
    which stream type has been selected
    from the deployment manifest.

    :param h: Client object pointer.
    :param name: Null-terminated string with the stream name.
      This must match the name of one
      of the streams defined on the deployment manifest.
    :param cb: User callback
      that shall be executed
      when input data becomes available.
    :param userData: Opaque pointer to user-defined data that shall
      be passed to :c:var:`cb`.
    :param stream: *[OUT]*
      On success, it shall be asssigned to a non-negative integer.
      Otherwise, it shall be assigned to a negative integer.

    :returns:

      - :c:enumerator:`~EVP_RESULT.EVP_OK` Success.
      - :c:enumerator:`~EVP_RESULT.EVP_INVAL`
        if the stream was not defined by the
        deployment manifest or the stream was not defined for input.
      - :c:enumerator:`~EVP_RESULT.EVP_EXIST`
        if a stream with the same :c:var:`name` has already been opened.
      - :c:enumerator:`~EVP_RESULT.EVP_NOMEM`
        if memory could not be allocated.
      - :c:enumerator:`~EVP_RESULT.EVP_ERROR`
        if an unexpected error occurred.

.. c:function:: EVP_RESULT EVP_streamClose(struct EVP_client *h, EVP_STREAM stream)

    Closes a stream previously opened with
    :c:func:`EVP_streamInputOpen` or
    :c:func:`EVP_streamOutputOpen`.

    :param h: Client object pointer.
    :param stream: Stream identifier.

    :returns:

      - :c:enumerator:`~EVP_RESULT.EVP_OK` Success.
      - :c:enumerator:`~EVP_RESULT.EVP_INVAL`
        if the stream was not defined by the deployment manifest.
      - :c:enumerator:`~EVP_RESULT.EVP_ERROR`
        if an unexpected error occurred.

.. c:function:: EVP_RESULT EVP_streamWrite(struct EVP_client *h, EVP_STREAM stream, const void *buf, size_t n)

    Sends a buffer over a stream
    previously opened with
    :c:func:`EVP_streamInputOpen` or
    :c:func:`EVP_streamOutputOpen`.

    :param h: Client object pointer.
    :param stream: Stream identifier.
    :param buf: Buffer to send.
    :param n: Buffer length.

    :returns:

      - :c:enumerator:`~EVP_RESULT.EVP_OK` Success.
      - :c:enumerator:`~EVP_RESULT.EVP_INVAL` 
        if the stream was not defined by the
        deployment manifest or was not configured for output.
      - :c:enumerator:`~EVP_RESULT.EVP_ERROR`
        if an unexpected error occurred.
