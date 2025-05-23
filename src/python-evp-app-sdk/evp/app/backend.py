# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

# Import the low-level C/C++ module
from enum import Enum

from . import _backend as _be
from .exceptions import get_exception, Denied

__all__ = ["Backend"]


def wrap_exceptions(func=None, whitelist=()):
    """
    Decorator to wrap interface return code into exception.

    Low level call return code is then checked and raise equivalent exception.

    Args:
        func (callabe, optional): If passed, wrap function without extra
            arguments.
        whitelist (tuple, optional): A list of error code to let call to be
            returned.
    """

    def decorator(func):
        def wrap(*args, **kwargs):
            ret = func(*args, **kwargs)
            if ret == _be.EVP_OK:
                return None
            if whitelist and ret in whitelist:
                return ret
            exception_cls = get_exception(ret)
            raise exception_cls(f"{func.__name__} failed with {ret}")

        return wrap

    if func:
        return decorator(func)
    return decorator


class _ClientMixIn:
    def __init__(self):
        r"""
        Initialize the SDK.

        Performs the required initialization operations for the module
        instance.

        This should be called by the main thread of the module instance.
        Otherwise, the behaviour is undefined.

        This should not be called more than once for a module instance.
        Otherwise, the behaviour is undefined.
        """
        self._client = _be.EVP_initialize()
        if self._client is None:
            raise Denied("Could not initialize EVP client connection")

    @wrap_exceptions
    def process_event(self, timeout_ms):
        r"""
        Wait for an event and process it.

        This function is intended to be called in the main loop of
        the module instance.
        It waits for an event (e.g. Configuration update) and process it.
        It processes one pending event per call.

        Args:
            handler (callable): A callable handler to process configuration
                                reception.
            timeout_ms (int):   Timeout in milliseconds:
                                0 means immediate.
                                -1 means forever.


        Return:
            When at least one event has been processed.

        Raise:
            TimedOut    When the period specified by `timeout_ms`
                        has elapsed without any events.
            ShouldExit  When the module instance is requested to stop.
                        It should exit performing cleanup as soon as
                        possible.
        """
        return _be.PyEVP_processEvent(self._client, timeout_ms)

    def get_workspace_directory(self, type=_be.EVP_WORKSPACE_TYPE_DEFAULT):
        r"""
        Returns the absolute path of the workspace directory
                for the calling Module Instance.

        The workspace directory with the default type (
        EVP_WORKSPACE_TYPE_DEFAULT) has the following characteristics:

        - Initially, the workspace directory is empty.

        - The workspace directory is left intact across a reboot of the Module
        Instace and/or the device. It can contain the contents left by the
        Module Instance before a reboot.

        - The Module Instance has an exclusive access to its workspace
        directory during its lifetime.

        - The Module Instance can access the workspace directory directly,
        using the OS interfaces like `open()` and `mkdir()`.

        - The Module Instance can request file operations on the workspace
        directory via the SDK. For example, upload from/download to a file
        on the workspace directory.

        - The Module Instance should only use regular files and directories on
        the workspace directory. If it attempts to create other file types,
        the behavior is undefined.

        - The agent will remove files in the workspace directory after
        the corresponding Module Instance has gone away. That is, at some point
        after a successful deployment of a new Deployment which doesn't contain
        the Module Instance anymore.

        Args:
            type: 'EVP_WORKSPACE_TYPE_DEFAULT'

        Return:
            The absolute path to the workspace directory.
        """
        return _be.EVP_getWorkspaceDirectory(self._client, type)


class _ConfigurationMixIn:
    @wrap_exceptions
    def set_configuration_handler(self, handler):
        r"""
        Register a callback function for Configuration.

        This should not be called more than once for a struct EVP_client *.
        Otherwise, the behaviour is undefined.

        The callback `cb` will be called in the context of this function or of
        'EVP_processEvent'.

        The callback will be called on the following events at least:

        - When the callback function is registered.
        - When the SDK received the latest Configuration.

        The SDK might coalesce multiple events into one.
        In that case, the callback will be called with the latest
        Configuration.

        The SDK might choose to invoke this callback more frequently than
        necessary. The callback function should not assume that the given
        Configuration was updated.

        All pointers given to the callback, including topic and
        Configuration, are only valid until the callback function
        returns. The callback function should make a copy if necessary.

        Args:
            handler (callable): A callable handler to process configuration
                                reception.

        Raise:
            TypeError  if handler is not callable
        """
        if not callable(handler):
            raise TypeError("`handler` argument is not a callable")

        return _be.PyEVP_setConfigurationCallback(self._client, handler)


class _StateMixIn:
    @wrap_exceptions
    def send_state(self, topic, state, complete):
        r"""
        Schedule to send the specified State for the specified topic.

        The callback `cb` will be called in the context of this function or of
        'EVP_processEvent', when the request has been sent or cancelled.
        It will be invoked with one of the reasons defined by
        'EVP_STATE_CALLBACK_REASON'.

        It's the caller's responsibility to keep the specified `topic` and
        `state` valid until the callback is called. Otherwise, the behaviour is
        undefined.
        (The SDK implementation might choose to keep pointers of them without
        making copies.)

        Args:
            topic (str):            Destination topic.
            state (str|bytearray):  State data.
            complete (callable):    Completion handler

        Raise:
            TypeError  if complete is not callable
        """
        if not callable(complete):
            raise TypeError("`complete` argument is not a callable")

        return _be.PyEVP_sendState(
            self._client, topic, state, len(state), complete
        )


class _MessageMixIn:
    @wrap_exceptions
    def set_message_callback(self, handler):
        r"""
        Specifies a callback to invoke on every incoming message.

        This should not be called more than once for a struct EVP_client *.
        Otherwise, the behaviour is undefined.

        The callback will be called in the context of EVP_processEvent,
        upon reception of a message on any of the subscribed topics.

        Messages which have been arrived before a successful call of this
        function might or might not be delivered to the specified callback.

        Args:
            handler (callable): A callable handler to process messages
                                reception.

        Raise:
            TypeError  if handler is not callable
        """
        if not callable(handler):
            raise TypeError("`handler` argument is not a callable")

        return _be.EVP_setMessageCallback(self._client, handler)

    @wrap_exceptions
    def send_message(self, topic, state, statelen, complete):
        r"""
        Schedule to send the specified message.

        The callback will be called in the context of this function or of
        EVP_processEvent(), when the request has been sent or cancelled.
        It will be invoked with one of the reasons defined by
        'EVP_MESSAGE_SENT_CALLBACK_REASON'.

        It's the caller's responsibility to keep the specified topic and State
        valid until the callback is called.
        Otherwise, the behaviour is undefined.
        (The SDK implementation might choose to keep pointers of them without
        making copies.)

        Args:
            topic (str): Destination topic
            state (str|bytearray): State data
            complete (callable): Completion handler.

        Raise:
            TypeError  if complete is not callable
        """
        if not callable(complete):
            raise TypeError("`complete` argument is not a callable")

        return _be.EVP_sendMessage(self._client, topic, state, complete)


class _TelemetryMixIn:
    @wrap_exceptions
    def send_telemetry(self, entries, complete):
        r"""
        Schedule to send the telemetry.

        The callback will be called in the context of this function or of
        EVP_processEvent(), when the request has been sent or cancelled.
        It will be invoked with one of the reasons defined by
        'EVP_TELEMETRY_CALLBACK_REASON'.

        It's the caller's responsibility to keep the specified entries and
        data referenced by them valid until the callback is called.
        Otherwise, the behaviour is undefined.
        (The SDK implementation might choose to keep pointers of them without
        making copies.)

        Args:
            entries (list[tuple]): The array of the telemetry data.
            complete (callable): Completion handler.

        Raise:
            TypeError  if complete is not callable
        """
        if not callable(complete):
            raise TypeError("`complete` argument is not a callable")

        return _be.PyEVP_sendTelemetry(self._client, entries, complete)


class _CommandMixIn:
    @wrap_exceptions
    def set_command_handler(self, handler):
        r"""
        Specifies a handler to invoke on every incoming command call.

        This should not be called more than once for a struct EVP_client *.
        Otherwise, the behaviour is undefined.

        The callback will be called in the context of EVP_processEvent,
        upon reception of a RPC request.

        RPC calls which have been arrived before a successful call of this
        function might or might not be delivered to the specified callback.

        For each invocation of the specified callback,
        'PyEVP_sendRpcResponse' should be called exactly once with
        the ID given by the callback and struct EVP_client * specified to
        this function.
        It's the caller's responsibility to ensure that.
        Otherwise, the behaviour is undefined.

        Args:
            handler (callable): A callable handler to process messages
                                reception.

        Raise:
            TypeError  if handler is not callable
        """
        if not callable(handler):
            raise TypeError("`handler` argument is not a callable")

        return _be.PyEVP_setRpcCallback(self._client, handler)

    @wrap_exceptions
    def send_command_response(self, id, response, status, complete):
        r"""
        Schedule to send the specified RPC response.

        This function can be used within the context of
        'EVP_RPC_REQUEST_CALLBACK'.

        The callback will be called in the context of this function or of
        EVP_processEvent(), when the request has been sent or cancelled.
        It will be invoked with one of the reasons defined by
        'CommandResponseReason'.

        For implementing named methods, the SDK provides a method-not-found
        response by setting the status flag to
        'CommandResponseStatus.METHOD_NOT_FOUND'. In that case, the
        value of 'response' will be ignored.

        See the entire set  * of values of the 'CommandResponseStatus'
        enum for values to use in other situations.

        It's the caller's responsibility to keep the specified parameters
        valid until the callback is called. Otherwise, the behavior is
        undefined (The SDK implementation might choose to keep pointers
        of them without making copies).

        Args:
            id (int):   The request ID from request handler, to which you want
                        to reply.
            response:   The response. It should be a string representation of
                        a valid JSON value.
            status:     A value from the 'CommandResponseStatus' enum.
            complete (callable): Completion handler.

        Raise:
            TypeError   if complete is not callable
            TooBig      when the payload is larger than the agent
                        can handle (i.e. due to device constraints).
            Invalid     if response is None.
        """
        if not callable(complete):
            raise TypeError("`complete` argument is not a callable")

        if isinstance(status, Enum):
            status = status.value

        return _be.PyEVP_sendRpcResponse(
            self._client, id, response, status, complete
        )


class _StreamMixIn:
    @wrap_exceptions
    def stream_output_open(self, name):
        r"""
        Opens an output stream.

        Streams allow for device-to-device and module-to-module
        communication, using an interface somewhat similar to BSD sockets.
        However, the actual implementation depends on which stream type has
        been selected from the deployment manifest.

        Args:
            name:       Null-terminated string with the stream name.
                        This must match the name of one
                        of the streams defined on the deployment manifest.

        Return:
            On success, it shall be assigned to a non-negative integer.
            Otherwise, it shall be assigned to a negative integer.

        Raise:
            Invalid     if the stream was not defined by the
                        deployment manifest or the stream was not defined for
                        output.
            Exists      if a stream with the same 'name' has
                        already been opened.
            NoMem       if memory could not be allocated.
            Unknown     if an unexpected error occurred.
        """
        # TODO
        # return _be.EVP_streamOutputOpen(self._client, name, stream)
        raise NotImplementedError()

    @wrap_exceptions
    def stream_input_open(self, name, handler):
        r"""
        Opens an input stream.

        Streams allow for device-to-device and module-to-module
        communication, using an interface somewhat similar to BSD sockets.
        However, the actual implementation depends on which stream type has
        been selected from the deployment manifest.

        Args:
            name:       Null-terminated string with the stream name.
                        This must match the name of one
                        of the streams defined on the deployment manifest.
            handler:    Handler that shall be executed when input data
                        becomes available.

        Return:
            On success, it shall be assigned to a non-negative integer.
            Otherwise, it shall be assigned to a negative integer.

        Raise:
            Invalid     if the stream was not defined by the
                        deployment manifest or the stream was not defined for
                        output.
            Exists      if a stream with the same 'name' has
                        already been opened.
            NoMem       if memory could not be allocated.
            Unknown     if an unexpected error occurred.
        """
        # TODO
        # check_call(
        #    _be.EVP_streamInputOpen(self._client, name, handler, stream)
        # )
        raise NotImplementedError()

    @wrap_exceptions
    def stream_close(self, stream):
        r"""
        Closes a stream previously opened with 'EVP_streamOpen'.

        Args:
            stream:	Stream identifier.

        Raise:
            Invalid     if the stream was not defined by the
                        deployment manifest or the stream was not defined for
                        output.
            Unknown     if an unexpected error occurred.
        """
        # TODO
        #  return _be.EVP_streamClose(self._client, stream)
        raise NotImplementedError()

    @wrap_exceptions
    def stream_write(self, stream, buf):
        r"""
        Sends a buffer over a stream previously opened with
        'EVP_streamOpen'.

        Args:
            stream:	Stream identifier.
            buf:    Buffer to send.

        Raise:
            Invalid     if the stream was not defined by the
                        deployment manifest or the stream was not defined for
                        output.
            Unknown     if an unexpected error occurred.
        """
        # TODO
        #  return _be.EVP_streamWrite(self._client, stream, buf)
        raise NotImplementedError()


class _BlobOperationMixIn:
    @wrap_exceptions
    def blob_operation(self, type, op, request, store, complete):
        r"""
        Schedule a blob operation

        Enqueues the specified  operation `op` on a blob of the given `type`
        which is described by `request`, linking it to the given data specified
        by `store`

        Args:
            type:        'EVP_BLOB_TYPE_AZURE_BLOB' or 'EVP_BLOB_TYPE_EVP'
                            or 'EVP_BLOB_TYPE_EVP_EXT'
            op:          Whether to GET or PUT the blob.
            request: A pointer to a structure to specify requestparameters.
                            if `type` is 'EVP_BLOB_TYPE_AZURE_BLOB', it is
                            'EVP_BlobRequestAzureBlob'.
                            if `type` is 'EVP_BLOB_TYPE_EVP', it is
                            'EVP_BlobRequestEvp'.
                            if `type` is 'EVP_BLOB_TYPE_EVP_EXT', it is
                            'EVP_BlobRequestEvpExt'.
                            if `type` is 'EVP_BLOB_TYPE_HTTP', it is
                            'EVP_BlobRequestHttp'.
                            if `type` is 'EVP_BLOB_TYPE_HTTP_EXT', it is
                            'EVP_BlobRequestHttpExt'.
            store:  The info about the local store for the data.
                    The pointed info is copied as needed, so it is
                    responsibility of the caller to free it.
            complete: Called when completed.
        """
        # TODO
        # check_call(
        #     _be.EVP_blobOperation(
        #         self._client, type, op, request, localStore, cb, user
        #     )
        # )
        raise NotImplementedError()


class Backend(
    _ClientMixIn,
    _ConfigurationMixIn,
    _StateMixIn,
    _TelemetryMixIn,
    _CommandMixIn,
    # _BlobOperationMixIn,
    # _StreamMixIn,
    # _MessageMixIn,
):
    """
    Low level backend wrapper

    Features are split in mix ins classes.
    Implemented and available features are the one listed in Backend class
    inherited mix-ins classes.
    """
