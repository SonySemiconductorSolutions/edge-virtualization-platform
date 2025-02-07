

.. SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
..
.. SPDX-License-Identifier: Apache-2.0

.. c:struct:: evp_agent_context

    Agent context object.

    This contains the runtime data
    for the instance of
    the running agent.

.. c:function:: struct evp_agent_context *evp_agent_setup(const char *progname)

    Initialize an agent instance context object.

    This must be called to create an agent context
    to pass to any ``evp_agent_*()`` functions
    that require :c:struct:`evp_agent_context` as parameter.

    It takes a c string as parameter to set
    the program name to be printed
    in error basic log functions :c:func:`xerr` and :c:func:`xerrx`.

    The agent :ref:`status` is expected to remain
    :c:enumerator:`~evp_agent_status.EVP_AGENT_STATUS_INIT` at this stage.

    :param progname: Program name

    :returns:

        A :c:struct:`evp_agent_context` object pointer.

    :errors:

        The function guaranties to return
        a valid allocated pointer,
        or abort if object memory allocation failed.

    **Example**:

    .. code:: C

        int
        main(int argc, char *argv[])
        {
            struct evp_agent_context *ctxt = evp_agent_setup(argv[0]);
            ...
        }

.. c:function:: int evp_agent_start(struct evp_agent_context *ctxt)

    Start the agent.

    Runs all initialization procedures
    to start up the agent.

    The agent :c:enum:`evp_agent_status` is expected to pass to
    :c:enumerator:`~evp_agent_status.EVP_AGENT_STATUS_READY`
    when startup is complete.

    :param ctxt: Opaque pointer to internal agent-related data.

    :returns: Always return ``0``.

    :errors:

        This function may abort the program
        if TLS cannot be initialised
        or for other internal critical
        failure reasons.

.. c:function:: int evp_agent_loop(struct evp_agent_context *ctxt)

    This is the agent runtime routine
    to keep calling in an infinite loop.

    .. note::

        This is expected to block until
        agent events are emitted
        for processing.

        It is therefore necessary
        to keep this call in the loop
        without any other blocking
        or time consuming calls,
        to avoid any unwanted hangs.
        or delays.

    It is expected to handle
    the following status transitions:

    * :c:enumerator:`~evp_agent_status.EVP_AGENT_STATUS_CONNECTING` to
      :c:enumerator:`~evp_agent_status.EVP_AGENT_STATUS_CONNECTED`
      when agent becomes connected
      to the hub.
    * :c:enumerator:`~evp_agent_status.EVP_AGENT_STATUS_CONNECTED` to
      :c:enumerator:`~evp_agent_status.EVP_AGENT_STATUS_CONNECTING`
      when agent gets disconnected
      from the hub
      and is re-establishing connection.
    * :c:enumerator:`~evp_agent_status.EVP_AGENT_STATUS_DISCONNECTING` to
      :c:enumerator:`~evp_agent_status.EVP_AGENT_STATUS_DISCONNECTED`
      when agent disconnection is complete
      after being requested
      to disconnect from hub.

    .. warning::

        If routine is called after
        a successful stop (:c:func:`evp_agent_stop`)
        the function will return ``0``
        and no events will be processed.

    :param ctxt: Opaque pointer to internal agent-related data.

    :returns:

        Returns ``0`` in mominal case
        or non-zero if an error occurred.

    :errors:

        If the agent has not been started
        with the call to :c:func:`evp_agent_start`
        (:c:enumerator:`~evp_agent_status.EVP_AGENT_STATUS_INIT`),
        the function will return ``-1``
        and not process any event.

    **Example**:

    .. code:: C

            int ret = 0;
            while (ret == 0) {
                ret = evp_agent_loop(ctxt);
            }

.. c:function:: int evp_agent_stop(struct evp_agent_context *ctxt)

    Proceed to stopping the agent.

    Shuts down all running instances,
    and free internal resources.

    The agent :ref:`status` is expected to pass to
    :c:enumerator:`~evp_agent_status.EVP_AGENT_STATUS_STOP` when shudown
    is complete.

    .. note::

        Currently, the implementation
        does not support :c:func:`evp_agent_start`
        to be called again after a successful stop.

    :param ctxt: Opaque pointer to internal agent-related data.

    :Returns: Always return ``0``.

.. c:function:: int evp_agent_free(struct evp_agent_context *ctxt)

    Free allocated agent context
    and related resources.

    This must be called only after
    :c:func:`evp_agent_stop` had been called.

    :param ctxt: Opaque pointer to internal agent-related data.
