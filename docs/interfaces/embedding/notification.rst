.. SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
..
.. SPDX-License-Identifier: Apache-2.0

.. c:function:: int evp_agent_notification_subscribe(struct evp_agent_context *ctxt, const char *event, int (*cb)(const void *args, void *user_data), void *user_data)

    Subscribes to an event using a custom callback.

    :param ctxt: Opaque pointer to internal agent-related data.
    :param event: Human-readable string that uniquely identifies the event.
        It is recommended that event categories are defined similarly to
        directories i.e., using the forward slash '/' character. For example:
        "event-group/event" .
    :param cb: User-defined callback to attach to a given event. Several
        callbacks can be attached to a single event by calling this function
        repeatedly.
    :param user_data: Opaque pointer to user-defined data. The library shall
        make no attempts to dereference this pointer, and it can be safely
        assigned to a null pointer.
        
    :return: Returns zero on success, non-zero otherwise.
    
    .. warning::
        
        ctxt is currently ignored
        by this API but a valid pointer
        must be assigned
        for future compatibility.

    .. note::
        
        This function will create
        a deep copy of all of its arguments.
    
    .. note:: 
        
        This function is called under
        the EVP Agent context.
        In order to ensure
        the stability of the EVP agent,
        it is recommended that
        long-running or blocking user-defined tasks
        are either avoided or moved
        to a separate thread.
        
.. c:function:: int evp_agent_notification_publish(struct evp_agent_context *ctxt, const char *event, const void *args)

    Triggers a specific event that will call its associated callbacks.
    
    :param ctxt: Opaque pointer to internal agent-related data.
    :param event: Human-readable string that uniquely identifies the event.
    :param args: Event-specific arguments. The callback is then responsible
        to cast this data to the appropriate type.
    :return: Returns zero on success, non-zero otherwise.
