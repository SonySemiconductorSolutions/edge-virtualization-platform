.. SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
..
.. SPDX-License-Identifier: Apache-2.0

.. _embedding:

EVP Agent SDK
#############

.. note::

    Embedding API interfaces
    are defined in ``include/evp/agent.h``.

Although this project provides a stand-alone
EVP Agent executable ``evp-agent``,
it can be embedded in a user application with
EVP Agent SDK library ``libevp-agent``.

Runtime
*******

Embedding the agent in user application requires
the following, as a minimum:

#. Initialize an agent instance with :c:func:`evp_agent_setup`,
   which returns a instance of the agent context
   that is then required by all ``evp_agent_*()`` functions.
#. Startup the agent with :c:func:`evp_agent_start`.
#. Call :c:func:`evp_agent_loop` within a loop
   that the user may break as they require or
   when the function returns an error.
   If previously connected see #3.
#. Stop the agent with :c:func:`evp_agent_stop`.
#. Free resources with :c:func:`evp_agent_free`.
#. Then the application can safely exit.

.. code:: C

    int
    main(int argc, char *argv[])
    {
        struct evp_agent_context *agent = evp_agent_setup(argv[0]);

        int ret = evp_agent_start(agent);
        if (ret)
            goto release;

        while (ret == 0) {
            ret = evp_agent_loop(agent);
        }

        evp_agent_stop(agent);
    release:
        evp_agent_free(agent);
        return 0;
    }

.. include:: embedding/runtime.rst

Network Connection
******************

The network connection can be controlled by the user.

Calling :c:func:`evp_agent_connect`
will initiate connection to the network (Hub and Web).
Agent can then be disconnected
with :c:func:`evp_agent_disconnect`.

The user may control connection
as they see fit,
as long as it called
after :c:func:`evp_agent_start` and
before :c:func:`evp_agent_stop`.

It is standard to initiate connection
after agent startup,
and disconnect before stopping:

.. code:: C

    int
    main(int argc, char *argv[])
    {
        struct evp_agent_context *agent = evp_agent_setup(argv[0]);

        int ret = evp_agent_start(agent);
        if (ret)
            goto release;

        ret = evp_agent_connect(agent);
        if (ret)
            goto stop;

        while (ret == 0) {
            ret = evp_agent_loop(agent);
        }

        evp_agent_disconnect(agent);
    stop:
        evp_agent_stop(agent);
    release:
        evp_agent_free(agent);
        return 0;
    }

.. include:: embedding/connection.rst

.. _status:

Status
******

It is possible to query
the agent status with :c:func:`evp_agent_get_status`,
to handle different use cases according
to the agent state.

See :c:enum:`evp_agent_status` for reference.

As a convenience,
:c:func:`evp_agent_ready` queries
the readiness of the agent after startup,
It returns :c:var:`true` if agent
is not in :c:enumerator:`~evp_agent_status.EVP_AGENT_STATUS_INIT` state.

.. include:: embedding/status.rst

Platform
********

Platform allows user to redefine methods
that may need specific implementation
according to the platform
the agent is running on.

A constant :c:struct:`evp_agent_platform` object
may be declared and initialized with
the user implemeted methods,
otherwise standard POSIX platform methods
will be used.

A method can be overloaded by defining
it in the user code and initializing
the platform object with the user method.
All pointers left :c:var:`NULL`
will not overwrite default methods.

Then the overloaded platform
must be registered with
:c:func:`evp_agent_platform_register`
to set the platform methods.

See :ref:`design/architecture/platform` documentation.

.. code:: C

    int evp_agent_platform_register(struct evp_agent_context *ctxt,
                    const struct evp_agent_platform *p);

.. note::

    This method must be called at most once
    before :c:func:`evp_agent_start`.

Example:

.. code:: C

    void
    my_out_of_memory(const char *file, int line, const char *where, size_t siz)
    {
        ...
    }

    void *
    my_malloc(size_t sz)
    {
        ...
    }

    void
    my_free(void *p)
    {
        ...
    }

    static struct evp_agent_platform my_platform = {
        .out_of_memory = my_out_of_memory,
        .secure_malloc = my_malloc,
        .secure_free = my_free,
    };

    int main(const int c, const char *argv[])
    {
        struct evp_agent_context *agent = evp_agent_setup(argv[0]);
        evp_agent_platform_register(agent, &my_platform);

        ...

        return 0;
    }

.. include:: embedding/platform.rst

.. _notifications:

Notification
************

The embedded API provides a way
to be notified upon some internal events.

The event to watch must be register with
:c:func:`evp_agent_notification_subscribe`.

See :ref:`design/architecture/notifications`
documentation.

Example:

.. code:: C

    int on_reconcile_status(const void *args, void *user_data)
    {
        struct reconcileStatusNotify *notify_value = args;

        printf("Reconcile status of %s is %s", notify_value->deploymentId,
               notify_value->reconcileStatus);
        return 0;
    }

    int main(const int c, const char *argv[])
    {
        struct evp_agent_context *agent = evp_agent_setup(argv[0]);
        evp_agent_notification_subscribe(agent, "deployment/reconcileStatus",
                                         NULL);

        ...

        return 0;
    }

.. include:: embedding/notification.rst

Deployment
**********

Individual instances can be stopped with
:c:func:`evp_agent_stop_instance`.
There might be little need in production
but is used for testing.

User may request to undeploy
all instances and modules
(for example, before a device reboot).
This can be achieved with :c:func:`evp_agent_undeploy_all`.

.. include:: embedding/deployment.rst

Messaging
*********

It is possible to inject messages to the agent,
like the Hub would, through MQTT requests,
with :c:func:`evp_agent_send`.
Even if this has little usage in production,
it is very useful for testing.

Individual instances can be stopped with
:c:func:`evp_agent_stop_instance`.
There might be little need for this in production
but is useful for testing.

User may request to undeploy
all instances and modules
(for example, before a device reboot).
This can be achieved with :c:func:`evp_agent_undeploy_all`.

.. include:: embedding/messaging.rst

Modules
*******

This section presents functions related to
module state.

.. include:: embedding/modules.rst

Thread safety
*************

All ``evp_agent_*()`` functions
are mutex protected,
therefore thread-safe.
