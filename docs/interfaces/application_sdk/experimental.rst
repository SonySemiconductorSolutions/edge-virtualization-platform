.. SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
..
.. SPDX-License-Identifier: Apache-2.0

.. _evp_streams:

Experimental features
*********************

EVP streams
===========

Introduction
------------

EVP streams are meant as a communication mechanism between module instances.
Their design is closely inspired by the POSIX sockets interface, but streams
are opinionated towards asynchronous communication. This means, among other
things:


* Write operations do not block the calling thread. Data shall be transferred
  asynchronously, probably from another thread.
* Users do not have to read synchronously. Instead, a user-defined callback
  shall be triggered once input data is available.

Similarly to POSIX sockets, EVP streams do not assume a specific transport
layer or network interface, but are extensible to any implementation that
provides the semantics required by its public interface, described below:

.. code-block:: c

   EVP_RESULT EVP_streamInputOpen(struct EVP_client *h, const char *name, EVP_STREAM_READ_CALLBACK cb, void *userData, EVP_STREAM *stream);
   EVP_RESULT EVP_streamOutputOpen(struct EVP_client *h, const char *name, EVP_STREAM *stream);
   EVP_RESULT EVP_streamClose(struct EVP_client *h, EVP_STREAM stream);
   EVP_RESULT EVP_streamWrite(struct EVP_client *h, EVP_STREAM stream, const void *buf, size_t n);

Where:

*
  ``EVP_streamInputOpen`` sets up a stream that must be configured with direction
  ``in`` and name ``name`` from the ``deploymentManifest``. ``cb`` refers to a
  user-defined callback that will be triggered by the implementation as soon
  as input data is available. ``user`` is an opaque pointer that is passed to the
  callback pointed to by ``cb``. The implementation will not attempt to read or
  modify the contents pointed to by ``user``. Therefore, ``user`` can also be a null
  pointer.

*
  ``EVP_streamOutputOpen`` sets up a stream that must be configured with
  direction ``out`` and name ``name`` from the ``deploymentManifest``.

*
  ``EVP_streamClose`` releases the resources allocated by a stream opened
  with ``EVP_streamInputOpen`` or ``EVP_streamOutputOpen``. For streams opened with
  ``EVP_streamOutputOpen``\ , ``EVP_streamClose`` shall flush any pending outgoing
  messages before closing the stream.

*
  ``EVP_streamWrite`` must queue the request defined by the ``const void *``\ ,
  which is the user payload, and the ``size_t``\ , which defines its size. This
  function must return immediately, and therefore is not required to send data
  over the network. This should be done asynchronously, for example, via a separate
  thread. This function can only be used with streams previously opened with
  ``EVP_streamOutputOpen``.

Another significant difference between POSIX sockets and EVP streams is
their direction: while POSIX sockets can be bidirectional, EVP streams are
*only* unidirectional. In other words, EVP streams can be either ``in`` or
``out``\ , but never both. As a consequence, using ``EVP_streamWrite`` on an
``in`` stream will return an error.

Bidirectional streams are currently not planned, but it should still be
possible to implement them. Otherwise, they might limit some usecases.

Use cases
---------

EVP streams have been designed for real-world scenarios, such as:

* A network of cameras that send information to a central server, without
  relying on a MQTT broker.

Usage
-----

Two things are required from the user side:

Add ``streams`` to the ``deploymentManifest``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If EVP streams are used, the ``instanceSpecs`` object from a ``deploymentManifest``
must include a ``streams`` object in it, with at least one stream definition.
The example below shows an output stream, called ``my-stream``\ , of type ``example``\ :

.. code-block:: json

   {
       "instanceSpecs": {
           "instance-name": {
               "streams": {
                   "my-stream": {
                       "type": "example",
                       "direction": "out",
                       "parameters": {
                           // Type-specific parameters, if any.
                       }
                   }
               }
           }
       }
   }

The definition for the ``parameters`` object is entirely ``type``\ -defined, and
might as well not exist if the stream type does not require it.

The following stream types are supported:

* ``nng``\ : based on the `nng`_ library. In
  the case of an agent using a local SDK implementation, ``nng`` streams are
  only available if ``EVP_AGENT_LOCAL_SDK_NNG_STREAMS`` is defined. Moreover,
  ``nng`` are known to have issues on NuttX + ESP32; issues that have not been
  investigated.
* ``null``\ : a placeholder implementation only meant for testing purposes.
  ``null`` streams are always supported by the agent.
* ``posix``\ : only uses the POSIX C standard library, which makes it a more
  lightweight and convenient choice, compared to ``nng`` streams.

Take into account that, if a module does not use any stream, the ``streams``
object must not exist.

Open the stream from the module instance
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When a module instance has been started with a set of configured streams, a
call to ``EVP_streamInputOpen`` or ``EVP_streamOutputOpen`` will look up the
current ``deploymentManifest`` to check whether the stream was defined
accordingly.

The example module below shows how to open an output stream called
``my-stream``\ :

.. code-block:: c

   int main(void)
   {
       EVP_client *h = EVP_initialize();
       /* Pointer validation. */
       EVP_stream stream;
       EVP_RESULT result = EVP_streamOutputOpen(h, "my-stream", &stream);

       if (result != EVP_OK) {
           /* Handle error. */
       }

       /* Application code. */
   }

If ``my-stream`` could not be found on the ``streams`` JSON object belonging to
the calling module instance, ``EVP_INVAL`` will be returned. See the
documentation for ``EVP_streamInputOpen`` and ``EVP_streamOutputOpen`` for a list of possible error values.

Once a stream has been opened successfully:

* Input streams shall get their user-defined callback triggered once input
  data is available.
* Output streams can call ``EVP_streamWrite``.

High-level design
-----------------

As stated above, one of the design goals behind EVP streams is extensibility.
This means any protocol that provides a reliable, stream-oriented connection
is eligible as a stream type, such as the TCP protocol.

File hierarchy
--------------

EVP streams are implemented with the following source files from
the `streams`_ directory:

* `stream.h`_: provides the type definitions
  and function declarations used internally by
  the agent and ``evpmodulesdk``.
* `stream.c`_: provides the protocol-agnostic code
  shared among all stream types.

However, this implementation must be complemented with:

* SDK-specific implementation:

  * |local evpmoduledsk|_.
  * |remote evpmoduledsk|_.

.. |local evpmoduledsk| replace:: Local ``evpmoduledsk``
.. _local evpmoduledsk: https://github.com/SonySemiconductorSolutions/edge-virtualization-platform/tree/main/src/libevp-agent/sdk.c
.. |remote evpmoduledsk| replace:: Remote ``evpmoduledsk``
.. _remote evpmoduledsk: https://github.com/SonySemiconductorSolutions/edge-virtualization-platform/tree/main/src/libevp-app-sdk/sdk.c

* Stream type-specific implementation:

  * `nng.c <https://github.com/SonySemiconductorSolutions/edge-virtualization-platform/tree/main/src/libevp-agent/stream/nng.c>`_.
  * `null.c <https://github.com/SonySemiconductorSolutions/edge-virtualization-platform/tree/main/src/libevp-agent/stream/null.c>`_.
  * `posix.c <https://github.com/SonySemiconductorSolutions/edge-virtualization-platform/tree/main/src/libevp-agent/stream/posix.c>`_.

Private interfaces
------------------

``stream.h`` declares the functions that must be implemented by the SDK
implementation:

.. code-block:: c

   struct stream_impl *stream_from_stream(struct EVP_client *h, EVP_STREAM stream);
   struct stream_impl *stream_from_name(struct EVP_client *h, const char *name);
   EVP_RESULT stream_insert(struct EVP_client *h, struct stream_impl *si);
   EVP_RESULT stream_remove(struct EVP_client *h, struct stream_impl *si);
   int stream_insert_read_event(struct EVP_client *h, struct sdk_event_stream_read_available *ev);

where:

* ``stream_from_stream``\ : a thin wrapper over ``stream_impl_from_stream``\ , required
  since the ``TAILQ`` containing the available streams is defined on
  ``struct EVP_client``\ , whose definition in turn depends on the SDK
  implementation. This function creates the relationship between a ``EVP_STREAM``
  (an opaque integer type) and ``struct stream_impl *`` (the internal data
  structure used across all files on this component).
* ``stream_from_name``\ : a thin wrapper over ``stream_impl_from_name``, required
  since the ``TAILQ`` containing the available streams is defined on
  ``struct EVP_client``, whose definition in turn depends on the SDK
  implementation.

Stream type-specific interfaces
-------------------------------

An instance of the following data type must be defined for each stream type:

.. code-block:: c

   struct stream_ops {
       EVP_RESULT (*init)(struct stream_impl *);
       int (*close)(struct stream_impl *);
       int (*write)(const struct stream_impl *, const void *, size_t);
       int (*read)(struct stream_impl *, struct stream_read *sr);
       void (*free_msg)(void *);
       int (*atexit)(void);
   };

where:

* ``init`` performs the required type-specific initialization of a stream.
  The desired stream configuration is contained inside the ``cfg`` member on
  the ``struct stream_impl`` passed to this function. A status code as defined
  by ``EVP_RESULT`` must be returned. If not ``EVP_OK``\ , the status code shall be
  propagated to the user.
* ``close`` must deallocate any resources previously allocated by a call
  to ``init``. Returns zero if successful, non-zero otherwise.
* ``write`` must queue the request defined by the ``const void *``\ , which is
  the user payload, and the ``size_t``\ , which defines its size. This function
  must return immediately, and therefore is not required to send data over
  the network. This should be done asynchronously e.g.: via a separate thread.
* ``read`` is called from a separate thread by ``stream.c`` and must lock until
  a message is received from a peer. When a message is received from a peer,
  ``read`` must fill the ``struct stream_read`` passed to it. See chapter
  "Filling a ``struct stream_read``\ " for further reference.
* ``free_msg`` defines how to release the resources as given by the
  ``free_args`` member on ``struct stream_read``.
* ``atexit`` defines a function handler that will be registered to the
  standard ``atexit(3)`` function. It can be a null pointer if no actions are
  required.

  * Note: ``atexit`` was required by ``nng`` streams so as to avoid a false
    positive from ``valgrind(1)`` when closing the agent.

Input streams
-------------

Since EVP streams are meant to receive messages asynchronously from peers,
this requires setting up a separate thread that can block until a message
is received, without blocking the normal execution flow of the agent or
SDK.

This thread is required for all stream types,
so it is implemented by `stream.c`_
. The thread body is defined by the function ``in_thread``. There, it triggers
the type-specific ``read`` callback and, if successful, it shall call
``notify_read_available`` to create a new
``struct sdk_event_stream_read_available`` event.

However, implementations must fill a ``struct stream_read`` instance, which
contains the following members:

.. code-block:: c

   struct stream_read {
       EVP_STREAM_PEER_ID id;
       const void *buf;
       size_t n;
       void *free_args;
   };

where:

* ``id`` is an opaque identifier that shall be propagated to user code, and
  is typically meant to identify a connection. User must not make any
  assumptions about the meaning behind this value, as it is entirely
  implementation-defined. This member was added as a compromise to distinguish
  several peers on unencrypted connections. However, it is meant to be replaced
  with a strong authentication method once TLS support is added to EVP streams.
* ``buf`` is the pointer where the input message is stored. This is defined
  as a read-only pointer since users are not meant to modify it. However,
  if ``buf`` needs to be released by the implementation, ``free_args`` can be used
  for this purpose.
* ``n`` is the length of the input message.
* ``free_args`` is an optional pointer that shall be passed to the ``free``
  callback in ``struct sdk_event_stream_read_available``, once the event has
  been processed by the user-defined callback. It can be a null pointer if no
  resources need to be released. It can also point to the same buffer pointed
  to by ``buf``.

Filling a ``struct stream_read``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When an input message is received from a peer, a ``struct stream_read`` must
be filled by the implementation so as to generate a
``struct sdk_event_stream_read_available`` instance that can be appended to the
``struct EVP_client`` member ``events``.

Inserting a ``struct sdk_event_stream_read_available``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Once an input message is received, `stream.c`_
will call ``stream_insert_read_event`` in order to ask the SDK implementation
how the event should be stored in the event queue.

Local SDK
^^^^^^^^^

Since ``EVP_client`` was already designed to be accessed from multiple threads
in the case of local SDK, the implementation for ``stream_insert_read_event``
was relatively straightforward: the ``struct sdk_event_stream_read_available``
instance can be safely appended into the queue as long as the ``sdk_{un}lock``
function pair is called.

Remote SDK
----------

A new challenge appeared when attempting to integrate this functionality:
as opposed to local SDK, remote SDK has no mechanism to access a
``struct EVP_client`` instance in a thread-safe manner.

The possibility to add mutexes in various places to ensure thread-safety is not implemented
as it would have added a significant amount of complexity
to the existing remote SDK implementation, which already suffers from
unneeded complexity.

Therefore, it was preferred to take advantage
of the call to ``poll(2)`` on `client_io.c`_.
Since this system call can monitor several file descriptors at once, it can
be used to monitor events coming from ``in_thread``.

This solution requires the use of nameless ``AF_UNIX`` sockets, which can be
achieved via the ``socketpair(2)`` function. Then, the new file descriptor would
be added to the list defined by the ``struct pollfd`` instance passed to
``poll(2)``.

This required some more changes,
though, as `client_io.c`_
always assumed that *any* incoming information from the only file descriptor
consumed by ``poll(2)`` comes from the agent side. However, this assumption was
no longer true, as EVP streams now introduce a new event source.

In other words, ``poll(2)`` would now return because of the following events:

* A timeout;
* Information coming from the agent side;
* Information coming from the thread running ``in_thread``.

To solve this, a callback table was set up to assign a specific function
for each file descriptor:

.. code-block:: c

   static int (*const process[sizeof(fds) / sizeof(*fds)])(
       struct sdk_client *,
       const struct pollfd *) = {process_agent_in, process_stream_in};

Therefore, when ``stream_insert_read_event`` is called, the *address* of the
``struct sdk_event_stream_read_available`` instance passed to it is sent over
the socket. Notice that only the ``struct`` address is required, as the
ownership is always transferred to the event queue, which is then responsible
for deallocating the resources.

Since the socket pair is shared among all streams, it is required to set up
a mutex that ensures only full and ordered packets are sent, even if the
packet size is in fact small (that is, ``sizeof (void *)``).

Multi-layered callback interface
--------------------------------

As suggested above, the remote SDK implementation is a bit overly complex
for several reasons. One of them is the abuse of opaque data types that
end up obscuring or forbidding the access to internal data structures
without any clear benefits, as the various interfaces within the remote SDK
are never meant to be available to users in any case.

As a consequence of this, ``process_stream_in`` has no way to retrieve the
``struct EVP_client`` related to the stream, since its caller is only limited
to a ``struct sdk_client`` instance. This forces ``EVP_initialize`` to set up
a callback/opaque-pointer pair that allows `sdk.c`_
to insert the new event into ``struct EVP_client`` member ``events``, which must
be assigned to its ``struct sdk_transport`` instance, which is the only data
type available from ``struct sdk_client``.

FAQ
---

Why not use POSIX sockets directly?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Networking in `wasi-sdk`_
is not supported. This means that code such as the example below would not
build because of missing functionality, for example, with ``undefined reference to socket``
link-time errors:

.. code-block:: c

   #include <sys/socket.h>

   int main(void)
   {
       int fd = socket(/* arguments */);
       /* Application code. */
   }

This means applications hosting a Wasm runtime,
such as the agent running `wasm-micro-runtime`_,
must relay networking from module instances to the host.

Why asynchronous I/O?
^^^^^^^^^^^^^^^^^^^^^

While a thinner abstraction with identical semantics compared to POSIX
sockets could have been possible, an interface always relying on
asynchronous semantics was deemed more desirable and interesting to future
users.

--------

.. _nng: https://github.com/nanomsg/nng
.. _streams: https://github.com/SonySemiconductorSolutions/edge-virtualization-platform/tree/main/src/libevp-agent/stream
.. _stream.c: https://github.com/SonySemiconductorSolutions/edge-virtualization-platform/tree/main/src/libevp-agent/stream/stream.c
.. _stream.h: https://github.com/SonySemiconductorSolutions/edge-virtualization-platform/tree/main/src/libevp-agent/stream/stream.h
.. _client_io.c: https://github.com/SonySemiconductorSolutions/edge-virtualization-platform/tree/main/src/libevp-app-sdk/sdkrpc/client_io.c
.. _sdk.c: https://github.com/SonySemiconductorSolutions/edge-virtualization-platform/tree/main/src/libevp-app-sdk/sdk.c
.. _wasi-sdk: https://github.com/WebAssembly/wasi-sdk
.. _wasm-micro-runtime: https://github.com/bytecodealliance/wasm-micro-runtime
