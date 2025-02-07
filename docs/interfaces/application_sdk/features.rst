.. SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
..
.. SPDX-License-Identifier: Apache-2.0

Features
********

Most of the features described below
are available to module instances via
the use of an opaque handle.
In the C EVP Application SDK,
``struct EVP_client`` is the opaque pointer type
exposed to users.
In the Python EVP SDK,
the ``evp.client`` module
exposes the ``Client`` data type.

The main features
available to module instances
listed below
are also documented by the Doxygen documentation.

Module Instance Configuration
=============================

Users can assign
key-value configuration pairs
to module instances
from the Hub
and get them forwarded
by the agent.
Module instances can then
subscribe to zero or more configuration topics,
defining a callback
that will be executed
whenever a given configuration topic is received.

In the C EVP Application SDK,
module instances can subscribe
to a given configuration
via the ``EVP_setConfigurationCallback`` function:

.. code:: C

	EVP_RESULT EVP_setConfigurationCallback(struct EVP_client *h, EVP_CONFIGURATION_CALLBACK cb, void *userData);

In the Python EVP SDK,
module instances can subscribe
to a given configuration
via the ``evp.configuration`` package,
which defines the ``ConfigHandlerBase`` class,
that users must derive from
and implement their own ``handle`` method:

.. code:: Python

	class ConfigHandlerBase:
		def handle(self, topic: str, config: bytearray):
			...

Module Instance State
=====================

Module Instance States are
one of the several possible ways
to report information
from the module instance to the Hub.
States are
defined by key-value pairs
and include a user-defined callback
that shall be executed by the EVP Agent
when the state
has been successfully collected by the EVP Agent
or whenever an error occurs.
States are only recommended
for small pieces of information
since all states
are merged into a single message
by the EVP Agent.

.. note::

	States do not have delivery guarantees.
	If delivery guarantees are required,
	blob operations should be used instead.

In the C EVP SDK,
states can be sent
using the ``EVP_sendState`` function:

.. code:: C

	EVP_RESULT EVP_sendState(struct EVP_client *h, const char *topic, const void *state, size_t statelen, EVP_STATE_CALLBACK cb, void *userData);

In the Python EVP SDK,
the ``evp.state`` module
provides the ``State`` class,
which can be derived by user applications
so as to
implement the ``complete`` method:

.. code:: Python

	class State:
		def complete(self, reason: int):
			...

States can be sent
using the ``State.send`` method:

.. code:: Python

	class State:
		def send(self, topic: str, blob: bytearray): ...

The ``State.send`` method
shall raise an exception
if the underlying call to ``EVP_sendState`` fails.

Telemetries
===========

Telemetries are one of several possible ways
for module instances
to report data to the Hub,
and is usually only meant
for small pieces of information,
since the payload is
made part of a larger JSON payload
where all telemetries for each module instance are defined.

.. note::

	Telemetries do not have delivery guarantees.
	If delivery guarantees are required,
	blob operations should be used instead.

In the C EVP SDK, telemetries can be sent
using the ``EVP_sendTelemetry`` function:

.. code:: C

	EVP_RESULT EVP_sendTelemetry(struct EVP_client *h, const struct EVP_telemetry_entry *entries, size_t nentries, EVP_TELEMETRY_CALLBACK cb, void *userData);

Where ``entries`` refers to
an arbitrary number of telemetry entries,
defined as key-value pairs.
The size of this array
is defined by the ``nentries`` parameter.

.. note::

	Since ``EVP_sendTelemetry`` takes
	a read-only pointer to such entries,
	it is advisable that the user-defined callback
	pointed to by ``user``
	is used to release resources.

.. note::

	The user-defined callback defined by ``cb``
	shall be executed by the agent
	when the telemetry
	has been successfully allocated internally
	or whenever an error occurs.
	This callback is not intended
	to be used for signalling
	whether the Hub has finally received the telemetry,
	so telemetries
	do not have delivery guarantees.

In the Python EVP SDK,
telemetries require to
derive the ``Telemetry`` class,
and override the definition
for the ``complete`` method:

.. code:: Python

	class Telemetry:
		def complete(self, reason: int):
			...

Telemetries can be sent
by calling the ``Telemetry.send`` method:

.. code:: Python

	telemetry = Telemetry(client)
	telemetries = [("temp-room1", "30C")]
	telemetry.send(telemetries)

Module Direct Commands
======================

Users can request modules
to execute specific actions
from the Hub.
This is achieved
with the use of
module direct commands,
which are defined
by a method name
and a parameter list,
which are both defined as strings.

In the C EVP SDK,
a module can subscribe
to module direct command requests
via the ``EVP_setRpcCallback`` function:

.. code:: C

	EVP_RESULT EVP_setRpcCallback(struct EVP_client *h, EVP_RPC_REQUEST_CALLBACK cb, void *userData);

All module direct commands
are then mapped
to a single, user-defined callback
with the following signature:

.. code:: C

	typedef void (*EVP_RPC_REQUEST_CALLBACK)(EVP_RPC_ID id, const char *methodName, const char *params, void *userData);

``id`` is an opaque identifier
dedicated to match a request against a response,
which is passed
via the ``EVP_sendRpcResponse``:

.. code:: C

	EVP_RESULT EVP_sendRpcResponse(struct EVP_client *h, EVP_RPC_ID id, const char *response, EVP_RPC_RESPONSE_STATUS status, EVP_RPC_RESPONSE_CALLBACK cb, void *userData);

In the Python EVP SDK,
modules can subscribe
to direct module commands
via the ``CommandHandler`` class,
which in turn can register
to one or more ``CommandBase`` objects
that must be derived by users.
Each ``CommandBase``-derived class
defines how to react
to a given command.
Then,
a ``CommandHandler`` object
maps it
into a regular expression pattern.

.. code:: Python

	class CommandBase:
		def init(self, *args, **kwargs):
			...

		def handle(self, params: str, *args, **kwargs):
			...

		def complete(self, reason: int):
			...

		def respond(self, response: str, status: int):
			...


	class CommandHandler:
		def register(self, cmd: Union[Type[CommandBase], Callable], pattern: str = r".*", args=(), kwargs={}):
			...

Blobs
=====

It is possible to download/upload data from/to external servers
using a variety of protocols.

In the C EVP SDK,
all these operations are performed
by the :c:func:`EVP_blobOperation` function:

.. code:: C

	EVP_RESULT EVP_blobOperation(struct EVP_client *h, EVP_BLOB_TYPE type, EVP_BLOB_OPERATION op, const void *request, struct EVP_BlobLocalStore *localStore, EVP_BLOB_CALLBACK cb, void *userData);

Every blob operation consumes a user-defined callback
that will be executed by the agent
whenever an event related to the operation occurs.
