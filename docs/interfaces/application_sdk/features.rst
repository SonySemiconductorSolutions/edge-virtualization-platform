.. SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
..
.. SPDX-License-Identifier: Apache-2.0

Features
********

Most of the features described below
are available to module instances via
the use of an opaque handle.
In the C EVP Application SDK,
:c:struct:`EVP_client` is the opaque pointer type
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
via the :c:func:`EVP_setConfigurationCallback` function.

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
using the :c:func:`EVP_sendState` function.

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
if the underlying call to :c:func:`EVP_sendState` fails.

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
using the :c:func:`EVP_sendTelemetry` function.

Where ``entries`` refers to
an arbitrary number of telemetry entries,
defined as key-value pairs.
The size of this array
is defined by the ``nentries`` parameter.

.. note::

	Since :c:func:`EVP_sendTelemetry` takes
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
via the :c:func:`EVP_setRpcCallback` function.

All module direct commands
are then mapped
to a single, user-defined callback
with the :c:type:`EVP_RPC_REQUEST_CALLBACK` signature.

``id`` is an opaque identifier
dedicated to match a request against a response,
which is passed
via the :c:func:`EVP_sendRpcResponse`.

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
by the :c:func:`EVP_blobOperation` function.

Every blob operation consumes a user-defined callback
that will be executed by the agent
whenever an event related to the operation occurs.
