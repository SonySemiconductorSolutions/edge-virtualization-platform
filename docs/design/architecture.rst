.. SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
..
.. SPDX-License-Identifier: Apache-2.0

Architecture of the agent
#########################

Blobs
*****

The EVP Application SDK
in ``include/evp/sdk_blob.h``
defines several blob operation types:

* :c:enumerator:`EVP_BLOB_TYPE_AZURE_BLOB`,
  where the non-standard ``x-ms-blob-type: BlockBlob`` HTTP header is appended.
* :c:enumerator:`EVP_BLOB_TYPE_EVP`
* :c:enumerator:`EVP_BLOB_TYPE_EVP_EXT`
* :c:enumerator:`EVP_BLOB_TYPE_HTTP`
* :c:enumerator:`EVP_BLOB_TYPE_HTTP_EXT`

For example,
for standard HTTP operations :c:macro:`EVP_BLOB_TYPE_HTTP_EXT` is used.
Internally,
the agent defines several implementations that are loosely coupled
against the blob operation types described above.

* ``src/libevp-agent/blob_type_azure_blob.c``
* ``src/libevp-agent/blob_type_evp.c``
* ``src/libevp-agent/blob_type_http.c``

Since all of the operation types described above rely on HTTP,
in turn they all rely on ``src/libevp-agent/blob_http.c``,
which will then interact with the `Web Client`_ HTTP library.

Modules
*******

The agent follows the same terminology
used in `WebAssembly`_,
where modules refer to executables
that can be instantiated into module instances.
As an OCI/Docker analogy,
modules mean to the agent what images mean to OCI/Docker.

Nevertheless,
the agent is not limited to Docker or WebAssembly.
It is designed to support any backend,
so that the higher-level implementation of the agent remains agnostic.

The officially supported module implementations
and their respective ``Kconfig`` variables are:

* WebAssembly: ``EVP_MODULE_IMPL_WASM``
* Python: ``EVP_MODULE_IMPL_PYTHON``

The following module implementations are considered experimental:

* Docker: ``EVP_MODULE_IMPL_DOCKER``
* Shared libraries: ``EVP_MODULE_IMPL_DLFCN``
* Executables: ``EVP_MODULE_IMPL_SPAWN``

Every module implementation is implemented by its
``src/libevp-agent/module_impl_<name>.c``,
where ``<name>`` refers to the implementation name
for example, ``wasm`` or ``dlfcn``.
An implementation is implemented using a common interface,
namely :c:struct:`module_impl_ops`.
See the definition for :c:struct:`module_impl_ops`
in ``src/libevp-agent/module_impl_ops.h`` for further reference.

Module instances
****************

The agent follows the same terminology
used in `WebAssembly`_,
where module instances refer to modules instantiated by the backend.
As an OCI/Docker analogy,
module instances mean to the agent what containers mean to OCI/Docker.

The supported module instance implementations
is that of the supported `module implementations <#modules>`_.
Every module instance implementation is implemented by its
``src/libevp-agent/module_instance_impl_<name>.c``,
where ``<name>`` refers to the implementation name
for example, ``wasm`` or ``dlfcn``.
An implementation is implemented using a common interface,
namely :c:struct:`module_instance_impl_ops`.
See the definition for :c:struct:`module_instance_impl_ops`
in ``src/libevp-agent/module_instance_impl_ops.h`` for further reference.

Config
******

The agent supports definining key/value pairs
to configure EVP module instances.
Module instances can subscribe to configurations
via ``EVP_setConfigurationCallback``.
Module instance configuration is implemented
by ``src/libevp-agent/instance_config.c``,
and is processed according to the configured version of the EVP protocol.

As part of the ``hub`` interface,
``src/libevp-agent/instance_config.h`` exports the following implementations:

* :c:func:`hub_evp1_parse_instance_config`
* :c:func:`hub_evp1_notify_config`
* :c:func:`hub_evp2_parse_instance_config`
* :c:func:`hub_evp2_notify_config`

Apart from module instance configurations,
``src/libevp-agent/instance_config.c`` also handles system app configurations.

.. _design/architecture/notifications:

Notifications
*************

Since the agent is usually provided as a library,
library users might want to receive events on specific internal events,
such as connection/disconnection events from the hub.
The agent defines a list of internal events
in ``src/libevp-agent/agent_event.c``,
to which users might want to subscribe,
via the :c:func:`evp_agent_notification_subscribe` function.

The user-defined callback can also receive
an optional pointer to user-defined data (``NULL`` in the example below).
The library will not attempt to dereference this pointer.
Every notification type might include additional data related to the event,
and is passed as a read-only pointer to the user-defined callback.

.. warning::

	The user is responsible for casting the read-only pointer
	passed to the user-defined callback to the appropriate data type.
	Otherwise, the behaviour is undefined.

For example, the ``network/error`` notification passes a read-only string
meant to help users to debug the networking issue:

.. code:: C

	int my_callback(const void *args, void *user_data)
	{
		const char *error = args;

		fprintf(stderr, "%s: network error: %s\n", __func__, error);
		return 0;
	}

	int foo(struct evp_agent_ctxt *ctxt)
	{
		if (evp_agent_notification_subscribe(ctxt, "network/error", my_callback, NULL)) {
			fprintf(stderr, "%s: notification_register failed\n",
				__func__);
			evp_agent_free(ctxt);
			return -1;
		}
	}

Events published by the agent
=============================

As documented in :ref:`notifications`,
every notification can include additional data passed as a ``const void *``,
requiring the user to cast the pointer into its appropriate data type.
The data types for each event type are described below.

.. note::

	``src/libevp-agent/agent_event.c`` is considered the source of truth.
	The events listed below are documented as a best effort.

* ``agent/status``: a ``const char *`` with the connection status
  (``connected`` or ``disconnected``).
* ``blob/result``: ``const struct evp_agent_notification_blob_result *``.
* ``deployment/reconcileStatus``: ``const struct reconcileStatusNotify *``.
* ``mqtt/sync/err``: a ``const char *``
  with an error string coming from the MQTT library.
* ``network/error``: a ``const char *`` with additional information about the
  error.
  Its value is only meant for debugging purposes,
  and therefore stability is not guaranteed.
* ``start``: always ``NULL``.
* ``wasm/stopped``: ``const struct evp_agent_notification_wasm_stopped *``.

.. _design/architecture/platform:

Platform
********

Being a platform-agnostic library,
the agent defines a platform abstraction layer.
The interface is provided by ``src/libevp-agent/platform.h``,
and all of the operations default to portable implementations where possible.

The list of platform-specific functions has grown organically,
based on internal requirements and historical reasons.

Persist
*******

The agent can fetch a local copy of the most recently applied deployment
on startup.
This is useful under some circumstances:
for example, if the agent starts without connectivity against the MQTT broker,

This is achieved by storing a pair of JSON databases,
namely ``current.json`` and ``desired.json``,
which express the last applied deployment and the desired deployment,
respectively.

This feature is activated via the ``EVP_TWINS_PERSISTENCE`` ``Kconfig`` variable.

SDK interface
*************

Module instances interact with the agent via the
:ref:`application_sdk`.
The transport layer used between module instances and the agent
depends on the module instance implementation:

- Communication is made inside the same process (``EVP_SDK_LOCAL``).
	- WebAssembly (``wasm``).
	- Shared libraries (``dlfcn``).
- Communication is made from a separate process via a Unix socket (``EVP_SDK_SOCKET``).
	- Docker containers (``docker``).
	- Executables (``spawn``).
	- Python (``python``).

``src/libevp-agent/sdk_local.c`` provides the implementation
for module instance implementations communicating
with the agent within the same process.
However,
module instances running on a sandbox, such as WebAssembly, might require
data extraction from the runtime.
For example, ``src/libevp-agent/sdk_local_wasm.c`` defines
the WebAssembly-specific implementation.

Deployment
**********

The agent attempts to reconcile
the desired ``deploymentManifest`` whenever possible.
The logic to achieve this is defined by ``src/libevp-agent/reconcile.c``.

On every iteration of the main loop,
``apply_deployment`` is unconditionally called
to attempt the reconciliation.
This involves:

* Loading any modules not loaded yet.
  This might involve downloading the module from an external service.
* Instantiating those modules that are already loaded.
* Stopping module instances no longer defined by the ``deploymentManifest``.
* Garbage-collecting modules no longer defined by the ``deploymentManifest``.

.. note::

	``src/libevp-agent/deployment.c`` is in fact only related to deployment
	resume/stop.

Request
=======

Report
======

The agent publishes a periodical report to the MQTT broker
with information about its state
and that of its modules, module instances, and system apps,
as well as some other system information.
The periodicity of this report is determined
by the ``EVP_REPORT_STATUS_INTERVAL_MIN_SEC``
and ``EVP_REPORT_STATUS_INTERVAL_MAX_SEC`` ``Kconfig`` variable.
The periodical report is not sent
if its contents were not changed from the last report.

The logic for the periodical report
is implemented by ``src/libevp-agent/report.c``.

Telemetry
=========

Multi-storage token provider (mSTP) cache
=========================================

The agent can store the tokens used
to access cloud storage providers into local storage,
so that they can be accessed while
the device is disconnected from the Hub_.

mSTP cache can only be available if
storage provider supports multi-file with
the same token.

The Hub_ provides the knowledge if
storage supports multi-file in
``storagetoken-response`` if
``responseType`` field is ``multifile``.

.. note::

    Currently, multi-file is only supported with Azure.

This cache has been designed as a single-file JSON database
with the following format::

	[
		{
			"instanceName": <string>
			"remoteName": <string>
			"storageName": <string>,
			"storagetoken-response": {
			    "responseType": "multifile",
				...
			}
		}
	]

Only one entry with the same ``instanceName``, ``remoteName`` and ``storageName``
can exist within the database.

The cache can be manipulated via the following functions:

.. code-block:: c

	int blob_type_evp_load(const struct evp_agent_context *agent, const struct blob_work *wk, struct storagetoken_response *resp);
	int blob_type_evp_store(const struct blob_work *wk, const JSON_Value *v);

where:

*
	``blob_type_evp_load``, as suggested, loads an entry from the cache.
	``agent`` is the ``struct`` holding agent-specific information,
	and it is required to determine
	how to parse the ``storagetoken-response`` JSON object
	based on the EVP hub version.
	``wk`` defines the ``instanceName``, ``remoteName`` and ``storageName``
	that must be looked up on the database so as to retrieve
	its matching ``storagetoken-response``.
	``resp`` is the object that shall be filled once
	a matching entry is found.

*
	``blob_type_evp_store`` writes an entry,
	as defined by ``wk`` and ``v``,
	into the cache.
	Existing entries with matching
	``instanceName``, ``remoteName`` and ``storageName``
	shall be replaced with the new entry.

Hub
***

Apart from the configured EVP version,
which defines the onwire protocol,
the agent can connect to different IoT platforms,
which in turn encapsulate the on-write protocol
defined by the EVP version.

However,
only `Thingsboard`_ is supported,
which is implemented by ``src/libevp-agent/hub/tb/tb.c``
and ``src/libevp-agent/hub/hub_tb.c``.

Streams
*******

EVP streams are meant as a communication mechanism between module instances.
Their design is closely inspired by the POSIX sockets interface, but streams
are opinionated towards asynchronous communication.

Read :ref:`evp_streams` for further reference.

Transport
*********

The agent interacts with several network services during its execution,
with a variety of protocols.
The ``transport`` component is therefore meant as a thin abstraction layer
over the MQTT client library
and implements higher-level operations
such as reconnections, sending messages, or subscribing to a topic.

PAL
===

Being a platform-agnostic library,
`MQTT-C`_ splits platform-specific details
into ``src/libevp-agent/MQTT-C/src/mqtt_pal.c``.

TLS
===

The agent relies on the `Mbed-TLS`_
library for cryptographic operations.

MQTT
====

The agent relies on the `MQTT-C`_
library to handle MQTT connections.

Web Client
==========

For HTTP operations,
the agent relies on the
`WebClient`_ library,
and defines ``src/libevp-agent/webclient_mbedtls.c`` to implement the
TLS-specific details required by ``webclient``.
On the other hand,
since users can disconnect the agent from the network using the embedded API
(i.e., via :c:func:`evp_agent_disconnect`),
``src/libevp-agent/connections.c`` is defined
as a thin wrapper over ``webclient``
that stops ongoing HTTP operations if required.

--------

.. _MQTT-C: https://github.com/LiamBindle/MQTT-C
.. _WebAssembly: https://github.com/WebAssembly/design
.. _WebClient: https://github.com/apache/nuttx-apps/tree/master/netutils/webclient
.. _Mbed-TLS: https://github.com/Mbed-TLS/mbedtls
.. _Thingsboard: https://thingsboard.io/
