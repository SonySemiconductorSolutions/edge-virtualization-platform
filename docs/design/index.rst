.. SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
..
.. SPDX-License-Identifier: Apache-2.0

System Design
#############

Introduction
============

The Edge Virtualization Platform Agent
is designed as a series of loosely coupled components
that interact with each other to allow the orchestration
and management of workloads in the Edge device.

Controller interface (HUB)
==========================

The agent connects to a controller hub, which can send
deployment manifests and other messages to instantiate
and control modules and module instances.

The module instances' lifecycles
are always managed by the Agent as
behavioral response
to a new deployment manifest from the Hub.
The Hub is the source of truth
about the desired deployment that runs on the device.

Whenever the Agent receives a new desired deployment from the hub,
It will "reconcile" the current and desired deployments,
and ultimately start/stop the relevant modules,
that were added or removed,
while maintaining the state of the modules and instances
that did not change.

The hub interface is designed as a common interface,
so that different onwire-schemas and protocols
can be easily added.

The agent supports
the deprecated EVP1
and the new EVP2 hub interfaces,
which is the default,
MQTT-based schema
that is used by the hub
to control the Agent.

More information can be found in :ref:`design/architecture`.

Applications, module instances types and APIs
=============================================

There are two implementations to communicate with module instances:
the local implementation (sometimes called Local SDK) and the remote
implementation (sometiems called Remote SDK).
Although, these offer the same interface,
the underlying communication mechanisms are different.

The local implementation is to be used
with modules and instances
that share the same process as the agent.
These are usually run in a pthread inside the agent task.
This is essentially used for wasm modules, since we include the
WAMR runtime in the Agent, we start WASM modules in a thread, and
they can communicate with the agent by direct function calls and pointers.

The remote implementation is to be used
with modules and instances
that run in a separate process from the Agent.
This is the case for docker, spawn and python modules.
Since for these modules, the runtime is not embedded in the agent,
a RPC-like flatbuffer interface over a UNIX domain socket is used.

These full featured interfaces offer
a variety of networking functionalities
to the module instances.
More information can be found in :ref:`application_sdk`.

System Application Interfaces
=============================

In some devices,
it is desirable
to have applications that control the system,
to handle workflows like reboot, OTA, configuration management, etc.

Since these applications lifecycle are not managed by the hub,
these are not Modules or Module instances.
They are not tracked in the deployment manifest or status.

These applications are started by the agent executable,
especially when a custom main program is linked using :ref:`embedding`.
and usually run in a pthread.

The SystemApps can use the EVP features
available in :ref:`evp-systemapp_sdk`,
on behalf of the device.

Also since they do not have module instances IDs,
all the operations are done on behalf of the device.

More information can be found in :ref:`evp-systemapp_sdk`

.. toctree::
	:maxdepth: 1

	life
	architecture
	main_loop
	channels
	string_map
