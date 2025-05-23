.. SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
..
.. SPDX-License-Identifier: Apache-2.0

Introduction
############

The EVP Agent is a runtime that orchestrates
applications called *modules* and connects them
to an MQTT-based Hub.

The hub can request the agent
to spawn zero or more *module instances*
of a *module*.

EVP is an abstraction layer
between devices the Hubs,
so that user applications (modules)
do not have to worry about
Hub-specific interfaces
or implementation details.

More specifically,
EVP is a set of interfaces and protocols
supported by the EVP Agent.

.. toctree::
	:maxdepth: 1

	agent_features
	../platforms/index
	release_process
