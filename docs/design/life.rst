.. SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
..
.. SPDX-License-Identifier: Apache-2.0

Agent life cycle
################

This section describes the possible life cycles of the agent.

Booting the agent
*****************

At startup, agent will try to load persisted deployment and states
from the respective files ``<EVP_DATA_DIR>/twins/desired``
and ``<EVP_DATA_DIR>/twins/current``.

Agent will setup **MQTT** to connect to the **HUB**
and send state report.

If no DB exists, or ``desired`` deployment is empty,
the agent will wait to receive a valid manifest from **HUB**.

The agent also creates a named FIFO with a temporary name by default
that is required for the correct timing of the agent
(see :ref:`main_loop`).

.. _design/life/life_cycle/runtime:

Runtime
*******

During runtime, the agent processes the following:

* Apply deployment if deployment has changed.
* Send periodic state reports messages to the **HUB**.
* Send queued telemetries from module instances to the **HUB**.
* Send queued blob operations request from module instances.
* Send queued RPCs requests from module instances to the **HUB**.
* Transmit queued **HUB** requests through **MQTT**.
* Process outbox messages.

Stopping the agent
******************

The agent listens to the ``SIGINT`` signal,
and will properly stop the agent following this sequence:

* Exit runtime loop.
* Disconnect from **HUB** to ensure all requests.
	and blob operations are cancelled.
	and agent is ready to exit.
* Terminate all running module instances,
	and stop all threads that the agent created.
* Finally, free the allocated resources
	to free all memory held in agent process.

Modules and module instances life cycle
#######################################

This section describes the possible life cycles of modules and module instances,
regardless of their actual implementation.

.. _design/life/module_instance/runtime:

Runtime
*******

The agent will rely on the ``desired`` ``deploymentManifest`` to determine
which modules must be loaded
and which module instances must be started.
It will attempt to do so on every iteration of the agent main loop,
and the time between main loop iterations depends on several factors.

.. note::

	There is a well-known issue whereby
	the agent miscalculates the time
	between main loop iterations
	because a MQTT mechanism,
	namely ``Keep Alive``,
	is always taken into account,
	even if explicitly disabled.
	Unfortunately,
	fixing this wrong behavior
	has side effects on most tests,
	and therefore has been avoided.

Modules
*******

Before module instances can be started,
their respective modules must be loaded first.
How these modules are loaded is implementation-defined.
Therefore, the agent will attempt to load as many modules as possible,
even if some of them fail to load for any reason
(for example, a missing file or a system error).

An exception to this is backdoor modules,
which are identified by the lack of a ``downloadUrl``.

Module instances
****************

Similar to the case with modules,
the agent will attempt to start as many module instances as possible.
How these module instances are started is implementation-defined.

If a module instance has been started but has stopped for whatever reason,
the agent will not attempt to restart it.
