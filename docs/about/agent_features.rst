.. SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
..
.. SPDX-License-Identifier: Apache-2.0

Feature Overview
################

Application API and SDK
=======================

The agent provides an API for module instances to
communicate to the hub.

More information can be found in `EVP Application SDK`_.

Deployment
==========

In order to communicate
the modules and module instances
that must run in a given environment,
the EVP Agent consumes
a deployment manifest defined by the Hub.
Once received, the EVP Agent
will reconcile the current deployment against the desired one,
which might also involve steps such as
fetching the modules from the Internet.

Python modules
--------------

To run a Python module,
it has to be specified in the deploymentManifest by
``"moduleImpl": "python"``

Docker modules
--------------

There is experimental support for Docker module implementation.
Docker containers can be run specifying ``"moduleImpl": "docker"`` in deploymentManifest.

.. _EVP streams: ../interfaces/streams.html

Process modules
---------------

There is experimental support for process module implementation.
To run a module as a separate process via ``posix_spawn(3)``,
it has to be specified in the deploymentManifest by
`"moduleImpl": "spawn"`

Wasm modules
------------

To run a WebAssembly module,
it has to be specified in the deploymentManifest by
``"moduleImpl": "wasm"``

WASM Module log capture
^^^^^^^^^^^^^^^^^^^^^^^

WASM modules ``stdout`` and ``stderr``
can be logged as telemetry reports.
The feature can be enabled/disabled
by sending a special direct command
to a module with the following payload:

.. code:: JSON

	{
	  "direct-command-request": {
	    "reqid":"10000",
	    "method":"$agent/set",
	    "instance":"0b4d0865-10a1-4480-a485-10999fb44c4c",
	    "params": {
	      "log_enable": true
	    }
	  }
	}

The logs will then be transmitted
in telemetry reports:

.. code:: JSON

	{
	  "device/log":[
	    {
	      "log":"EVP_processEvent returned 2",
	      "app":"0b4d0865-10a1-4480-a485-10999fb44c4c",
	      "stream":"stdout",
	      "time":"2023-11-22T08:22:34.382621Z"
	    }
	  ]
	}

It is also possible to query
the state of logging for a given module:

.. code:: JSON

	{
	  "direct-command-request": {
	    "reqid":"10000",
		"method":"$agent/get",
	    "instance":"0b4d0865-10a1-4480-a485-10999fb44c4c",
	    "params": {}
	  }
	}

Embedding API
=============

The agent can operate as an embedded library,
so that it can be included in another application,
like for example a Camera Firmware.

More information can be found `EVP Agent SDK`_

System App API
==============

The System App API can be used
to provide the EVP features
for privileged processes in the system
which are not part of a deployment.

These processes lifecycle
are not managed by the agent or the hub,
yet they can use the EVP features
through the System App API
on behalf of the device.

More information can be found in `EVP SystemApp SDK`_

.. _EVP Application SDK: ../interfaces/application_sdk/index.html
.. _EVP Agent SDK: ../interfaces/embedding.html
.. _EVP SystemApp SDK: ../interfaces/c_systemapp_sdk.html