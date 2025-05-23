.. SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
..
.. SPDX-License-Identifier: Apache-2.0

.. _running_the_agent:

Running the EVP Agent
#####################

The behaviour of the EVP Agent can be configured via environment variables.
The following variables can be configured:

- ``EVP_IOT_PLATFORM``: defines the protocol version exchanged
  between the EVP Agent and the Hub.
  ``TB`` corresponds to the second version of the EVP protocol,
  whereas ``EVP1``corresponds to the first version of the EVP protocol.
  The default value is ``TB``.
- ``EVP_DATA_DIR``: defines a path to a directory
  where internal files allocated by the agent shall be accessed.
  This directory must be readable and writeable by the agent.
  It has to exist before running the agent.
- ``EVP_MQTT_HOST``: defines the MQTT hostname to connect to.
  With TLS,
  this is also used to validate the CN of the server cert.
- ``EVP_MQTT_PORT``: defines the port number of the MQTT host to connect to.
- ``EVP_MQTT_TLS_CA_CERT``: defines the path to
  the TLS Certificate Authority chain as consumed by the internal MQTTS client.
  Only PER or DER files without password are accepted.
  This option is only required if TLS is used.
- ``EVP_MQTT_TLS_CLIENT_CERT``: defines the path to the TLS client key.
  Only PER or DER files without password are accepted.
  This option is only required if TLS is used.
- ``EVP_MQTT_TLS_CLIENT_KEY``: defines the path to the TLS client certificate.
  Only PER or DER files without password are accepted.
  This option is only required if TLS is used.
- ``EVP_HTTPS_CA_CERT``: defines the path to
  the TLS Certificate Authority chain
  as consumed by the internal HTTPS client.
  Only PER or DER files without password are accepted.
- ``EVP_REGISTRY_AUTH``: defines a collection of name/value pairs
  where the name specifies a registry
  and the value specifies the authentication info for the registry.
  The agent passes the authentication info
  as the value of the ``X-Registry-Auth:`` HTTP header
  when asking Docker to pull images from the corresponding registry.
  For example:

	.. code:: JSON

		{
			"docker.io": "some value",
			"ghcr.io": "another value"
		}

  This environment variable only applies to EVP Agent versions
  configured to fetch Docker modules.
- ``EVP_REPORT_STATUS_INTERVAL_MIN_SEC``:
  defines the minimum interval time,
  in seconds,
  that the agent would send reports to the hub.
  The default value is `3`.
- ``EVP_REPORT_STATUS_INTERVAL_MAX_SEC``:
  Usually,
  the agent tries to suppress reports
  when nothing new to report.
  After this period,
  the agent tries a report
  even when nothing has been changed since the previous report.
  The default value is `180`.
- ``EVP_CONFIG_RAWCONTAINERSPEC_SIGNVERIF_PUBKEY``
- ``EVP_MQTT_PROXY_HOST``: defines the hostname for the MQTT proxy.
- ``EVP_MQTT_PROXY_PORT``: defines the port number for the MQTT proxy.
- ``EVP_MQTT_PROXY_USERNAME``: when defined,
  this value will be used as the username for the `Basic` authentication
  in the connection to the MQTT proxy server.
- ``EVP_MQTT_PROXY_PASSWORD``: when defined,
  this value will be used as the password for the `Basic` authentication
  in the connection to the MQTT proxy server.
- ``EVP_HTTP_PROXY_HOST``: defines the hostname for the HTTP proxy.
- ``EVP_HTTP_PROXY_PORT``: defines the port number for the HTTP proxy.
- ``EVP_HTTP_PROXY_USERNAME``: when defined,
  this value will be used as the username for the `Basic` authentication
  in the connection to the HTTP proxy server.
- ``EVP_HTTP_PROXY_PASSWORD``: when defined,
  this value will be used as the password for the `Basic` authentication
  in the connection to the HTTP proxy server.
- ``EVP_DOCKER_TLS_CA_CERT``: defines the path to
  the TLS Certificate Authority chain for the Docker API.
  Only PEM or DER files without a password are allowed.
- ``EVP_DOCKER_TLS_CLIENT_CERT``: defines the path to
  the TLS client certificate
  Only PEM or DER files without a password are allowed.
- ``EVP_DOCKER_TLS_CLIENT_KEY``: defines the path to the TLS client key
  for the Docker API.
  Only PEM or DER files without a password are allowed.
- ``EVP_DOCKER_HOST``: defines the Docker API endpoint.
  It is usually assigned to ``http://dockerd``.
  The scheme should be ``http``
  since TLS over ``AF_UNIX`` sockets is not supported.
  This option is only relevant
  for a EVP Agent configured to run Docker containers.
- ``EVP_DOCKER_UNIX_SOCKET``: defines the path to a Unix domain socket
  to communicate with the Docker engine.
  The commonly used value is ``/var/run/docker.sock``.
  This option is only relevant
  for a EVP Agent configured to run Docker containers.
- ``EVP_MODULE_INSTANCE_DIR_FOR_DOCKERD``: defines the directory
  in the filesystem namespace used by the ``dockerd``,
  which corresponds to ``/evp_data/instances``
  in the filesystem namespace used by the EVP Agent.
  This option is only relevant
  for a EVP Agent configured to run Docker containers.
- ``EVP_TLS_KEYLOGFILE``: defines the path where the EVP Agent
  shall store TLS secrets.
  This option can only be used
  when the ``EVP_AGENT_TLS_KEYLOG`` KConfig flag is enabled.

.. warning::

	Using ``EVP_TLS_KEYLOGFILE`` in a production environment
	can be a security risk
	if the file can be accessed by third parties.

Minimal configuration
=====================

The following minimum set of environment variables must be assigned
in order to run the EVP Agent:

- ``EVP_MQTT_HOST``
- ``EVP_MQTT_PORT``

This configuration assumes:

- Unencrypted HTTP and MQTT connections.
- No MQTT or HTTP proxy.
- No Docker modules.

.. note::

    ``EVP_DATA_DIR`` is not mandatory,
    but its default value (``/evp_data``)
    might not be suitable for most enviroments.
    Therefore,
    it is recommended to assign ``EVP_DATA_DIR`` to a directory
    that the user running the agent can write into.

.. warning::

	Running the agent without *any* of the environment variables defined above
	will cause it to abort.
