.. SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
..
.. SPDX-License-Identifier: Apache-2.0

.. _evp-systemapp_sdk:

EVP SystemApp SDK
###################

The agent provides
mechanisms for registration of
SystemApps, which are applications
provided by the camera firmware
used to perform operations
that don\'t fit in the modules deployed by the deployment manifest.
SystemApps are not created by the agent and
they live independently of the agent
and for this reason they are not deployed.

Before a SystemApp can use any interface defined by this SDK
it has to register itself using the :ref:`embedding`,
and in the same way
it has to deregister itself once the job is done.
For example:

.. code:: C

	struct SYS_client *c = evp_agent_register_sys_client(ctxt);
	...
	evp_agent_unregister_sys_client(ctxt, c);

While the **EVP C-SystemApp SDK** is different from the :ref:`application_sdk`,
it shares the basic design principles.
The programming model is based on an event loop and registered callbacks,
which are called when the event happens.

The function ``evp_agent_unregister_sys_client`` will unregister all the callbacks,
it will delete all the pending events for the SysApp
and it will deallocate the ``SYS_client`` structure.

A typical System App will have a basic skeleton like this:

.. code:: C

	#include <stdio.h>

	#include <evp/sdk_sys.h>

	void
	sysapp(struct evp_agent_context *ctxt)
	{
		enum SYS_RESULT r;
		int exiting = 0;
		struct SYS_client *c;

		c = evp_agent_register_sys_client(ctxt);
		while (!exiting) {
			r = SYS_process_event(c, 100);
			switch (r) {
			case SYS_RESULT_OK:
			case SYS_RESULT_TIMEDOUT:
				break;
			case SYS_RESULT_ERRNO:
				perror("sysapp");
				break;
			case SYS_RESULT_SHOULD_EXIT:
				exiting = 1;
				break;
			default:
				fprintf(stderr, "sysapp: %s\n", SYS_result_tostr(r));
				break;
			}
		}
		evp_agent_unregister_sys_client(ctxt, c);
	}

The function ``SYS_process_event`` is the main interface of the SDK
and it has to be called periodically by the SysApps
in order to process any pending event.

After receiving a return value of ``SYS_RESULT_SHOULD_EXIT``
the SysApp should not call any function of this SDK and
it should call ``evp_agent_unregister_sys_client`` as soon as possible.
If after receiving a ``SYS_RESULT_SHOULD_EXIT``
any function of the SDK is called then
the behaviour is undefined.
When the function ``evp_agent_stop`` (see :ref:`embedding`) is called
the main loop will wait until
all the SysApps receive the ``SYS_RESULT_SHOULD_EXIT``
and each of them call the function ``evp_agent_unregister_sys_client``.

All the callbacks registered by the SystemApp
are called in the context of ``SYS_process_event``,
which means that
they cannot have race conditions with
other functions running in the same thread.
A callback can call functions of this SDK without problems,
and for that reason,
they receive a pointer to the current SysApp.
The function ``SYS_process_event`` waits for a number of milliseconds
specified in the second parameter.
If the value is 0 then it will attend any pending event
but it will not block if there aren't any pending events.
If the timeout value is negative then
it waits forever until an event has arrived.
``SYS_processEvent`` processes up to one event,
returning after processing it.
For that reason it can return before
the amount of milliseconds specified in the second parameter.

It is important to note that
most of the ``SYS_`` functions of the System App C SDK will block
until ``evp_agent_loop`` is called from the embedding api,
for this reason,
to avoid deadlocks,
it is recommended to run the SystemApp in a different thread than
the one calling ``evp_agent_loop``.
Multiple SystemApps can run in the same thread without problems,
but that thread cannot be shared with the agent.

Enumerations
************

The enumeration ``enum SYS_result`` is used as return code
by all the functions of the SDK and
it can be:

	* ``SYS_RESULT_OK``: The function finished without errors.
	* ``SYS_RESULT_TIMEDOUT``: The function finished because a
	  timeout expired.
	* ``SYS_RESULT_ERRNO``: The function failed and errno holds
	  the reason.
	* ``SYS_RESULT_SHOULD_EXIT``: The function finished and the
	  SystemApp should finish.
	* ``SYS_RESULT_ERROR_NO_MEM``: The function failed because
	  there isn't enough memory to finish it.
	* ``SYS_RESULT_ERROR_BAD_PARAMS``: The function failed because
	  the parameters passed to it were not valid.
	* ``SYS_RESULT_ERROR_ALREADY_REGISTERED``: This error code is
	  returned by callback registration functions when they
	  try to register a callback in something that already
	  has a registered callback.

Any constant of the type ``enum SYS_RESULT`` can be converted to string
using the ``SYS_result_tostr`` function.

The enumeration ``enum SYS_callback_reason`` is used as parameter
for all the callbacks and
it indicates the reason why the callback was called.
It can be:

	* ``SYS_REASON_FINISHED``: The pending operation is finished.
	* ``SYS_REASON_MORE_DATA``: The operation requires more data.
	* ``SYS_REASON_TIMEOUT``: The pending operation failed because
	  some timeout expired.
	* ``SYS_REASON_ERROR``: The pending operation failed.

Any constant of the ``enum SYS_callback_reason`` can be converted to
string using the ``SYS_reason_tostr`` function.

The ``enum SYS_type_configuration`` enumeration is used
for the functions related to configuration
and it is used to discriminate configuration changes
based in the origin of the change.
It can be:

	* ``SYS_CONFIG_PERSIST``: The configuration comes from the persist database.
	* ``SYS_CONFIG_HUB``: The configuration comes from a hub message.
	* ``SYS_CONFIG_ANY``: The configuration comes from any source.

The ``SYS_CONFIG_ANY`` value is used when a callback is registered and
the callback for any configuration will be called
independently of its origin.

.. _interfaces/c_systemapp_sdk/configuration:

Configuration
*************

Configurations for SysApps don\'t have a instance identifier or similar,
because SysApps are not exposed to the hub.
For that reason SysApps have to subscribe to the topics that
they manage using the ``SYS_set_configuration_cb`` function:

.. code:: C

	enum SYS_result SYS_set_configuration_cb(struct SYS_client *c,
	                                    const char *topic,
					    SYS_config_cb cb,
					    enum SYS_type_configuration type,
	                                    void *user);

The ``SYS_config_cb`` type defines the prototype of the callback:

.. code:: C

	typedef void (*SYS_config_cb)(struct SYS_client *c,
				      const char *topic, const char *value,
				      enum SYS_type_configuration type,
				      enum SYS_callback_reason reason, void *user);

Where the ``user`` parameter is the pointer
supplied to the ``SYS_set_configuration_cb`` function.
Users can pass a pointer to a data structure or similar
and it helps to avoid global variables.
The library will make no attempt
to dereference this pointer,
so it can also be a null pointer.
The callback will be called only for the type of configuration
selected by the ``SYS_set_configuration_cb`` type parameter,
and the callback will receive as parameter the type of configuration.
This is useful in the case of using ``SYS_CONFIG_ANY``
when the callback is registered.
For example:

.. code:: C

	#include <stdio.h>

	#include <evp/agent.h>
	#include <evp/sdk_sys.h>

	void
	config_cb(struct SYS_client *c,
		  const char *topic, const char *value,
		  enum SYS_type_configuration type,
		  enum SYS_callback_reason reason, void *user)
	{
		if (reason != SYS_REASON_FINISHED) {
			fprintf(stderr,
			        "sysapp: callback called with type %s\n",
			        SYS_reason_tostr(type);
			return;
		}

		printf("New configuration of type %d, %s:%s\n",
		        type, topic, value);
	}

	int
	sysapp(struct evp_agent_context *ctxt, const char *name)
	{
		enum SYS_RESULT res;
		struct SYS_client *c = evp_agent_register_sys_client(ctxt);

		if (!c) {
			fprintf(stderr, "sysapp: error registering sysapp %s\n", name);
			return -1;
		}

		res = SYS_set_configuration_cb(c, "framerate",
					     config_cb, SYS_CONFIG_HUB, NULL);
		if (res != SYS_RESULT_OK) {
			fprintf(stderr,
			        "sysapp: %s: error registering configuration callback\n",
			        name);
			goto err;
		}

		for (;;) {
			res = SYS_process_event(c, 100);
			if (res == SYS_RESULT_SHOULD_EXIT)
				break;
			if (res != SYS_RESULT_OK) {
				fprintf(stderr,
					"sysapp: %s: error processing events: %s\n",
					name, SYS_result_tostr(res));
			}
		}
		res = SYS_RESULT_OK;

	err:
		evp_agent_unregister_sys_client(ctxt, c);
		return (res != SYS_RESULT_OK) ? -1 : 0;
	}

In this example
the configuration callback is registered only for
configurations coming from a hub message
and configurations from the persist database will be ignored.

State
*****

States are set using the function ``SYS_set_state`` with the prototype:

.. code:: C

	enum SYS_RESULT SYS_set_state(struct SYS_client *c, const char *key,
				 const char *value);

There is no callback for state,
so the SysApp does not have a way
to know when the state will be visible in the hub.
This is done in this way because
the agent sends the states as part of the periodic report
that is sent with no delivery guarantees.
The caller of the function
can modify the ``key`` and ``value`` parameters as desired
once the function returns.
As the prototype indicates,
a state is composed of a key and value pair.
The state keys are part of a global namespace
that is shared between all the SysApps,
and it means that different SysApps can set the same key
that will overwrite the previous one
without an error being reported.

For example:

.. code:: C

	SYS_set_state(c, "battery", "charging");
	...
	SYS_set_state(c, "battery", "full");

Will set the ``battery`` state to ``charging`` and later to ``full``.
The current state will arrive to the Hub as part of the periodic report,
but any intermediate state between two periodic reports
will not been seen by the hub.

Telemetries
***********

SysApps can send telemetries
using the ``SYS_send_telemetry`` function with prototype:

.. code:: C

	enum SYS_RESULT SYS_send_telemetry(struct SYS_client *c,
	                              const char *key, const char *value,
	                              SYS_telemetry_cb cb,
				      void *user);

Telemetries are intended for small pairs of key/value
that usually will be sent in a periodic fashion,
and for this reason is sent with no delivery guarantees.
and it means the callback is called
once the telemetry has been sent to the hub (that is, left the agent).

.. note::
    This interface is not intended for big chunks of data,
    and sending things like images can be very inefficient.
    The blob interfaces are more suitable for that use case.

The ``SYS_telemetry_cb`` type defines the prototype of the callbacks
called when the telemetry is sent to the hub
but it does not guarantee
that it arrives to it.

.. code:: C

	enum SYS_RESULT (*SYS_telemetry_cb)(struct SYS_client *c,
	                               enum SYS_callback_reason reason,
				       void *user);

Where the ``user`` pointer is
the same used in the call to ``SYS_send_telemetry``.

It is important to notice that
copies of the ``key`` and ``value`` parameters are done
and the SysApp does not need to maintain the values
once the ``SYS_send_telemetry`` function returns.

For example:

.. code:: C

	#include <stdlib.h>
	#include <stdio.h>
	#include <time.h>

	#include <evp/agent.h>
	#include <evp/sdk_sys.h>

	int
	sysapp(struct evp_agent_context *ctxt, const char *name)
	{
		time_t t;
		enum SYS_RESULT res;
		struct SYS_client *c = evp_agent_register_sys_client(ctxt);

		if (!c) {
			fprintf(stderr, "sysapp: error registering sysapp %s\n", name);
			return -1;
		}

		for (time(&t); ; ) {
			res = SYS_process_event(c, 100);
			if (res == SYS_RESULT_SHOULD_EXIT)
				break;
			if (res != SYS_RESULT_OK) {
				fprintf(stderr,
					"sysapp: %s: error processing events: %s\n",
					name, SYS_result_tostr(res));
			}
			if (difftime(time(NULL), t) < 1)
				continue;

			time(&t);
			res = SYS_send_telemetry(c, "temperature", temp(), NULL, NULL);
			if (res != SYS_RESULT_OK) {
				fprintf(stderr,
					"sysapp: %s: error sending telemetry for %s: %s\n",
					name, "temperature", SYS_result_tostr(res));
			}
		}

		evp_agent_unregister_sys_client(ctxt, c);
		return SYS_RESULT_OK;
	}

In this example the ``cb`` parameter is NULL and
it means that
there will not be any function to call when
the telemetry is sent.
If some action is required then
the caller of ``SYS_send_telemetry`` has to
set a value for ``cb`` and a value ``user``
that will allow the callback to discriminate between different calls.
As ``topic`` and ``value`` are copied in the call to ``SYS_send_telemetry``,
there is little need for a callback.
However, it is still accepted in case the user requires it.
For the same reason,
the caller can modify the parameters ``key`` and ``value``
after the call to ``SYS_send_telemetry`` without problems.

Direct Command
**************

Direct Commands are remote procedure calls (RPC) that
the hub can send to SysApps.

Commands can be registered using the function ``SYS_register_command_cb``
and are handled in the user callback:

.. note::

	Only one SysApp can register to each command.
	If the SysApp tries to register again or
	another SysApp tries to register a handler for
	a command that is already assigned to a handler,
	the `SYS_RESULT_ERROR_ALREADY_REGISTERED` error
	will be returned by `SYS_register_command_cb`.

.. code:: C

	enum SYS_result SYS_register_command_cb(struct SYS_client *c,
						const char *command,
						SYS_command_cb cb,
						void *user);

The ``SYS_command_cb`` type defines the prototype of the callback
called when a command is received:

.. code:: C

	typedef void (*SYS_command_cb)(struct SYS_client *c,
				       SYS_response_id id,
				       const char *body,
				       void *user);

... where the ``user`` pointer is
the same used in the call to ``SYS_register_command_cb``.

SysApps can respond to these requests by
sending a string calling ``SYS_set_response_cb``
in the user-defined command callback.

.. code:: C

	enum SYS_result SYS_set_response_cb(struct SYS_client *c,
					    SYS_response_id id,
					    const char *response,
					    enum SYS_response_status status,
					    SYS_response_cb cb,
					    void *user);

The type ``SYS_response_cb`` defines the prototype of the callback
called when a response has been sent:

.. code:: C

	typedef void (*SYS_response_cb)(struct SYS_client *c,
					enum SYS_callback_reason reason,
					void *user);

Example:

.. code:: C

	#include <stdlib.h>
	#include <stdio.h>

	#include <evp/agent.h>
	#include <evp/sdk_sys.h>

	static void
	syscmd_reset_response_cb(struct SYS_client *c, enum SYS_callback_reason reason, void *user)
	{
		/* Process reset */
		printf("Reseting...\n");
	}

	static void
	syscmd_reset_cb(struct SYS_client *c,
			SYS_response_id id,
			const char *body,
			void *user)
	{
		enum SYS_RESULT res;

		res = SYS_set_response_cb(c, id, "{\"result\":\"OK\"}", SYS_RESPONSE_STATUS_OK,
					  syscmd_reset_response_cb, NULL);

		if (res != SYS_RESULT_OK) {
			fprintf(stderr, "%s: SYS_set_response_cb failed\n", __func__);
		}
	}

	int
	sysapp(struct evp_agent_context *ctxt, const char *name)
	{
		enum SYS_RESULT res;
		struct SYS_client *c = evp_agent_register_sys_client(ctxt);

		if (!c) {
			fprintf(stderr, "sysapp: error registering sysapp %s\n", name);
			return -1;
		}

		res = SYS_register_command_cb(c, "reset", syscmd_reset_cb, NULL);

		if (res != SYS_RESULT_OK) {
			fprintf(stderr, "%s: SYS_register_command_cb failed\n", name);
			return res;
		}

		for (;;) {
			res = SYS_process_event(c, 100);
			if (res == SYS_RESULT_SHOULD_EXIT)
				break;
			if (res != SYS_RESULT_OK) {
				fprintf(stderr,
					"sysapp: %s: error processing events: %s\n",
					name, SYS_result_tostr(res));
			}
		}

		evp_agent_unregister_sys_client(ctxt, c);
		return SYS_RESULT_OK;
	}

Blob Operations
***************

SysApps can handle blob operations.

HTTP operations can be ``GET``, ``PUT`` and
``PUT`` with ``Multiple Storage Token Provider``
with the respective APIs ``SYS_get_blob``, ``SYS_put_blob`` and
``SYS_put_blob_mstp``:

.. code:: C


	enum SYS_result SYS_get_blob(struct SYS_client *c, const char *url,
				const struct SYS_http_header *headers,
				SYS_blob_cb cb, void *user);


	enum SYS_result SYS_put_blob(struct SYS_client *c, const char *url,
				const struct SYS_http_header *headers,
				unsigned long datalen,
				SYS_blob_cb cb, void *user);

	enum SYS_result SYS_put_blob_mstp(struct SYS_client *c,
					const char *storage_name,
					const char *filename,
					unsigned long datalen,
					SYS_blob_cb cb, void *user);

The ``SYS_blob_cb`` type defines the prototype of the callback
called when the blob operation has data to produce or consume,
or has completed.

On receiving (``GET`` operation),
the data may get split into multiple calls to the blob callback.
It is the user's responsibility to recover the data
by concatenating the user reception buffer
with each ``SYS_blob_data::blob_buffer`` content
of length ``SYS_blob_data::len``.

On transmitting (``PUT`` operation),
the callback must fill ``SYS_blob_data::len`` bytes in the pointer provided
by ``SYS_blob_data::blob_buffer``.
If the total length is larger,
the blob callback will be called again for
the user to supply the rest of the data.

The callbacks must return ``SYS_RESULT_OK``
for the operation to continue.
Other return codes will abort the blob operation.

.. code:: C

	typedef enum SYS_result (*SYS_blob_cb)(struct SYS_client *c,
					struct SYS_blob_data *blob,
					enum SYS_callback_reason reason,
					void *user);

... where the ``user`` pointer is
the same used in the call to the blob operation functions.

Example:

.. code:: C

	#include <stdlib.h>
	#include <stdio.h>
	#include <string.h>

	#include <evp/agent.h>
	#include <evp/sdk_sys.h>

	#define BLOB_DATA "blob-data"
	#define BLOB_LEN  strlen(BLOB_DATA)

	struct user {
		char *data;
		int nsent;
	};

	static enum SYS_result
	blob_cb(struct SYS_client *c,
		struct SYS_blob_data *blob,
		enum SYS_callback_reason reason,
		void *vpuser)
	{
		struct user *user = vuser;
		if (reason == SYS_REASON_FINISHED) {
			/* Completed blob */
			/* Do something here */
			return SYS_RESULT_OK;
		}
		else if (reason == SYS_REASON_MORE_DATA) {
			if (user->nsent + blob->len > BLOB_LEN) {
				fprintf(stderr, "%s: Invalid amount of bytes left to send\n", __func__;
				return SYS_RESULT_ERROR_BAD_PARAMS;
			}
			/* Copy left data into `blob->blob_buffer` */
			memcpy(blob->blob_buffer, &user->data[user->nsent], blob->len);
			user->nsent += blob->len;
			return SYS_RESULT_OK;
		}
		return SYS_RESULT_ERROR_BAD_PARAMS;
	}

	int
	sysapp(struct evp_agent_context *ctxt, const char *name)
	{
		static const struct SYS_http_header headers[] = {
			{.key = "key1", .value = "value1"},
			{.key = "key2", .value = "value2"},
			{.key = "key3", .value = "value3"},
			NULL,
		};

		enum SYS_result res;
		struct SYS_client *c = evp_agent_register_sys_client(ctxt);
		struct user user = {
			.data = malloc(BLOB_LEN),
		};

		res = SYS_put_blob(c, "https://localhost:8080/data.txt", headers, BLOB_LEN, blob_cb, &user);

		if (res) {
			fprintf(stderr, "%s: SYS_put_blob failed with %s\n", name,
				SYS_result_tostr(res));
			goto end;
		}

		for (;;) {
			res = SYS_process_event(c, -1);

			if (res == SYS_RESULT_SHOULD_EXIT)
				break;
			if (res != SYS_RESULT_OK) {
				fprintf(stderr,
					"sysapp: %s: error processing events: %s\n",
					name, SYS_result_tostr(res));
			}
		}

	end:
		free(user.data);
		return NULL;
	}
