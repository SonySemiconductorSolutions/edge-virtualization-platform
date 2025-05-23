.. SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
..
.. SPDX-License-Identifier: Apache-2.0

.. _main_loop:

Main loop
*********

The ``main_loop`` component deals with
the timing required by the main loop of the agent.
It provides primitives to
wait for an event and to
wake up the agent when it is required.

The mechanism of this component is based in a call to `poll(2)`
where it waits for events in different file descriptors.
Some operations are not based in file descriptors
(for example, data available in some queue)
and for that reason it has to provide another mechanism to awaken the main loop.
While a common approach would be to send a signal
it doesn\'t work well with `poll(2)` and
the agent uses the well-known `self-pipe trick`_,
but as the agent is executed as a Nuttx task in some configurations
and Nuttx tasks don\'t share file descriptors (see `Nuttx documentation`_) then
a named pipe is required.
By default it tries to create a temporary pipe
but this location can be overridden using the `EVP_AGENT_FIFO` environment variable.

.. c:function:: void main_loop_init(void)

	This function initializes the pipe required by the `self-pipe trick`_,
	using the one already present in the filesystem
	or by creating a new one
	if it doesn\'t exist.
	By default it uses a temporary named pipe
	but it can be overridden using the `EVP_AGENT_FIFO` environment variable.
	If it cannot create this, it instead prints an error message and
	tries to continue,
	but it would work in degraded mode and
	unexpected behaviours can happen.

.. c:function:: void main_loop_block(void)

	This function blocks the main thread waiting for an event,
	and after the event arrives
	the pending part of the main loop is executed.
	It uses a call to `poll(2)` to block until
	some file descriptor is ready for some operation or
	until the `self-pipe trick`_ is used.

.. c:function:: void main_loop_wakeup(const char *name)

	This function uses the `self-pipe trick`_ to force an exit
	from the call to `poll(2)` done in :c:func:`main_loop_block`.
	A string is received as parameter for logging purpose
	recording why the main loop was awoken.

--------------

.. _self-pipe trick: https://cr.yp.to/docs/selfpipe.html
.. _Nuttx documentation: https://nuttx.apache.org/docs/latest/reference/user/01_task_control.html#task-control-interfaces
