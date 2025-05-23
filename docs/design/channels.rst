.. SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
..
.. SPDX-License-Identifier: Apache-2.0

Channels
********

Channels are mechanisms used in the agent
to share and synchronize threads.
They are basically a queue that supports two primitives:

	- ``chan_send``.
	- ``chan_recv``.

Both of them are based on a ``chan_msg``
that is the unit transmitted in the queue.
These functions return the number of messages sent/received,
0 or 1,
with 0 usually being an error in the case of ``chan_send``.
A ``chan_msg`` is:

.. code:: C

	struct chan_msg {
		void (*fn)(struct chan_msg *);
		void *param;
		void *resp;
	};

The field ``fn`` defines the function
that will attend the message on the receiver side
while ``param`` is a pointer to the input parameters
and ``resp`` is a pointer to the output response.
The field ``resp`` also defines the behaviour of the channel,
if it is ``NULL`` then it is considered an asynchronous message
but if it is different than ``NULL`` then
it is a synchronous message.

There are several versions the receiving function:

	- ``chan_recv``: It blocks the thread until a message is received.
	- ``chan_tryrecv``: It attends a pending message if any and otherwise
	  it just returns without blocking.
	- ``chan_timedrecv``: It blocks the thread until a message is received
	  or a timeout expires.

It is important to notice that in both cases,
synchronous and asynchronous messages,
the message passed to ``chan_send`` is copied when
it is stored in the channel queue,
so the sender can use local variables for ``chan_msg``
even in the case of asynchronous messages.
Beware that it only applies to the ``chan_msg`` struct itself
and not to the memory pointed to by ``params`` and ``resp``.

For asynchronous messages, when ``resp`` is ``NULL``,
care must be taken in allocating ``params``
in the heap or statically, because these data should be
available to the agent running on another thread.

Semantic of synchronous messages
================================

A synchronous channel follows the semantic of `CSP`_,
where a communication in the channel implies a rendezvous
between ``chan_send`` and ``chan_recv``.
The thread calling ``chan_send`` will block
until the other endpoint thread calls ``chan_recv``
and it finishes the execution of the receiving function indicated in the message.
This rendezvous implies a synchronization between both threads
and it means
that the receiving thread can access the parameters in mutual exclusion.
This can be summarized by the Go lemma `Share Memory By Communicating`_:

	Don\'t communicate by sharing memory; share memory by communicating.

Channels allow passing references to data structures between
threads. If this is considered passing around ownership of the data
(the ability to read and write it), they become a powerful and expressive
synchronization mechanism.

Semantic of asynchronous messages
=================================

When a message is sent using ``chan_send`` but
the field ``resp`` is ``NULL``
then the message is just enqueued and sends returns immediately.
It means
that the life of parameters passed by ``params`` must be longer that
the function calling ``chan_send``,
usually implying dynamic memory because
as the sender doesn\'t known when
the receiver will attend the message
only the receiver can free the memory allocated by the sender.

Example of a synchronous message
================================

.. code:: C

	struct sum_params {
		int *ary;
		int n;
	};

	void
	add(struct chan_msg *msg)
	{
		int i, n, *out = msg->resp;
		struct sum_params *p = msg->params;

		for (i = n = 0; i < p->n; i++)
			n += p->ary[n];
		*out = n;
	}

	void
	sender(struct chan *ch, int *array, int size)
	{
		struct chan_msg msg;
		struct sum_params par;
		int sum;

		par.ary = array
		par.n = siz;

		msg.fn = add;
		msg.params = &par;
		msg.resp = &sum;

		if (chan_send(&msg) != 1) {
			perror("sender");
			return;
		}

		printf("sum value=%d\n", ret);
	}

	void
	receiver(struct chan *ch)
	{
		for (;;)
			chan_recv(ch);
	}

The thread calling ``sender`` will block
until the thread calling ``receiver`` finishes the execution of ``add``
and it means
that ``receiver`` accesses the integer array in mutual exclusion
without race conditions.

Example of an asynchronous message
==================================

.. code:: C

	struct sum_params {
		int *ary;
		int n;
	};

	void
	add(struct chan_msg *msg)
	{
		int i, n;
		struct sum_params *p = msg->params;

		for (i = n = 0; i < p->n; i++)
			n += p->ary[n];
		printf("sum value=%d\n", n);
		free(p);
	}

	void
	sender(struct chan *ch, int *array, int n)
	{
		struct chan_msg msg;
		struct sum_params *par;

		par = malloc(sizeof(struct sum_params));
		if (!par) {
			free(ary);
			perror("sender");
		}

		par->ary = array
		par->n = n;

		msg.fn = add;
		msg.params = &par;
		msg.resp = NULL;

		if (chan_send(&msg) != 1) {
			perror("sender");
			return;
		}
        }

	void
	receiver(struct chan *ch)
	{
		for (;;)
			chan_recv(ch);
	}

The thread calling ``sender`` returns from ``chan_send`` as soon
the request is stored in the internal queue of the channel
and it means
that it cannot free the memory pointed to by ``par``
because it does not known when
the receiver thread will use it.
In the same way,
the thread calling ``sender`` does not know
when it can use the memory pointed by array without race conditions.
External mechanism are needed to ensure the mutual exclusion
of the sender thread has to assume that
the full ownership of the memory pointed to by ``array``
was transferred to the thread calling ``chan_recv``
until the end of life of that memory.

--------------

.. _CSP: https://en.wikipedia.org/wiki/Communicating_sequential_processes
.. _Share Memory By Communicating: https://go.dev/doc/codewalk/sharemem/
