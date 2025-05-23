.. SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
..
.. SPDX-License-Identifier: Apache-2.0

Local debugging using gdb
=========================

By default, the build system generates an executable for the local host,
as defined in the :ref:`all_target`.
It is possible to use that executable with `GDB`_ to run it
using step debugging or breakpoints.
For a better debug experience
it is desirable to have debug symbols and
disable optimizations.
This can be done by passing the appropiate flags
to the build system.
For example,
in POSIX alike systems:

.. code:: shell

    make CFLAGS='-g -Og' LDFLAGS=-g

As these flags would be required in every compilation,
it is better to set them in the personal configuration
as it is shown in the :ref:`personal_configuration` section.

It is important to notice that
to be able to run the agent in `GDB`_,
the same configuration and environment
for a normal execution is required,
as explained in :ref:`running_the_agent`.

For a detailed description of the `GDB`_ commands
it is possible to use the `info` command in any `UNIX` machine:

.. code:: shell

    info gdb

There are many graphical frontends for `GDB`_,
like for example `DDD`_.
Almost all the development environments,
like for example
`VScode`,
`Eclipse`,
`Emacs`,
include a frontend for `GDB`_.
Please,
consult the documentation of the development environment
to learn how to setup it to use `GDB`_.

--------------

.. _GDB: https://www.sourceware.org/gdb
.. _DDD: https://www.gnu.org/software/ddd
.. _Nemiver: https://wiki.gnome.org/Apps/Nemiver
