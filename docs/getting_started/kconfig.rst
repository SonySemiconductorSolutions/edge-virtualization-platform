.. SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
..
.. SPDX-License-Identifier: Apache-2.0

.. _kconfig:

Kconfig
#######

This project makes use of `KConfig <>` for build-time configurations.
``KConfig`` is a well-known tool
that originated from the `Linux kernel`_.
Among the various implementations available,
the `Kconfiglib`_ implementation
is required by this project.
See the :ref:`prerequisites` documentation for further reference.

The build system relies on the ``KBUILD_DEFCONFIG`` Make variable
to determine the configuration.
``KBUILD_DEFCONFIG`` must point to a file
including the list of configurations.
For example:

.. code:: shell

	make KBUILD_DEFCONFIG=/path/to/my/config

This file is used to generate a ``.config`` file in the root directory,
which in turn is included by the build system
to generate a ``config.h`` header file
inside the ``include/`` directory.
This header file is later consumed by other source files.

If no ``KBUILD_DEFCONFIG`` is given,
``configs/default.config`` is selected by default.
``configs/default.config`` points to builds meant for Raspberry Pi users.

In order to remove the generated ``config.h``,
call ``make distclean``.
Note that this will also remove other artifacts,
such as object files,
as well as de-initializing all submodules in the repository.

Available configurations
************************

The ``configs/`` directory provides a set of ``.config`` files
that can be used as ``KBUILD_DEFCONFIG``.
However, all of them
(except from ``unit-test-all-hubs-wasm.config`` and ``default.config``)
are there for historical reasons,
they are not actively tested
and therefore they are not guaranteed to be maintained.

``unit-test-all-hubs-wasm.config`` is the configuration shared
among all unit tests and system tests.

.. _Linux kernel: https://git.kernel.org
.. _KconfigLib:  https://github.com/ulfalizer/Kconfiglib
