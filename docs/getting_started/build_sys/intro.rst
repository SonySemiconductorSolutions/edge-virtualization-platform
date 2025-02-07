.. SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
..
.. SPDX-License-Identifier: Apache-2.0

Introduction
############

Before building,
all of the dependencies listed in :ref:`prerequisites`
must be installed.

The EVP Agent
build system is based in make,
using some extensions commonly implemented by all the make implementations.
While it is possible that
it works with other make implementations,
it is only tested with `GNU Make`_.
The Makefiles consume the build configuration managed by `Kconfig`_.
The Kconfig file is processed by `Kconfiglib`_ that generates two files:

	* ``.config``: Contains all the definitions required by the Makefiles.
	* ``include/config.h``: Contains all the definitions required by the C code.

The build system is a recursive make
where make switches to different directories
and use specialized Makefiles
that contain only the required rules and definitions for those directories.
All the shared rules, definitions, and scripts are located in the scripts directory.

Building the default configuration natively for a Linux system
can be done with:

.. code:: shell

	make -j$((`nproc` * 2))

and it will compile the agent and sdk libraries
and also the reference agent using the agent library.

--------------

.. _GNU Make: https://www.gnu.org/software/make
.. _Kconfig: https://www.kernel.org/doc/html/next/kbuild/kconfig-language.html
.. _KconfigLib: https://pypi.org/project/kconfiglib
