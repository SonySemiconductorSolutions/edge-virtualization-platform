.. SPDX-FileCopyrightText: 2023-2025 Sony Semiconductor Solutions Corporation
..
.. SPDX-License-Identifier: Apache-2.0

.. _prerequisites:

Prerequisites
#############

This document describes the basic setup required to
build the EVP Agent for the Linux target.
Specific information required for the build of the different
hardware platform can be found in their specific sections.

While different combinations of tools and
dependencies might work, the only supported
ones are those in the list provided in this document,
with annotaged versions.

Build Host
**********

EVP Agent build is based on UNIX compatible systems,
and, while it should work in other Linux distributions,
only tested and supported are the following:

	* Ubuntu 24.04 LTS (64-bit AArch64 and AMD64)
	* Raspberry Pi OS bookworm (64-bit AArch64).

Other non-Linux UNIX-compatible systems may work,
but this is not guaranteed and have not been tested.

.. _prerequisites_toolchain:

Toolchain
*********

EVP Agent build is tested for AMD64 and AArch64 architectures
using gcc and clang. The recommended tools are:

	* `GNU Binutils`_
	* `Gcc`_ 13
	* `Clang`_ 18

Some functionalities, such as code formatting, rely on
clang independently of the toolchain used to compile the agent.

EVP Agent requires the following tools:

	* A toolchain (see :ref:`prerequisites_toolchain`)
	* `GNU make`_. Other versions of make can work too
	  (such as BSD make), but it has not been tested.
	* `CMake`_ (at least version 3.14)
	* `Git`_
	* `Kconfiglib`_
	* `Python3`_
	* ``jq``
	* ``python3-dev``: python3 development packages
	* ``python3-build``: python build

It also requires the following libraries:

	* `WAMR`_ 2.1.2
	* `MbedTLS`_ 3.6.2
	* `Nanomsg-ng`_ 1.7.3
	* `Flatcc`_ 0.6.1

All these libraries are shipped as :ref:`git_submodules` within
the EVP Agent git repository, so it is not required to have them
installed in the system. In case of being needed, the build system
can be configured to use external versions of these libraries.

Not all of them are always required always, some of them are used
only when some features are enabled in the Kconfig configuration
(see :ref:`kconfig`).

.. _wasm_toolchain:

Toolchain for WASM modules
**************************

The WASM modules need to be built with clang toolchain.
Either with upstream clang and a wasi-sysroot from wasi-sdk,
or with the wasi-sdk debian package which already includes
clang and wasi-sysroot preconfigured with wasm as default
target.

To build the AoT and XiP modules, WAMRC is required.

This requires:

	* `WASI-SDK`_ 24
	* `WAMRC`_ 2.1.2

Package installation
********************

The required packages can be installed in Debian-like systems using:

.. code:: shell

	sudo apt-get install python3-pip make cmake binutils
	pip3 install kconfiglib

After running these commands, ensure that
all the tools are accessible through the ``PATH`` variable and
it is likely that it will be necessary to add this to the shell profile:

.. code:: shell

	PATH=$PATH:~/.local/bin

or any other location where the `Kconfiglib`_ binaries are
installed. To avoid that problem it is usual to use
a Python venv:

.. code:: shell

	sudo apt-get install python3-pip make cmake binutils
	python3 -m venv .venv
	. .venv/bin/activate
	pip3 install kconfiglib

Getting the EVP Agent source
****************************

The source code of the EVP Agent is maintained as a `Github`_
repository, that can be cloned using:

.. code:: shell

	git clone https://github.com/SonySemiconductorSolutions/edge-virtualization-platform.git


--------------

.. _GNU Binutils: https://gnu.org/software/binutils
.. _GNU Make: https://www.gnu.org/software/make
.. _Gcc: https://gcc.gnu.org
.. _Clang: https://clang.llvm.org
.. _CMake: https://cmake.org
.. _Git: https://git-scm.com
.. _KconfigLib: https://pypi.org/project/kconfiglib
.. _Python3: https://www.python.org
.. _WAMR: https://bytecodealliance.github.io/wamr.dev
.. _MbedTLS: https://www.trustedfirmware.org/projects/mbed-tls
.. _Nanomsg-ng: https://nng.nanomsg.org
.. _Flatcc: https://github.com/dvidelabs/flatcc
.. _Github: https://www.github.com
.. _WASI-SDK: https://github.com/WebAssembly/wasi-sdk
.. _WAMRC: https://github.com/bytecodealliance/wasm-micro-runtime/blob/main/wamr-compiler/
