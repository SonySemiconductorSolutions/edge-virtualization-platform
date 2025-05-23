.. SPDX-FileCopyrightText: 2023-2025 Sony Semiconductor Solutions Corporation
..
.. SPDX-License-Identifier: Apache-2.0

.. _wasi_setup:

WASI SDK setup
##############

The build system uses the :ref:`wasm_toolchain` to build the test modules
that are required to be able to
run the test cases contained in the test directory.
The SDK is expected to be installed in the host system,
and the build system can be customized to adapt to different configurations
using two macros:

	* ``WASI_PREFIX``: It is a prefix that
	  is added to every command of the toolchain.
	* ``WASI_SYSROOT``: It is the location of the libc directory structure.

The official debian package distributed by the `WASI release`_
installs the binaries in ``/opt/wasi-sdk/bin/``,
so if that package is used then
the build system should be used as follows:

.. code:: shell

	make WASI_PREFIX=/opt/wasi-sdk/bin/

If the clang toolchain installed in the system supports wasi
and it is desired to use the libc installed with the `WASI release`_
then the build system can be invoked like:

.. code:: shell

	make WASI_SYSROOT=/opt/wasi-sdk/share/wasi-sysroot/

Of course,
in any case the parameters can be configured
in the personal ``config.mk``
as described in :ref:`personal_configuration`.

--------------

.. _WASI release: https://github.com/WebAssembly/wasi-sdk/releases
