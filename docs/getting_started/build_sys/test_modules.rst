.. SPDX-FileCopyrightText: 2023-2025 Sony Semiconductor Solutions Corporation
..
.. SPDX-License-Identifier: Apache-2.0

.. _test_modules:

``test_modules/Makefile``
#########################

This Makefile is in charge of generating all the modules
used by the different tests executed to verify the agent.
It is able to build them to different targets:

	* ``elf``: Native binary modules that can be executed with the spawn module implementation.
	* ``wasm``: Wasm binary modules that can be executed with the wasm module implementation.
	* ``aot``: WARM AoT binary modules that can be executed with the wasm module implementation
	  but with an important performance improvement.
	* ``xip``: Wasm binary modules that can be executed with the wasm module implementation
	  but that can be executed directly from ROM (eXecute In Place).
	* ``signed``: Wasm xip binary modules that are signed.

By default,
the Makefile only builds ``elf`` and ``wasm`` modules,
but ``aot``, ``xip`` and ``signed`` modules can be build with:

.. code:: shell

	make KEY_FILE=path signed

where ``KEY_FILE`` points to the file containing the key used to sign.
By default is uses a key located in ``tools/module_key.bin``
that is only used in a few tests,
which are disabled by default.

In order to build the test modules
it is required to have installed the WASI SDK as described in :ref:`wasm_toolchain` and in :ref:`wasi_setup`.
