.. SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
..
.. SPDX-License-Identifier: Apache-2.0

.. _rules.mk:

``scripts/rules.mk``
====================

This is the main file of the build system,
and it contains the generic rules and macros used by all the Makefiles.
The behaviour of this file is modified by the macros:

	* ``TOOL``: Selects the toolchain used for building.
	* ``SYS``: Selects the target system for building.
	* ``ARCH``: Selects the target architecture for building.
	* ``KBUILD_DEFCONFIG``: Selects the Kconfig file used for configuration.

All the Makefiles are able to include this file based in the macro ``PROJECTDIR``,
as it is the first thing defined in any Makefile:

.. code:: Makefile

	PROJECTDIR = ../
	include $(PROJECTDIR)/scripts/rules.mk

``rules.mk`` defines the common locations used by all the Makefiles:

	* ``INCDIR``: Directory for include files.
	* ``BINDIR``: Directory for binary executables.
	* ``LIBDIR``: Directory for libraries.
	* ``SCRIPTDIR``: Directory for shared scripts.

These locations are used in several places,
for example, in the generic rules for the `-I` options.
Every rule can be customized by the following macros:

	* ``PROJ_CPPFLAGS``: Flags used by the preprocessor.
	* ``PROJ_CFLAGS``: Flags used by the C compiler.
	* ``PROJ_LDFLAGS``: Flags used by the linker.
	* ``PROJ_ASFLAGS``: Flags used by the assembler.
	* ``PROJ_ARFLAGS``: Flags used by the library archiver.
	* ``PROJ_RLFLAGS``: Flags used by the library randomizer.
	* ``PROJ_LDLIBS``: Flags used by the linker to include libraries.

All these macros are built based on four categories:

	* ``MORE_XXXX``: Flags added by specific Makefiles.
	* ``SYS_XXXX``: Flags defined for the target system (such as Linux or Nuttx).
	* ``TOOL_XXXX``: Flags defined for the toolchain (such as gnu or clang).
	* **User flags**: Flags controlled by the user to customize the build:

		- ``CFLAGS``: For the compiler command.
		- ``LDFLAGS``: For the linker command.
		- ``LIBS``: For the additional libraries added to the linker command.
		- ``ARFLAGS``: For the library archiver command.
		- ``RLFLAGS``: For the library index builder command.
		- ``ASFLAGS``: For the assembler command.

For example, a Makefile can do:

.. code:: Makefile

	PROJECTDIR = ../
	include $(PROJECTDIR)/scripts/rules.mk

	MORE_CPPFLAGS = -I./local_include

and all the objects compiled by that Makefile will include that option.

In the same way, a user can run the make with:

.. code:: shell

	make CFLAGS=-g

and all the objects will be compiled adding the option ``-g`` to the C compiler flags.

``rules.mk`` also defines the rules to maintain the recursive structure.
The macro ``DIRS`` must be defined by the Makefile before including ``rules.mk``
and then make will apply automatically the recursive targets to them.
For example:

.. code:: Makefile

	PROJECTDIR = ../
	DIRS = libevp-agent libevp-app-sdk
	include $(PROJECTDIR)/scripts/rules.mk

	all: libevp-agent libevp-app-sdk

defines ``libevp-agent`` and ``libevp-app-sdk`` as recursive targets and
when the target *all* is required to build then
make will move unconditionally to them and
it will build the target *all* on them.

In the same way,
when the special targets ``clean`` and ``distclean`` are invoked,
the build system iterates unconditionally to the directories specified in ``DIRS``,
invoking the target on each directory,
before invoking the target in the current directory.

``rules.mk`` contains the more common ``clean`` and ``distclean`` actions that
usually are required by the Makefiles,
and the Makefiles don\'t have to define them
unless they need special actions. For example:

.. code:: Makefile

	clean:
		rm -f MQTT-C/*.o

will remove all the artifacts generated in the current directory
and it will remove all the objects in the MQTT-C directory.

.. _toolchain:

Toolchains and cross compilation
--------------------------------

The toolchain is selected by the Make macro ``TOOL``
and it defines all the macros required for a specific toolchain.
The file ``scripts/rules.mk`` defines the default values of all the tools using:

.. code:: Makefile

	CXX = $(CROSS_COMPILE)$(COMPXX)
	CC = $(CROSS_COMPILE)$(COMP)
	AS = $(CROSS_COMPILE)$(ASM)
	LD = $(CROSS_COMPILE)$(LINKER)
	AR = $(CROSS_COMPILE)$(ARCHIVE)
	CPP = $(CROSS_COMPILE)$(PRECOMP)
	NM = $(CROSS_COMPILE)$(NAMES)
	RANLIB = $(CROSS_COMPILE)$(RLIB)
	OBJCOPY = $(CROSS_COMPILE)$(OCOPY)
	OBJDUMP = $(CROSS_COMPILE)$(ODUMP)

All the tools are defined prepending the macro ``CROSS_COMPILE``,
which is used for cross compilation.
For example,
if the build is for linux aarch32 and musl libc using a PC
which has installed a GNU arm toolchain for
that configuration it can cross compile using something like:

.. code:: shell

	make config
	make TOOL=gnu CROSS_COMPILE=arm-linux-musleabi- ARCH=armel

which will use the cross compiler and will also select the desired
target architecture for :ref:`wasm_toolchain`.
The first ``make`` execution with the target ``config``
configures the build (see :ref:`config_target` for the config *target*
and :ref:`architecture` for the definition of the ``ARCH`` macro).

Every toolchain is expected to define the following macros:

	* ``COMPXX``: C++ compiler.
	* ``COMP``: C compiler.
	* ``ASM``: Assembler program.
	* ``LINKER``: Linker program.
	* ``ARCHIVE``: Program used to create library archives.
	* ``PRECOMP``: C preprocessor.
	* ``NAMES``: Nm compatible program.
	* ``RLIB``: Ranlib compatible program.
	* ``OCOPY``: Objcopy compatible program.
	* ``ODUMP``: Objdump compatible program.

Optionally,
toolchains can define the following macros

	* ``TOOL_CFLAGS``: Flags added by the toolchain to compile C files.
	* ``TOOL_CXXFLAGS``: Flags added by the toolchain to compile C++ files.
	* ``TOOL_LDFLAGS``: Flags added by the toolchain to to link programs.
	* ``TOOL_ASFLAGS``: Flags added by the toolchain to assembly files.
	* ``TOOL_ARFLAGS``: Flags added by the toolchain to create libraries.
	* ``TOOL_RLFLAGS``: Flags added by the toolchain to create library indexes.
	* ``TOOL_LDLIBS``: Libraries added by the toolchain to link programs.

``TOOL`` can take one of the following values:

	* ``gnu``: It is the default value and defines all the values for the GNU toolchain.
	* ``clang``: Defines all the values for the clang toolchain.
	* ``wasi``: Defines all the values for the :ref:`wasm_toolchain` used to compile to wasm.
	* ``cppcheck``: Toolchain that extends the GNU toolchain
	  to perform static analysis.

For example,
if static analysis using cppcheck is required,
it is possible to run:

.. code:: shell

	make config
	make TOOL=cppcheck analysis

The ``gnu`` and ``clang`` toolchains can be customized using two macros:

	* ``SANITIZER``: Setting it to ``ENABLED`` enables the sanitizer options.
	* ``COVERAGE``: It can select a coverage tool for the build process.

		- ``ccov``: Coverage using clang options.
		- ``gcov``: Coverage using gcc options.

While ``ccov`` is tied to clang,
``gcov`` can be used with both toolchains in some systems.
Both coverage tools add a *coverage* target
that generates the coverage information.
For example:

.. code:: shell

	make config
	make TOOL=clang SANITIZER=ENABLED COVERAGE=ccov test
	make TOOL=clang COVERAGE=ccov coverage

will compile and execute the tests (see :ref:`test_target`).
with the sanitizer options and
with the clang coverage instrumentation
and the last ``make`` execution with the ``coverage`` target
generates a directory called ``coverage``
that contains all the html and coverage information.
The ``ccov`` coverage tool is also used in the ci
and contains a special target ``coverage-ci`` that
filters the coverage information to cover only the ``libevp-agent`` library.

.. _architecture:

Architecture definition
-----------------------

``ARCH`` is not usually required,
because it is usually derived from the output of ``uname``,
but it cannot be derived in that way for cross compilation
or in systems that lack ``uname``.
In that case it is required and
the list of accepted values for ``ARCH`` is:

	* ``x86_64``: `System V AMD64 ABI`_.
	* ``i386``: `System V Intel386 ABI`_.
	* ``aarch64``: `System V Arm 64 bit ABI`_.
	* ``armel``: `System V Arm 32 bit ABI with hardware floating point`_.
	* ``armhf``: `System V Arm 32 bit ABI with software floating point`_.
	* ``xtensa``: `Xtensa ESP32 ABI`_.

System definition
-----------------

As there are some build flags that depend of the target system
the build system can be customized using the macro ``SYS``.
This macro is usually sets by default using ``uname``,
but it can be required in some systems lacking that tool or
when cross compilation is used.
The target build systems supported are:

	* ``posix``: It defines the required options for fully POSIX complaint systems.
	* ``nuttx``: It defines the required options for NuttX.
	* ``wasm``: It defines the required options compiling for WASM target (used by modules).

Default rules
-------------

There is a set of rules
that are shared between all the Makefiles
and ``rules.mk`` contains the common definition for all of them.

.. code:: Makefile

	FORCE:
	.PHONY: FORCE

The target ``FORCE`` can be used in any rule to force a build of the target.
It brings the same behavior of the common extension rule ``.PHONY``,
but it is pure POSIX without needing the GNU extension.

.. code:: Makefile

	.s.o:
		$(AS) $(PROJ_ASFLAGS) $< -o $@

This rule generates an object file from an assembly file
without applying the C preprocessor,
while the rule

.. code:: Makefile

	.S.o:
		$(CPP) $(PROJ_CPPFLAGS) $< | $(AS) $(PROJ_ASFLAGS) -o $@

uses the C preprocessor before assembling the file.

It contains rules to generate an object file from a C or C++ file:

.. code:: Makefile

	.c.o:
		$(CC) $(PROJ_CFLAGS) -o $@ -c $<

	.cpp.o:
		$(CC) $(PROJ_CXXFLAGS) -o $@ -c $<

It has a rule
that can be used to generate an executable elf file from an object of the same name

.. code:: Makefile

	.o.elf:
		$(CC) $(PROJ_LDFLAGS) -o $@ $< $(PROJ_LDLIBS)

that for example will generate ``hello`` from ``hello.o``.

It also contains a special rule that compiles a C file into a ``wo`` file
that is required
when native and wasm applications are required in the same directory:

.. code:: Makefile

	.c.wo:
		$(CC) $(PROJ_CFLAGS) -o $@ -c $<

	.wo.wasm:
		$(CC) $(PROJ_LDFLAGS) -o $@ $<


``rules.mk`` also contains a set of rules for debugging:

.. code:: Makefile

	.c.s:
		$(CC) $(PROJ_CFLAGS) -S -o $@ $<

	.c.i:
		$(CPP) $(PROJ_CPPFLAGS) -o $@ $<

	.o.dump:
		trap "rm -f $$$$.dump" EXIT QUIT INT TERM;\
		$(OBJDUMP) -D $< > $$$$.dump && mv $$$$.dump $@

	.elf.dump:
		trap "rm -f $$$$.dump" EXIT QUIT INT TERM;\
		$(OBJDUMP) -D $< > $$$$.dump && mv $$$$.dump $@

	.o.lst:
		trap "rm -f $$$$.lst" EXIT QUIT INT TERM;\
		$(NM) $< > $$$$.lst && mv $$$$.lst $@

	.elf.lst:
		trap "rm -f $$$$.lst" EXIT QUIT INT TERM;\
		$(NM) $< > $$$$.lst && mv $$$$.lst $@

	.a.lst:
		trap "rm -f $$$$.lst" EXIT QUIT INT TERM;\
		$(NM) -A $< > $$$$.lst && mv $$$$.lst $@

Allowing such actions as:

	* Generating an assembly file from a C file.
	* Generating the output of the C preprocessor.
	* Generating a disassembly of an object file.
	* Generating a dissasembly of an elf file.
	* Generating a symbol list form an object.
	* Generating a symbol list form an elf file.
	* Generating a symbol list from a library archive.

It also defines rules for common targets,
for example ``clean`` and ``distclean``,
which will have common command lines between
the different directories,
removing the generated artifacts by the previous commented rules.
They also consider the definition of the macro ``DIRS``
and apply them in a recursive way.

It also contains a few rules
that makes easier the integration with `CMake`_:

.. code:: Makefile

	# CMake rules
	%/build/Makefile: %/CMakeLists.txt
		CC=$(CC) \
		CXX=$(CXX) \
		SYS=$(SYS) \
		ARCH=$(ARCH) \
		CFLAGS="$(CFLAGS)" \
		MBEDTLS_CFLAGS="$(MBEDTLS_CFLAGS)" \
		$(SCRIPTDIR)/cmake-$* $(PWD)/$(PROJECTDIR)

	%: %/build/Makefile FORCE
		cd $@/build && $(MAKE) install

that enables actions such as:

.. code:: Makefile

	# cmake dependencies
	wasm-micro-runtime: wasm-micro-runtime/build/Makefile
	flatcc: flatcc/build/Makefile
	mbedtls: mbedtls/build/Makefile
	nng: nng/build/Makefile

that will generate a chain of dependencies
which will compile correctly a `CMake`_ project
containing a ``CMakeList.txt`` file.

.. _personal_configuration:

Personal configuration
----------------------

The build system allows a personal configuration file,
useful in same cases where it can be very tedious to pass always all the parameters,
and for that reason
it tries to include the file ``config.mk`` (which can be customized by the user) from the top level directory.

This file can include multiple definitions, for example:

.. code:: Makefile

	WASI_PREFIX=/opt/wasi-sdk/bin/
	CFLAGS=-g -Og
	TOOL=clang
	KBUILD_DEFCONFIG=configs/unit-test-all-hubs-wasm.config


defining the value of the macros
``WASI_PREFIX``,
``CFLAGS``,
``TOOL``
and ``KBUILD_DEFCONFIG``
for all the Makefiles
(see :ref:`config_target` and :ref:`toolchain` for the meaning of these macros),
usable for debug purposes.

--------------

.. _System V AMD64 ABI: https://refspecs.linuxbase.org/elf/x86_64-abi-0.99.pdf
.. _System V Intel386 ABI: https://www.sco.com/developers/devspecs/abi386-4.pdf
.. _System V Arm 64 bit ABI : https://github.com/ARM-software/abi-aa/blob/main/sysvabi64/sysvabi64.rst
.. _System V Arm 32 bit ABI with hardware floating point : https://github.com/ARM-software/abi-aa/blob/main/bsabi32/bsabi32.rst
.. _System V Arm 32 bit ABI with software floating point: https://github.com/ARM-software/abi-aa/blob/main/bsabi32/bsabi32.rst
.. _Xtensa ESP32 ABI : https://github.com/espressif/xtensa-isa-doc
.. _CMake: https://cmake.org/
