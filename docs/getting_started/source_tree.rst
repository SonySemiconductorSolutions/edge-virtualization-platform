.. SPDX-FileCopyrightText: 2023-2025 Sony Semiconductor Solutions Corporation
..
.. SPDX-License-Identifier: Apache-2.0

Source Directory Structure
##########################

This document provides an overview of
the structure of the repository
and the purpose of its key directories and files.

Key directories and files
*************************

* ``configs/``:
  Build system preset configuration files ``*.config``.
  These files can be used to build a specific configuration.
  See :ref:`config_target` for further details.

* ``docs/``:
  Documentation sources to be built with ``Sphinx``.
  This includes guides, design, and API documentation.

* ``include/``:
  C header files used accross project
  for shared definitions and interfaces.

* ``LICENSES/``:
  License files for the project
  and any third-party dependencies.

* ``scripts/``:
  Utility scripts for building and managing the project.
  See :ref:`rules.mk` for further details.

    - ``build/``: Contains makefiles for build variants.

       - ``sys/``: System specific makefiles, used according to
         the target platform (nuttx, posix, wasm)

       - ``tool/``: Tool chain specific makefiles
         (ccov, clang, gnu, wasi, etc.).

* ``src/``:
  Main source code of the project,
  organized into :ref:`git_submodules`.

    - ``flatcc/``: FlatBuffers compiler and related utilities (git module).
    - ``libparson/``: JSON parsing library.
    - ``libevp-agent/``: EVP Agent library.
    - ``libevp-app-sdk/``: EVP Application SDK for modules.
    - ``libevp-utils/``: Utility functions for the EVP project.
    - ``mbedtls/``: Lightweight cryptographic library (git module).
    - ``nng/``: Lightweight messaging library (git module).
    - ``python-evp-app-sdk/``: Python version sources of the EVP Application SDK.
    - ``wasm-micro-runtime/``: WebAssembly Micro Runtime integration (git module).
    - ``evp-agent/``: The runtime of the default EVP Agent.

* ``test/``:
  Test cases and supporting resources for the project.

    - ``certs/``: Certificates for testing (generated at build time).
    - ``libweb/``: Web server library (git module).
    - ``mock_objects/``: Shared code for test framework including default mocks.
    - ``src/``: Tests sources organized into suites.

       - ``*/``: Specific test suites (Unit Tests and System Tests)
    - ``websrv/``: Web server component.

* ``test_modules/``:
  Modules sources used in System Tests.

    - ``python/``: Python version of modules

* ``tools/``:
  Developer tools and utilities.

    - ``fortify/``: Filter files for static code analysis
      and security auditing Fortify tool.

* ``check.mk``: Makefile fragment for checks.
* ``LICENSE``: Project licensing terms.
* ``Makefile``: Primary makefile for building the project.
* ``pyproject.toml``: Python project configuration.
* ``README.md``: Overview of the project, including usage and contribution guidelines.

Build-time created directories
******************************

The build system creates ``lib``
and ``bin`` directories
to respectively store project built libraries
and binaries artifacts.
See :ref:`build_system` for further details.

Usage
*****

This structure ensures the repository is
organized, maintainable, and scalable
for future growth.
