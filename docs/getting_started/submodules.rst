.. SPDX-FileCopyrightText: 2023-2025 Sony Semiconductor Solutions Corporation
..
.. SPDX-License-Identifier: Apache-2.0

.. _git_submodules:

Git Submodules
##############

This repository uses git submodules
as external dependencies.

The build system will automatically check-out
dependent submodules as part of the build,
according to the given configuration.
See :ref:`depend_target` for further details.

Executing the single command ``make`` will build
a default configuration
and check-out all dependent submodules.

Executing the command ``make distclean``
will deinitialize all the submodules.

Submodules can be checked-out manually with the command:

.. code-block:: shell

    git modules update --init --recursive

or, when cloning a fresh repo:  

.. code-block:: shell  

    git clone --recursive git@github.com/<repository>.git

So that all submodules
and dependent recursive modules
are checked-out.
