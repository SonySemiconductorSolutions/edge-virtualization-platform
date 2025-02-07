.. SPDX-FileCopyrightText: 2023-2025 Sony Semiconductor Solutions Corporation
..
.. SPDX-License-Identifier: Apache-2.0

``libevp-agent`` and ``libevp-app-sdk`` Makefiles
=================================================

These Makefiles are called recursively by the top-level Makefile,
and they use a structure based on the `Kbuild system`_.
They use a macro called ``obj-y``
to collect the list of objects required to build the library.
The value of this macro is composed of several statements, such as:

.. code:: Makefile

	obj-y += agent_event.o
	obj-$(CONFIG_EVP_MODULE_IMPL_DOCKER) += docker.o

The first statement ``obj-y += agent_event.o``
adds the object file called ``agent_event.o`` to the ``obj-y`` list,
but the second statement ``obj-$(CONFIG_EVP_MODULE_IMPL_DOCKER) += docker.o``
adds conditionally the object ``docker.o``
based in the value of the macro ``CONFIG_EVP_MODULE_IMPL_DOCKER``,
which derives from the ``.config`` file generated in the :ref:`config_target`.
This structure simplifies the Makefile and avoids complex if-else chains
as every Kconfig option becomes a conditional statement.
If the Kconfig value is not set,
or it is set to a value different than ``y``,
then the list of objects will not be added to ``obj-y`` but to ``obj-`` or ``obj-n``
keeping them out of the final list of objects used to build the libraries.


--------------

.. _Kbuild system: https://docs.kernel.org/kbuild/kbuild.html
