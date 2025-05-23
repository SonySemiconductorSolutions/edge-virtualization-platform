.. SPDX-FileCopyrightText: 2023-2025 Sony Semiconductor Solutions Corporation
..
.. SPDX-License-Identifier: Apache-2.0

.. _run-tests:

``tests/Makefile``
##################

This Makefile is in charge of building and executing all the test cases.
It has a dependency on the :ref:`test_modules` Makefile.
All the test modules have to be built before this Makefile runs.
This is ensured by the :ref:`top_level`:

.. code:: Makefile

	test: libs test_modules

The tests use the `Cmocka`_ test framework,
and it is expected to be installed in the system.
Also,
some of the tests require the `Hitch`_ TLS proxy.
It is possible to install them in a debian-alike system using:

.. code:: shell

	apt-get install libcmocka-dev hitch

The Makefile contains the following targets:

	* ``build``: to build all the test cases without executing them.
	* ``test``: to build and executes all the test cases.
	  It is the default target.

The ``test`` target produces a listing after executing all the tests
with a summary of
how many tests where executed,
how many tests passed, and
how many tests failed.
It also prints the list of failed tests.

The tests are executed using the script ``run-tests.sh``
which takes the following options:

	* ``-p platform``: Selects the platform for the tests.
	  Valid values are ``EVP1`` (also named ``EVP1-TB``) or ``TB``.
	  By default it uses ``EVP1-TB``.
	* ``-t timeout``: Timeout used to declare that a test has failed.
	  The default is 60 seconds.
	* ``-d logdir``: Directory where logs are stored.
	  The default is ``logs``.
	* ``-e executor``: It uses the program `executor` to
	  run the tests.
	  This option can be used, for example, with ``-e valgrind``
	  to run all the tests with ``valgrind``.
	  By default it does not use any executor.
	* ``-c``: Enable colouring the test listing using terminal escape sequences.
	* ``-s``: Execute the tests serially.
	  By default ``run-tests.sh`` tries to execute as many tests in parallel as it can.
	  This option can be very helpful when debugging problems.

The behaviour of ``run-tests.sh`` can be modified from the make invocation
using the macro ``RUNFLAGS``.
For example,

.. code:: shell

	make RUNFLAGS='-t 30 -c'

will run the tests with a timeout of 30 seconds and
with output colouring enabled.
It may be more comfortable to set these options in the :ref:`personal_configuration`.

The Makefile allows (but does not encourage) fine control of the options.
Selecting the set of tests can be done using the following Makefile targets:

	* ``run-ut``: Run only the unit tests.
	* ``run-st``: Run only the system tests (also knonwn as integration tests).
	* ``run-ut-evp1-tb``: Run only the unit tests for ``EVP1-TB``.
	* ``run-ut-evp2-tb``: Run only the unit tests for ``EVP2-TB``.
	* ``run-ut-nh``: Run only the unit tests nohub
	  (tests that are independent of the hub configuration).
	* ``run-st-evp1-tb``: Run only the system tests for ``EVP1-TB``.
	* ``run-st-evp2-tb``: Run only the system tests for ``EVP2-TB``.
	* ``run-st-nh``: Run only the system tests nohub
	  (tests that are independent of the hub configuration).

These targets do not print the summary information printed by the ``test`` target.
In case it is desirable to run only one test,
the best option is usually to use the ``run-tests.sh`` script directly,
for example:

.. code:: shell

	./run-tests.sh -c -d logs/EVP2-TB -p TB src/systest/test_deployment.elf

will run the test ``src/systest/test_deployment.elf``
with a ``EVP2-TB`` configuration,
with colouring enabled and placing the logs in
``logs/EVP2-TB/src/systest/test_deployment.elf.log``.

.. warning::

	There is a known bug in GNU binutils that
	causes the build to fail
	when debug options are used.
	This problem was already `reported`_ to the binutils community
	and it was fixed,
	but the fix is not propagated to all supported build environments yet.
	As a workaround,
	using the `LLVM linker`_ avoids the problem.
	It is possible to select the linker
	by passing ``LDFLAGS='-fuse-ld=lld -g'`` in the ``make`` command.

--------------

.. _Cmocka: https://cmocka.org
.. _Hitch: https://hitch-tls.org
.. _reported: https://mail.gnu.org/archive/html/bug-binutils/2024-05/msg00020.html
.. _LLVM linker: https://lld.llvm.org
