.. SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
..
.. SPDX-License-Identifier: Apache-2.0

Testing
#######

The reliability and robustness of the EVP Agent
is ensured following a strict development process
where the tests have a prominent position.

The suite of tests are tested
against the two versions of the protocol between the agent and the hub,
EVP1 and EVP2,
although there are some tests
that are independent of the protocol used
(more information in :ref:`run-tests`).

Types of tests
**************

The test suite is divided in two sets of tests,
unit tests and integration tests (sometimes called system tests).
Both of them rely in the `Cmocka`_ framework,
which allows definition of test suites
and different kinds of assertions.

    * Unit tests: test individual units
      validating the precondition and postconditions
      of them.
      Usually,
      single C files are considered like the unit under test,
      and external dependencies are mocked.
    * Integration tests: instantiate a full agent
      using the :ref:`embedding` API.

To be able to run all the possible tests
the project has to be configured using
the configuration ``unit-test-all-hubs-wasm.config``
(for more information read :ref:`kconfig`).
For more information about
how to build and run these tests
refer to :ref:`run-tests`.

In both cases,
when a function or object is mocked
it is done at the linker level using wrapping.
For every symbol ``sym`` wrapped
the linker resolves all the undefined references to ``wrap_sym``.
In case of it being needed,
the original symbol ``sym`` can be accessed using ``__real_sym``.
The list of symbols
that require wrapping is automatically detected by the :ref:`run-tests`,
based in the ``__wrap_*`` symbols found at the link stage.

In addition to these tests
there are some other tests that
are integrated in the more general AITRIOS testing
and that test the agent in combination with the other AITRIOS components.
For that reason they are not covered here.

Integration tests
=================

These tests validate
the integration of the different components conforming the agent.
This agent has mocked interfaces for the communication with the hub,
enabling the tests to inject and inspect this communication.
No TLS or network communication is performed for the MQTT connection.
Beware that `Cmocka`_ uses thread local storage for its data,
as its intended use is unit testing,
and calling them from a thread other than
the one driving the test can produce unexpected results.
These tests usually consist of a deployment
and calls to the function ``agent_poll``
that polls the mocked communication between the agent and the hub
running some validation function that
expects some reply from the agent to the hub.
There are several of these validation functions,
for example ``verify_contains`` that validates
that a message contains a specific piece of text
or the more general ``verify_json``
that uses a :ref:`testing/json_validation_language`.

.. _testing/json_validation_language:

JSON validation language
------------------------

The communication between the agent and the hub is done using JSON payloads,
and the tests need a way to validate these JSON messages.
As the order of the fields can be different,
literal text matching is not an option,
and a schema validator would require a specific schema for every validation.
To resolve this problem a validation language was defined
inspired in printf formatting strings.
The format string would be composed of a set of clauses separated by commas,
for example:

.. code:: C

    verify_json(txt,
                "state/instance1/status=%s,"
                "state/instance2/status=%s",
                "starting", "working");

Every clause is composed of two parts,
the first part before the ``=`` character
which defines a dot expression that
evaluates to some JSON value.
and a pattern defined after the ``=`` character.
For instance,
the first clause of the last example
used ``state/instance1/status`` as dot expression
and ``%s`` as pattern.
The dot expressions are usually relative to the top-level object,
but this can be modified
with the suboject pattern described below in this section.
The order of the clauses is not important
as they only reflect paths to the JSON values to validate.
For instance,
a call like:

.. code:: C

    verify_json(txt,
                "object1.key2=%s,object2.key3=%s",
                "value2", "value3");

would validate a JSON object like:

.. code:: json

    {
        "object1": {"key1": "value1", "key2": "value2"},
        "object2": {"key3": "value3", "key4": "value4"}
    }

or

.. code:: json

    {
        "object2": {"key3": "value3", "key4": "value4"},
        "object1": {"key1": "value1", "key2": "value2"}
    }

The pattern tries to follow the printf conventions,
where every pattern uses
one matching parameter of a variable length argument list.

    * ``%s``: The matching parameter must be a ``char *`` and
      the dot expression must point to a string JSON value.
      It validates that
      the JSON value is equal to the matching parameter.
    * ``%t``: The matching parameter must be a ``int``
      and it must be one of the constants defined
      for the type ``enum json_value_type`` in `Parson`_,
      and it validates
      if the dot expression points to a value
      of the type defined by the matching parameter.
    * ``%f``: The matching parameter must be a ``double`` and
      the dot expression must point to a number JSON value.
      It validates that
      the JSON value is equal to the matching parameter.
    * ``%b``: The matching parameter must be a ``int`` and
      the dot expression must point to a boolean JSON value.
      It validates that
      the JSON value is equal to the matching parameter.
    * ``$#``: The matching parameter must be a ``int`` and
      the dot expression must point to
      a JSON object or JSON array.
      It validates that
      the number of children of the JSON value is equal
      to the matching parameter
      (the syntax for this pattern is inspired in
      the equivalent syntax of languages like
      `Bash`_,
      `Perl`_,
      `Tcsh`_ or
      `Rc`_).

Special patterns
^^^^^^^^^^^^^^^^

Suboject pattern
""""""""""""""""

.. code:: C

    verify_json(txt,
                "suboject={"
                "   key1=%s,"
                "   key2=%s}",
                "value3", "value4");

When a ``{`` follows a ``=`` then
it modifies the current object,
and following dot expressions are relative
to the dot expression before the ``=``,
until a closing ``}`` is found.
The previous example would match something like:

.. code:: json

    {
        "key1": "value1",
        "key2": "value2",
        "suboject": {
            "key1": "value3",
            "key2": "value4"
        }
    }

Subobject patterns can be nested.


Suboject pattern
""""""""""""""""

.. code:: C

    verify_json(txt,
                "object=#{"
                "  key1=%s,"
                "  key2=%s}",
                "value3", "value4");

This pattern is similar to the suboject pattern,
but in this case
the preceding dot expression must point to a JSON string value
that contains a literal JSON object.
The literal is parsed and
set as current object.
The previous example would match something like:

.. code:: json

    {
        "key1": "value1",
        "key2": "value2",
        "subobject": "{\"key1\": \"value3\",\"key2\": \"value4\"}"
    }

Static analysis
***************

When the code is compiled in the CI the program `Bear`_ is used
and it generates a compilation database that
can be consumed by static analysis tools to
recreate the compilation options used.
The compilation database is used to run `Cppcheck`_
enabling the ``information``, ``portability``, and ``warning`` checks.
For more information about them
please consult the `Cppcheck`_ documentation,
and for more information about
how `Cppcheck`_ is executed by the build system
please consult :ref:`toolchain`.

Dynamic analysis
****************

When the tests are executed in the CI environments
they are compiled using the
`Clang Undefined behavior sanitizer`_ and `Clang Address sanitizer`_.
and later ran with the environment variables

.. code: shell

    ASAN_OPTIONS="detect_leaks=1:detect_stack_use_after_return=1"
    UBSAN_OPTIONS="print_stacktrace=1"

These options help to detect many undefined behavior situations
that can create problems in the execution
and reduce the portability of the code.
The full list of checks enabled is:

.. code:: shell

    fsanitize=address
    fsanitize-address-use-after-scope
    fsanitize=alignment
    fsanitize=bool
    fsanitize=bounds
    fsanitize=enum
    fsanitize=integer
    fsanitize=implicit-integer-truncation
    fsanitize=implicit-integer-arithmetic-value-change
    fsanitize=implicit-conversion
    fsanitize=object-size
    fsanitize=pointer-overflow
    fsanitize=returns-nonnull-attribute
    fsanitize=shift
    fsanitize=undefined
    fsanitize=unreachable
    fsanitize=unsigned-integer-overflow
    fsanitize=vla-bound

More information about every specific option can be found in the
`Clang Undefined behavior sanitizer` and `Clang Address sanitizer` documentation.
More information about how this is done
can be found in :ref:`toolchain`.

Code coverage
*************

The tests are designed to cover
as much code as possible
and the coverage level is measured using `llvm-cov`.
When the tests are compiled for the CI execution
they are instrumented to generate output `llvm-cov` coverage information
that later is processed by some scripts and
reported to the CI
to ensure that the minimun coverage level is matched.
More information about how this is done
can be found in :ref:`toolchain`.

--------------

.. _Cmocka: https://cmocka.org
.. _Parson: https://github.com/kgabis/parson/blob/ba29f4eda9ea7703a9f6a9cf2b0532a2605723c3/parson.h#L50
.. _Bash: https://www.gnu.org/savannah-checkouts/gnu/bash/manual/bash.html
.. _Perl: https://perldoc.perl.org/perldata
.. _Tcsh: https://www.tcsh.org
.. _Rc: https://9fans.github.io/plan9port/man/man1/rc.html
.. _Clang Undefined behavior sanitizer: https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html
.. _Clang Address sanitizer: https://github.com/google/sanitizers/wiki/AddressSanitizer
.. _Bear: https://github.com/rizsotto/Bear
.. _Cppcheck: https://cppcheck.sourceforge.io/
.. _llvm-cov: https://llvm.org/docs/CommandGuide/llvm-cov.html
