.. SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
..
.. SPDX-License-Identifier: Apache-2.0

Release Process
###############

This project does frequent releases
that users can download and work with.
The releases are available from
the `EVP repository`_.
Each commit in the ``main`` branch is eligible for a release,
and thus every commit is tested with the complete set of tests.
There is no fixed release cadence,
and releases are made based on internal requirements.

.. note::

	The documentation in this section is meant for project administrators only.

In order to create a new release,
firstly it is necessary to bump the version
of the different relevant artifacts:

- ``scripts/rules.mk`` (agent)
- ``version.mk`` (agent deprecated)
- ``src/python-evp-app-sdk/setup.py`` (Python App SDK)

When creating and publishing a GitHub release UI,
targetting the ``main`` branch.
The tag ``releases/v<version>``
with the same value from ``scripts/rules.mk`` must be created.
The field version is the value defined in ``rules.mk``
where ``version`` must following `semantic versioning`_.

The release process is thoroughly documented by `GitHub`_.

The CI/CD shall the generate ready-to-use artifacts,
such as Debian packages and tarballs, automatically.

.. _EVP repository: https://github.com/SonySemiconductorSolutions/edge-virtualization-platform/releases
.. _semantic versioning: https://semver.org/
.. _GitHub: https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository#creating-a-release
