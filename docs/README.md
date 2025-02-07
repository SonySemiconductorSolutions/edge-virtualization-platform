<!--
SPDX-FileCopyrightText: 2023-2025 Sony Semiconductor Solutions Corporation

SPDX-License-Identifier: Apache-2.0
-->

# Project Documentation

This repository contains the
Sphinx-based documentation for the
Edge Virtualization Platform (EVP) project.

## Building the documentation

The latest documentation of EVP
can always be found in [Midokura EVP Agent documentation],
built automatically through [Read the Docs]
for every update of any branch.
Additionally, the documentation
can be built locally.

The documentation is located in the `docs` directory,
and it uses the [Sphinx] framework to generate the full
documentation site.

### Prerequisites

In order to build the documentation it is required:

	* Python 3 (3.9 or later), with the `pip` and `venv` packages installed.

It is possible to install them in a Debian-like system using:

```shell
apt-get install python3 python3-pip python3-venv
```

[Sphinx] supports multiple backends to generate output documents,
but it is recommended the html backend render.
The first step for any backend render is
to install the dependencies.
Is is recommended to use a `venv` for it:

```shell
cd docs
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

### Generate html documentation

Once all dependencies installed,
it is possible to build the documentation
using the `Makefile` located
in the `docs` directory:

```shell
cd docs
. venv/bin/activate
make html
```

and the generated html site
will be created in the `build/html/` directory
whose pages can be read with any browser.

## Writing Guidelines (reStructuredText Policies)

The documentation style is based on
[Python Developer’s Guide for documenting]
Please ensure to follow these guidelines.

When writing documentation in reStructuredText (reST),
please adhere to the following enforced policies:

The `conf.py` [Sphinx] project configuration file
allows the use of [Markdown] or [reStructuredText],
although it is recommended the use
of [reStructuredText] whenever possible.

### General Style

- Use clear and concise language.
- Follow Sphinx and reST best practices.
- Ensure proper indentation and spacing for readability.
- Prefer following [Semantic Linefeeds] guidelines.

### Cross-referencing

- **Do not use the `autosectionlabel` extension**
  to prevent conflicts with duplicate section names,
  even with `autosectionlabel_prefix_document = True`.

  The reason is that it could make
  the documentation maintenance fragile.

  Instead, prefer explicit labeling when needed,
  with eventual namespacing to avoid conflict:

  ```rst
  .. _namespace-my_section:

  My Section
  **********

  Referencing with :ref:`namespace-my_section`
  ```

## Contribution Guidelines

1. Follow the reST writing policies
   when adding or modifying documentation.
2. Submit a pull request
   with a clear description of changes.

## License

This documentation is licensed
under the Apache-2.0 License.
See `LICENSE` in repository root for details.

[Sphinx]: https://www.sphinx-doc.org/en/master
[Midokura EVP Agent documentation]: https://midokura-edge-virtualization-platform.readthedocs-hosted.com/en/latest/about/agent_features.html
[Read the Docs]: https://readthedocs.com
[Python Developer’s Guide for documenting]: https://devguide.python.org/documentation/markup/#sections
[Semantic Linefeeds]: https://rhodesmill.org/brandon/2012/one-sentence-per-line
[Markdown]: https://www.markdownguide.org
[reStructuredText]: https://www.sphinx-doc.org/en/master/usage/restructuredtext/basics.html
