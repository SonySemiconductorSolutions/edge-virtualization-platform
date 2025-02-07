# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

# Configuration file for the Sphinx documentation builder.

# -- Project information

import re

project = "EVP Agent"
copyright = (
    "2025, Sony Semiconductor Solutions Corporation. "
    + "Sony Semiconductor Solutions Confidential"
)
author = "Sony Semiconductor Solutions Corporation"
version = "unknown-dev"
version_re = re.compile(r"^VERSION\s*=\s*(.*)\s*$")
version_file = "../scripts/rules.mk"

try:
    f = open(version_file, "r")
    version = next(filter(None, map(version_re.match, f))).group(1)
except FileNotFoundError:
    print(f"WARNING: {version_file} not found")
except StopIteration:
    print("WARNING: Could not identify version")

print(f"INFO: Version: {version}")
# -- General configuration

extensions = [
    "myst_parser",
    "sphinx.ext.duration",
    "sphinx.ext.doctest",
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.intersphinx",
]

intersphinx_mapping = {
    "python": ("https://docs.python.org/3/", None),
    "sphinx": ("https://www.sphinx-doc.org/en/master/", None),
}
intersphinx_disabled_domains = ["std"]

templates_path = ["_templates"]

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = [
    ".venv",
    "interfaces/embedding/*.rst",
    "README.md",
]

# -- Options for HTML output
try:
    import sphinx_rtd_theme

    html_theme = "sphinx_rtd_theme"
    html_theme_path = [sphinx_rtd_theme.get_html_theme_path()]
except ImportError:
    html_theme = "classic"

# html_favicon = "favicon.ico"

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ["_static"]

# -- Options for EPUB output
epub_show_urls = "footnote"
