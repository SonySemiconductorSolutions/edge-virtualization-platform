# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

from setuptools import setup, Extension
from setuptools.command.build_py import build_py

library_name = "evp-app"
package_name = "evp.app"
package_path = "evp/app"
version = "1.0.0"
backend_name = "backend"


# Build extensions before python modules,
# or the generated SWIG python files will be missing.
class BuildPy(build_py):
    def run(self):
        self.run_command("build_ext")
        super(build_py, self).run()


backend = Extension(
    name=f"{package_name}._{backend_name}",
    sources=[
        f"{package_path}/{backend_name}.i",
    ],
    library_dirs=[
        "external/lib",
    ],
    libraries=[
        "evp-app-sdk-bundle",
    ],
    swig_opts=[
        "-doxygen",  # Add doxygen docstring,
        "-noproxy",
    ],
    define_macros=[("EVPMODULESDK", None)],
)

setup(
    name=library_name,
    version=version,
    description="Edge Virtural Platform Application SDK for Python",
    long_description=open("README.md").read(),
    author="EVP Device Team",
    license="Apache",
    packages=[package_name],
    cmdclass={"build_py": BuildPy},
    include_package_data=True,
    ext_modules=[backend],
)
