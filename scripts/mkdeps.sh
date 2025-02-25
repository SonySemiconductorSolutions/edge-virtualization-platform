#!/bin/sh

# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -e

config=${1:-./.config}

. $config

# In the NuttX build, parson can be built as an internal library
# embedded in libapps.a, so we avoid compiling and installing parson.
if test "$CONFIG_EXTERNAL_PARSON" != y
then
    libs="$libs -lparson"
    dirs="$dirs libparson"
    files="$files \$(LIBDIR)/libparson.a"
fi

# In the NuttX build, MbedTLS is not built by us but is included and built by
# nuttx build system. In those cases, CONFIG_CRYPTO_MBEDTLS or
# CONFIG_EXTERNALS_MBEDTLS are defined and we can skip our build
if test "$CONFIG_CRYPTO_MBEDTLS" != y -a "$CONFIG_EXTERNALS_MBEDTLS" != y
then
    libs="$libs -lmbedtls -lmbedcrypto -lmbedx509"
    dirs="$dirs mbedtls"
    files="$files \$(LIBDIR)/libmbedtls.a \$(LIBDIR)/libmbedcrypto.a \$(LIBDIR)/libmbedx509.a"
    git submodule update --init --recursive src/mbedtls
fi

# In the NuttX build, WAMR is not built by us but is included and built by
# nuttx build system. In those cases, CONFIG_INTERPRETERS_WAMR is selected,
# so we skip our build
if test "$CONFIG_EVP_MODULE_IMPL_WASM" = y &&
    test "$CONFIG_INTERPRETERS_WAMR" != y
then
    libs="$libs -lvmlib"
    dirs="$dirs wasm-micro-runtime"
    files="$files \$(LIBDIR)/libvmlib.a"
    git submodule update --init src/wasm-micro-runtime
fi

if test "$CONFIG_EVP_SDK_SOCKET" = y
then
    libs="$libs -lflatccrt"
    dirs="$dirs flatcc sdkenc"
    files="$files \$(LIBDIR)/libflatccrt.a"
    git submodule update --init src/flatcc
fi

cat <<EOF > deps.mk
LIBDIRS=$dirs
DEPLIBS=$libs
FILELIBS=$files
EOF
