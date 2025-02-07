#!/bin/sh

# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -e

prefix="${1-$PWD}"
mkdir -p "$prefix"

build=$PWD/nng/build
trap "rm -rf $build" EXIT INT TERM HUP

rm -rf nng/build
mkdir nng/build
cd nng/build

# TODO:
# -DCMAKE_BUILD_TYPE=$(LIB_BUILD) \

cmake \
    -DCMAKE_INSTALL_PREFIX="$prefix" \
    -DCMAKE_C_COMPILER="${CC:-cc}" \
    -DCMAKE_C_FLAGS="${CFLAGS}" \
    -DCMAKE_INSTALL_LIBDIR=lib \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DNNG_TESTS=OFF \
    ..

trap "" EXIT INT TERM HUP
