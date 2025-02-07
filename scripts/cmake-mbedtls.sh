#!/bin/sh

# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -e

prefix=${1-$PWD}
mkdir -p "$prefix"

build=$PWD/mbedtls/build
trap "rm -rf $build" EXIT INT TERM HUP

rm -rf mbedtls/build
mkdir mbedtls/build
cd mbedtls/build

# TODO:
# -DCMAKE_BUILD_TYPE=$(LIB_BUILD) \

cmake \
    -DCMAKE_INSTALL_PREFIX="$prefix" \
    -DCMAKE_INSTALL_LIBDIR=lib\
    -DCMAKE_C_COMPILER="${CC:-cc}" \
    -DCMAKE_C_FLAGS="$CFLAGS $MBEDTLS_CFLAGS" \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DENABLE_TESTING=OFF \
    -DENABLE_PROGRAMS=OFF \
    ..

trap "" EXIT INT TERM HUP
