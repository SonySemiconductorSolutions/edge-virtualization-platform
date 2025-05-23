#!/bin/sh

# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -e

prefix=${1-$PWD}
mkdir -p "$prefix"

build=$PWD/libweb/build
trap "rm -rf $build" EXIT INT TERM HUP

rm -rf libweb/build
mkdir libweb/build
cd libweb/build

# TODO:
# -DCMAKE_BUILD_TYPE=$(LIB_BUILD) \

cmake \
    -DCMAKE_INSTALL_PREFIX="$prefix" \
    -DCMAKE_C_COMPILER="${CC:-cc}" \
    -DCMAKE_CXX_COMPILER="${CXX:-c++}" \
    -DCMAKE_C_FLAGS="${CFLAGS}" \
    ..

trap "" EXIT INT TERM HUP
