#!/bin/sh

# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -e

prefix=${1-$PWD}
mkdir -p "$prefix"

build=$PWD/flatcc/build
trap "rm -rf $build" EXIT INT TERM HUP

rm -rf flatcc/build
mkdir flatcc/build
cd flatcc/build

# TODO:
# -DCMAKE_BUILD_TYPE=$(LIB_BUILD) \

cmake \
    -DCMAKE_INSTALL_PREFIX="$prefix" \
    -DCMAKE_C_COMPILER="${CC:-cc}" \
    -DCMAKE_C_FLAGS="${CFLAGS} -DFLATCC_DEBUG_VERIFY=0" \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DFLATCC_COVERAGE=0 \
    -DFLATCC_TEST=0 \
    -DFLATCC_INSTALL=ON \
    -DFLATCC_DEBUG_CLANG_SANITIZE=OFF \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    ..

trap "" EXIT INT TERM HUP
