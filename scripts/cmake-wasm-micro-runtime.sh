#!/bin/sh

# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -e

prefix=${1-$PWD}
mkdir -p "$prefix"

build=$PWD/wasm-micro-runtime/build
trap "rm -rf $build" EXIT INT TERM HUP

rm -rf wasm-micro-runtime/build
mkdir wasm-micro-runtime/build
cd wasm-micro-runtime/build

# TODO:
# -DCMAKE_BUILD_TYPE=$(LIB_BUILD)

case "$ARCH" in
x86_64)
    arch=X86_64
    ;;
i386)
    arch=x86_32
    ;;
aarch64)
    arch=AARCH64
    ;;
armel)
    arch=ARM
    ;;
armhf)
    arch=ARMV7_VFP
    ;;
xtensa)
    arch=XTENSA
    ;;
*)
    echo cmake-wasm-micro-runtime: invalid arch $arch >&2
    exit 1
    ;;
esac

cmake \
    -DCMAKE_INSTALL_PREFIX="$prefix" \
    -DCMAKE_C_COMPILER=${CC:-cc} \
    -DCMAKE_CXX_COMPILER=${CXX:-c++} \
    -DCMAKE_C_FLAGS="${CFLAGS}" \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DWAMR_BUILD_TARGET=${arch:-X86_64} \
    -DWAMR_BUILD_SHARED=0 \
    -DWAMR_BUILD_INTERP=1 \
    -DWAMR_BUILD_FAST_INTERP=1 \
    -DWAMR_BUILD_JIT=0 \
    -DWAMR_BUILD_AOT=1 \
    -DWAMR_BUILD_LIBC_WASI=1 \
    -DWAMR_BUILD_LIBC_BUILTIN=0 \
    -DWAMR_BUILD_LIBC_UVWASI=0 \
    -DWAMR_BUILD_MULTI_MODULE=0 \
    -DWAMR_BUILD_MINI_LOADER=0 \
    -DWAMR_BUILD_SHARED_MEMORY=1 \
    -DWAMR_BUILD_THREAD_MGR=0 \
    -DWAMR_BUILD_LIB_WASI_THREADS=1 \
    -DWAMR_BUILD_BULK_MEMORY=1 \
    -DWAMR_DISABLE_WRITE_GS_BASE=1 \
    -DCMAKE_STRIP=0 \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    ..

trap "" EXIT INT TERM HUP
