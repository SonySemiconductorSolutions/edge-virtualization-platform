#!/bin/sh

# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -e

logdir=$(dirname $0)/../test/logs

printf "# HTTP upload performance tests\n"

for dir in EVP1-TB EVP2-TB; do
    printf "## $dir\n"
    for test in \
        test_wasm_mod_upload_http_file \
        test_wasm_mod_failed_connect; do
        f=$logdir/$dir/src/systest/$test.elf.log
        printf "### $test\n"

        while read r; do
            url=$(printf "$r" | awk '{print $1}')
            t=$(printf "$r" | awk '{print $2}')
            printf -- "- %s: %s s\n" "$url" "$t"
        done <<-EOF
            $(grep -oe '<ci/blob/upload/time>.*' $f | awk '{print $2 " " $3}')
EOF
    done
done
