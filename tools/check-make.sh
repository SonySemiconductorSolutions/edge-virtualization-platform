#! /bin/sh

# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

RET=0
RED=$(tput setaf 1)
RESET=$(tput sgr0)

for f in $(git ls-files '*Makefile*' '*.mk'); do
    RESULT=$(grep -n '[[:blank:]]$' $f)

    if [ "$RESULT" != "" ]; then
        echo ${RED}Trailing whitespaces on $f:${RESET} >&2
        echo "$RESULT" >&2
        RET=1
    fi

    if [ "$(tail -c 1 $f)" != "$(printf '\n')" ]; then
        echo ${RED}$f not ending with LF${RESET} >&2
        RET=1
    fi
done

exit $RET
