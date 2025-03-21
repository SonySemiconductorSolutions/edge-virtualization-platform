#!/usr/bin/awk

# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

# formatter or checker (run as checker-python.sh) for python files
#
# Input variables:
#   EXCLUDE_NAMES: List of csv of exluce files/directory names
#
# Expected usage:
#   To format files > EXCLUDE_NAMES="local_test" ./formatter-python.sh
#   To check files  > EXCLUDE_NAMES="local_test" ./checker-python.sh

{
    match($0, /\[([0-9]+\.[0-9]+)\|[0-9A-F]+\|.*\]/, ts)
    if (match($0, /BLOB action (GET|PUT) STARTING/, blob)) {
        match($0, /(type [0-9]+.*)/, m)
        action = blob[1]
        desc = m[1]
        start_times[FILENAME, action, desc] = ts[1]
        if (file != FILENAME) {
            printf "\n## %s\n\n", FILENAME
        }
        file = FILENAME
    }
    if (match($0, /BLOB action (GET|PUT) ENDING/, blob)) {
        match($0, /(type [0-9]+.*)( \(RESULT is [0-9]+, error [0-9]+, http_status [0-9]+\))/, m)
        action = blob[1]
        desc = m[1]
        if ((FILENAME, action, desc) in start_times) {
            end = ts[1]
            diff = end - start_times[FILENAME, action, desc]
            if (diff > 1.0) b = "*";
            else b = ""
            printf "* %s%s - %s : %.9f s%s\n", b, action, desc, diff, b
            delete start_times[FILENAME, action, desc]
        }
    }
}
