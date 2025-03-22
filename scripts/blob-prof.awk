#!/usr/bin/awk

# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0
{   
    match($0, /\[([0-9]+\.[0-9]+)\|/)
    timestamp = substr($0, RSTART+1, RLENGTH-2)
    if (match($0, /BLOB action (GET|PUT) STARTING/)) {
        action = substr($0, RSTART+12, 3)
        match($0, /BLOB action (GET|PUT) STARTING for (.*)/)
        desc = substr($0, RSTART+29, RLENGTH)
        key = FILENAME "|" action "|" desc
        starts[key] = timestamp
        if (file != FILENAME) {
            printf "\n## %s\n\n", FILENAME
            printf "| Operation | Time | Description |\n"
            printf "| --------- | ---- | ----------- |\n"
        }
        file = FILENAME
    }
    if (match($0, /BLOB action (GET|PUT) ENDING/)) {
        action = substr($0, RSTART+12, 3)
        match($0, /BLOB action (GET|PUT) ENDING for (.*) \(RESULT/)
        desc = substr($0, RSTART+27, RLENGTH-35)
        key = FILENAME "|" action "|" desc
        if (key in starts) {
            start = starts[key]
            diff = timestamp - start
            if (diff > 1.0) b = "**";
            else b = ""
            printf "| %s | %s%.9f s%s | %s |\n", action, b, diff, b, desc
            delete starts[key]
        } else {
            printf "| %s | - | Warning: No matching %s started at %s |\n", action, desc, start
        }
    }
}
