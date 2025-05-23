#!/usr/bin/awk -f

# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0
{   
    # Extract timestamp
    match($0, /\[([0-9]+\.[0-9]+)\|/)
    timestamp = substr($0, RSTART+1, RLENGTH-2)
    # Find Blob operation start
    if (match($0, /BLOB action (GET|PUT) STARTING/)) {
        # Extract action GET or PUT
        action = substr($0, RSTART+12, 3)
        # Extract Blob description
        match($0, /BLOB action (GET|PUT) STARTING for (.*)/)
        desc = substr($0, RSTART+29, RLENGTH)
        # Create unique key
        key = FILENAME "|" action "|" desc
        # Store timestamp to starts hash map
        starts[key] = timestamp
        if (file != FILENAME) {
            if (length(file) > 0) {
                printf("::endgroup::\n")
            }
            printf("::group::%s\n", FILENAME)
        }
        file = FILENAME
    }
    # Find Blob operation end
    if (match($0, /BLOB action (GET|PUT) ENDING/)) {
        # Extract action GET or PUT
        action = substr($0, RSTART+12, 3)
        # Extract Blob description
        match($0, /BLOB action (GET|PUT) ENDING for (.*) \(RESULT/)
        desc = substr($0, RSTART+27, RLENGTH-35)
        # Create unique key
        key = FILENAME "|" action "|" desc
        # Find start timestamp
        if (key in starts) {
            start = starts[key]
            diff = timestamp - start
            if (diff > 1.0) diff = "\033[31m" diff "\033[0m" ;
            printf("* %s: %s (%s)\n", action, diff, desc)
            delete starts[key]
        } else {
            printf("Warning: No matching '%s' started at %s |\n", key, start)
        }
    }
}

END {
    printf("::endgroup::\n")
    if (length(starts) > 0) {
        printf("\nUnmatched blob ending:\n\n")
    }
    for (key in starts) {
        printf("* '%s' at %s\n", key, starts[key])
    }
}
