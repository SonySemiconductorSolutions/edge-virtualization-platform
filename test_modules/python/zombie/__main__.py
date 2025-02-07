#!/bin/env python3

# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

import sys
from time import sleep

from evp.app.client import Client
from evp.app.exceptions import ShouldExit

MODULE_NAME = "ZOMBIE"


def log(*args, **kwargs):
    print(f"{MODULE_NAME}:", *args, file=sys.stderr, **kwargs)


def main():
    log("started!")

    client = Client()

    try:
        while True:
            log("main loop")
            client.run(1000)

    except (KeyboardInterrupt, ShouldExit):
        log("Received SIGINT or ShouldExit. But ignoring for 2 min :evil:")
        sleep(120)


if __name__ == "__main__":
    main()
