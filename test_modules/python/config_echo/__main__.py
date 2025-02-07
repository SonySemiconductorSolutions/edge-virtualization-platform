#!/bin/env python3

# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

import sys

from evp.app.client import Client
from evp.app.state import State
from evp.app.configuration import ConfigHandlerBase

MODULE_NAME = "CONFIG-ECHO"


def log(*args, **kwargs):
    print(f"{MODULE_NAME}:", *args, file=sys.stderr, **kwargs)


class ConfigEchoState(State):
    def complete(self, reason):
        log(f"state sent with reason {reason}")


class ConfigEchoConfigHandler(ConfigHandlerBase):
    def __init__(self, client: Client):
        super().__init__(client)
        self.state = ConfigEchoState(client)

    def handle(self, topic, config):
        log(
            "Received Config",
            f"topic={topic},",
            f"config={config},",
        )

        log("Echoing State")
        self.state.send(
            topic,
            config,
        )


def main():
    log("started!")

    client = Client()
    client.config = ConfigEchoConfigHandler(client)

    while True:
        log("main loop")
        client.run(1000)


if __name__ == "__main__":
    main()
