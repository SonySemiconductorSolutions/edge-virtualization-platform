#!/bin/env python3

# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

import sys

from evp.app.client import Client
from evp.app.configuration import ConfigHandlerBase
from evp.app.telemetry import Telemetry


MODULE_NAME = "TELEMETRY-ECHO"


def log(*args, **kwargs):
    print(f"{MODULE_NAME}:", *args, file=sys.stderr, **kwargs)


class TelemetryEcho(Telemetry):
    def complete(self, reason):
        log(f"telemetry sent with reason {reason}")


class TelemetryEchoConfigHandler(ConfigHandlerBase):
    def __init__(self, client: Client):
        super().__init__(client)
        self.telemetry = TelemetryEcho(client)

    def handle(self, topic, config):
        log(
            "Received Config",
            f"topic={topic},",
            f"config={config},",
        )

        log("Echoing telemetry")
        self.telemetry.send(
            [
                (topic, config),
            ]
        )


def main():
    log("started!")

    client = Client()
    client.config = TelemetryEchoConfigHandler(client)

    while True:
        log("main loop")
        client.run(1000)


if __name__ == "__main__":
    main()
