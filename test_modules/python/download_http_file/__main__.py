#!/bin/env python3

# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

from enum import Enum
import sys

from evp.app.client import Client
from evp.app.blob import (
    BlobOperationGet,
    BlobFileWriter,
    BlobReason,
    BlobResult,
)
from evp.app.configuration import ConfigHandlerBase
from evp.app.state import State


class Step(Enum):
    # Wait TOPIC_LOCAL_FILE configuration
    WAIT_CONFIG = 0

    # Wait TOPIC_DOWNLOAD configuration. start downloading the given url
    DOWNLOAD = 1

    # Wait for the download completion
    DOWNLOAD_WAIT = 2

    END_TEST = 3

    END_TEST_FAIL = 999
    END_TEST_OK = 1000


def next(step, isok=True):
    if (
        step is Step.WAIT_CONFIG
        or step is Step.DOWNLOAD
        or step is Step.DOWNLOAD_WAIT
    ):
        new = Step(step.value + 1)
    elif step is Step.END_TEST:
        new = Step.END_TEST_OK
    elif step is Step.END_TEST_FAIL or step is Step.END_TEST_OK:
        # Wait in this step. Module has to be stopped externally
        pass
    else:
        raise ValueError(f"FATAL: invalid step {step}")

    if not isok:
        new = Step.END_TEST_FAIL

    eprint(f"Step {step} => {new}")
    return new


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


class Config(ConfigHandlerBase):
    TOPIC_INSTANCE_NAME = "instance_name"
    TOPIC_DOWNLOAD = "download"
    TOPIC_LOCAL_FILE = "local_file"

    def __init__(self, client: "Client"):
        self.instance_name = "DOWNLOAD-HTTP-FILE"
        self.filename = None
        self.download = None
        super().__init__(client)

    def handle(self, topic: str, config: bytearray):
        eprint(
            f"{self.instance_name}:",
            f"topic={topic},",
            f"config={config},",
        )

        if topic == self.TOPIC_INSTANCE_NAME:
            self.instance_name = config
        elif topic == self.TOPIC_LOCAL_FILE:
            self.filename = config
        elif topic == self.TOPIC_DOWNLOAD:
            self.download = config
        else:
            eprint(
                f"{self.instance_name}:",
                "Ignoring Configuration with unknown topic,",
                f"topic={topic},",
            )


class Blob(BlobOperationGet):
    def __init__(
        self,
        client: "Client",
        url,
        # None, BlobFile or BlobIo
        stream,
        step,
        headers={},
    ):
        self.step = step
        super().__init__(
            client=client,
            url=url,
            stream=stream,
            headers=headers,
        )

    def complete(self, reason, result):

        if reason == BlobReason.DONE:
            self.step[0] = next(
                self.step[0], result.result == BlobResult.SUCCESS
            )
        elif reason == BlobReason.EXIT:
            eprint(f"{self.instance_name}: BlobReason.EXIT")
            self.step[0] = next(self.step[0], False)
        else:
            raise ValueError(f"Invalid reason {reason}, error={result.error}")


def main():
    abs_filename = None
    step = [Step.WAIT_CONFIG]
    reported_step = -1
    client = Client()
    config = Config(client)
    client.config = config

    while True:
        try:
            client.run(1000)
        except Exception:
            eprint(f"{config.instance_name}: exiting the main loop")
            return -1

        if config.filename and step[0] == Step.WAIT_CONFIG:
            workspace = client.workspace_dir()
            abs_filename = workspace + "/" + config.filename
            eprint(
                f"{config.instance_name}: ",
                f"The blob will be downloaded to: {abs_filename}",
            )
            step[0] = next(step[0])

        if config.download and step[0] == Step.DOWNLOAD:
            eprint(f"{config.instance_name}: Scheduling a download")

            blob = Blob(
                client=client,
                url=config.download,
                stream=BlobFileWriter(client, abs_filename),
                step=step,
            )

            blob.start()
            config.download = None
            step[0] = next(step[0])

        if step[0] == Step.END_TEST:
            eprint(f"{config.instance_name}: SUCCESS")
            step[0] = next(step[0])

        if reported_step != step[0]:
            print(f"Sending state {step[0]}")
            state = State(client)
            state.send("status", f"g_step = {step[0].value}")
            reported_step = step[0]


if __name__ == "__main__":
    sys.exit(main())
