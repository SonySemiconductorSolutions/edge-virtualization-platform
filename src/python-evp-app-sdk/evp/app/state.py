# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

"""
State module
"""


class State:
    def __init__(self, client: "Client"):  # noqa: F821
        self.client = client

    def complete(self, reason: int):
        """
        Implement the processing of state send completion.
        """

    def send(self, topic: str, blob: bytearray):
        self.client.backend.send_state(
            topic,
            blob,
            self.complete,
        )
