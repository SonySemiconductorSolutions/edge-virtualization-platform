# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

"""
EVP Client
"""


class Telemetry:
    def __init__(self, client: "Client"):  # noqa: F821
        self.client = client

    def complete(self, reason: int):
        """
        Implement the processing of telemetry send completion.
        """

    def send(self, telemetries: list[(str, str)]):
        self.client.backend.send_telemetry(telemetries, self.complete)
