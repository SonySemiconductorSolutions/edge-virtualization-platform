# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

"""
EVP Client
"""


class ConfigHandlerBase:
    """
    Configuration handler abstract class
    """

    def __init__(self, client: "Client"):  # noqa: F821
        """
        Create a configuration handler

        Args:
            client (Client): The client
        """
        self.client = client
        client.backend.set_configuration_handler(self)

    def __call__(self, topic: str, config: bytearray):
        self.handle(topic, config)

    def handle(self, topic: str, config: bytearray):
        """
        Implement the processing of configuration updates.
        """
        raise NotImplementedError()
