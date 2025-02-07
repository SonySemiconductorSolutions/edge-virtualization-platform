# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

"""
EVP Client
"""

from datetime import datetime, timedelta
from .backend import Backend
from .configuration import ConfigHandlerBase
from .command import CommandHandler
from .executor import ClientExecutor


class Client:
    def __init__(
        self,
        commands_cls: type[CommandHandler] = CommandHandler,
    ):
        self._backend = Backend()
        self.commands = commands_cls(self)
        self.executor = ClientExecutor(self)

    @property
    def backend(self):
        return self._backend

    @property
    def config(self):
        return self._config

    @config.setter
    def config(self, handler: ConfigHandlerBase):
        self._config = handler

    def workspace_dir(self):
        return self._backend.get_workspace_directory()

    def run(self, timeout=None):
        """
        Process event queue.

        Args:
            timeout (float, optional): Amount of time in milliseconds that the
                loop will block until continue.
                Defaults to None (block until an event is processed).

        Return:
            True if an event has been processed
            False if return on timeout (no event processed)
        """

        def process_events_timeout():
            if not self.executor.run():
                return False
            elapsed = datetime.now() - start
            return elapsed < timeout

        if timeout is not None:
            start = datetime.now()
            timeout = timedelta(microseconds=1000 * timeout)
            process = process_events_timeout
        else:
            process = self.executor.run

        while process():
            pass
