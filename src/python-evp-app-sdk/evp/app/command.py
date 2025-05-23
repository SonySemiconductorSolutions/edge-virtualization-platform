# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

"""
Command module
"""

from enum import Enum
import re
from typing import Type, Union, Callable

from .backend import Backend


class CommandResponseStatus(Enum):
    OK = 0
    METHOD_NOT_FOUND = 1
    ERROR = 2
    MAX = 3


class CommandBase:
    """
    Command abstract class

    Defines a base class to define commands.
    `CommandBase` requires `handle` and `complete` to be implemented in
    the inherited class.

    The command can then be registered in the client's command manager.

    Example:

        class MyCommand(CommandBase):
            def handle(self, cmd_id, name, params):
                self.respond(cmd_id, "ok", 0)

            def complete(self, reason):
                print("MyCommand completed")

        ...

        client = Client()
        client.commands.register(".*", MyCommand)
    """

    def __init__(
        self,
        handler: "CommandHandler",
        reqid: int,
        name: str,
        params: str,
        *args,
        **kwargs,
    ):
        """
        Create a command handler

        Args:
            handler (CommandHandler): The command handler
            reqid (int): Request id
            name (str): Command method name
            params (str): Parameter as string
        """
        self.handler = handler
        self.id = reqid
        self.name = name
        self.init(*args, **kwargs)
        self.handle(params)

    def init(self, *args, **kwargs):
        """
        Implement user specific init from extra arguments
        """

    def handle(self, params: str, *args, **kwargs):
        """
        Implement command handling

        Args:
            params (str): Command parameters
        """
        raise NotImplementedError(
            "handle needs to be implemented in the derived class"
        )

    def complete(self, reason: int):
        """
        Implement completion

        Args:
            reason (int): Completion reason status
        """
        raise NotImplementedError(
            "complete needs to be implemented in the derived class"
        )

    def respond(self, response: str, status: int):
        """
        Respond to the request.

        This can be called in the `handle` method.

        Args:
            response (str): Response string
            status (int): Status
        """
        self.handler.respond(self.id, response, status, self.complete)


class CommandHandler:
    """
    Command manager class

    Command manager provides registration of commands by regex pattern
    matching.

    Example:

        client = Client()
        client.commands.register(MyCommand)


    """

    def __init__(self, client: "Client"):  # noqa: F821
        self.client = client
        self.commands = []
        self.registered = False

    @property
    def backend(self) -> Backend:
        return self.client.backend

    def __call__(self, cmd_id: int, name: str, params: str):
        for pattern, cmd, args, kwargs in self.commands:
            if not pattern.match(name):
                continue
            cmd(self, cmd_id, name, params, *args, **kwargs)

    def register(
        self,
        cmd: Union[Type[CommandBase], Callable],
        pattern: str = r".*",
        args=(),
        kwargs={},
    ):
        """
        Register a command

        The `cmd` argument must either have a class initializer or callable
        prototype with the minimum arguments `(manager, reqid, name, params)
        see `CommandBase`. The additional `args` and `kwargs` will be expanded
        to the command call.

        Example:

            class CommandContext:
                value = 4

            def my_command(manager, reqid, name, params, context=None):
                print(f"my_command '{name}' called with {context.value}")

            client.commands.register(
                my_command, kwargs={"context":CommandContext},
            )

        Output:

            my_command called with 4

        Args:
            cmd (callable): a callable object or a sub class of CommandBase.
            pattern (str, optional): a regex pattern match to the command name
                to handle the command. Defaults to r".*".
            args (tuple, optional): a tupple of extra arguments to pass to the
                handler call. Defaults to ().
            kwargs (dict, optional): a dict of extra keyword args to pass to
                the handler call. Defaults to {}.

        Raises:
            KeyError: when a command is alreay registered to a specific pattern
        """
        if not self.registered:
            self.backend.set_command_handler(self)
            self.registered = True

        if pattern in (p.pattern for p, *_ in self.commands):
            raise KeyError("Command already registered")
        self.commands.append((re.compile(pattern), cmd, args, kwargs))

    def respond(self, id, response, status, complete):
        self.backend.send_command_response(
            id,
            response,
            status,
            complete,
        )
