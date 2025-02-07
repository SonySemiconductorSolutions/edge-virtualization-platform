# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0
from unittest.mock import MagicMock

import pytest

from evp.app.command import CommandBase, CommandHandler


class UnimplementedCmd1(CommandBase):
    pass


class UnimplementedCmd2(CommandBase):
    def handle(self, params):
        self.complete(0)


class Cmd(CommandBase):
    def init(self, context):
        self.context = context

    def handle(self, params):
        self.context.name = self.name
        self.context.params = params
        self.respond("ok", 0)

    def complete(self, reason):
        print("cmd response done")


def test_commands(commands: CommandHandler):
    cmd1 = MagicMock()
    context = MagicMock()
    cmd2 = Cmd
    commands.register(cmd1, "test1")
    commands.register(cmd2, "test2", args=(context,))
    commands(123456789, "test1", "Some string")
    commands(123456790, "test2", '{"some-key":"Some value"}')
    cmd1.assert_called_once_with(commands, 123456789, "test1", "Some string")
    assert context.name == "test2"
    assert context.params == '{"some-key":"Some value"}'
    commands.backend.send_command_response.assert_called_once()


def test_commands_cannot_register_twice(commands: CommandHandler):
    commands.register(MagicMock(), "test")
    with pytest.raises(KeyError):
        commands.register(MagicMock(), "test")


@pytest.mark.parametrize("cmd", (UnimplementedCmd1, UnimplementedCmd2))
def test_commands_unimplemented(commands: CommandHandler, cmd: CommandBase):
    commands.register(cmd)

    with pytest.raises(NotImplementedError):
        commands(1, "test", "Dummy")
