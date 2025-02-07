#!/bin/env python3

# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

import sys

from evp.app.client import Client
from evp.app.command import CommandBase, CommandResponseStatus
from evp.app.state import State


MODULE_NAME = "RPC"


def log(*args, **kwargs):
    print(f"{MODULE_NAME}:", *args, file=sys.stderr, **kwargs)


class RpcStateClient(State):
    def complete(self, reason):
        log(f"reason={reason}")


class RpcFsm:
    def __init__(self):
        self.client = Client()
        self.client.commands.register(EchoCommand, args=(self,))
        self.state = RpcStateClient(self.client)
        self.step = 0
        self.calls = 0
        self.requests = 0
        self.responses = 0
        self.states = {
            0: self.state_init,
            1: self.state_ready,
            2: self.state_done,
        }

    def run(self):
        try:
            while self.step is not None:
                log("main loop")
                self.emit("loop")
                self.client.run(1000)
        except Exception as e:
            log(e)
            return -1
        return 0

    def emit(self, event):
        state = self.states.get(self.step, None)
        if not state:
            return
        step = state(event)
        if self.step == step:
            return

        self.step = step
        step = f"g_step = {step}"
        log(
            "Sending State (topic=status,",
            f"value='{step}'",
            f"size={len(step)}",
        )
        self.state.send("status", step)

    def state_init(self, event):
        if event == "request":
            return 1
        return self.step

    def state_ready(self, event):
        step = self.step
        if event == "respond":
            self.requests += 1
        elif event == "done":
            self.responses += 1
            step = 2

        log(
            f"requests={self.requests},",
            f"responses={self.responses}",
        )
        return step

    def state_done(self, event):
        return 1000


class EchoCommand(CommandBase):
    def init(self, fsm: RpcFsm = None):
        self.fsm = fsm

    def handle(self, params):
        log(
            f"Received RPC request (id={self.id},",
            f"method={self.name}, params={params})",
        )
        if self.name == "echo":
            status = CommandResponseStatus.OK
            self.fsm.emit("request")
            blob = params
            log(
                f"Sending Response (id={self.id},",
                f"response len={len(params)})",
            )
        else:
            status = CommandResponseStatus.METHOD_NOT_FOUND
            blob = None
            log(
                f"Sending Not-Found Response (id={self.id},",
                "response=NULL",
            )

        self.respond(blob, status)
        self.fsm.emit("respond")

    def complete(self, reason):
        log(
            "Command response completed",
            f"with reason {reason} (id={self.id})",
        )
        self.fsm.emit("done")


def main():
    log("started!")

    rpc = RpcFsm()
    return rpc.run()


if __name__ == "__main__":
    sys.exit(main())
