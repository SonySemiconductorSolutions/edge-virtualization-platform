# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0
import pytest

from evp.app.state import State


@pytest.fixture
def state(client):
    return State(client)


def test_state_send(client, state):
    state.send("state", "Some value")
    client.backend.send_state.assert_called_once_with(
        "state", "Some value", state.complete
    )
