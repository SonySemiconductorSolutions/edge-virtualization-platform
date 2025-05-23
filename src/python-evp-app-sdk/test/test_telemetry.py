# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0
import pytest

from evp.app.telemetry import Telemetry


@pytest.fixture
def telemetry(client):
    return Telemetry(client)


def test_telemetry_send(client, telemetry):
    telemetry.send([("key" "Some value")])
    client.backend.send_telemetry.assert_called_once_with(
        [("key" "Some value")], telemetry.complete
    )
