# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0
from unittest.mock import MagicMock

import pytest

from evp.app.exceptions import TimedOut


@pytest.mark.parametrize("timeout", (None, 0, 100))
def test_client_process_one_event(client, timeout):
    client.run(timeout)
    client.backend.process_event.assert_called_once()


@pytest.mark.parametrize("timeout", (0, 100))
def test_client_process_timeout(client, timeout):
    client.backend.process_event = MagicMock(side_effect=TimedOut())
    client.run(timeout)
    client.backend.process_event.assert_called()


def test_client_workspace_dir(client):
    client.backend.get_workspace_directory = MagicMock(
        return_value="workspace"
    )
    assert client.workspace_dir() == "workspace"
