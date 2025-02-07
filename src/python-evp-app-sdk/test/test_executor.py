# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0
import pytest
from unittest.mock import MagicMock

from evp.app.executor import ClientExecutor


@pytest.fixture
def executor(client):
    return ClientExecutor(client)


def test_executor_process_backend_event(executor):
    assert executor.run() is False
    executor.client.backend.process_event.assert_called_once()


def test_executor_process_differed_event(executor):
    call = MagicMock(spec=callable, return_value="called")
    f = executor.submit(call, "test", test="value")
    assert executor.run() is True
    call.assert_called_once_with("test", test="value")
    res = f.result()
    assert res == "called"
    executor.client.backend.process_event.assert_not_called()


def test_executor_process_differed_event_except(executor):
    call = MagicMock(spec=callable, side_effect=Exception("expected fail"))
    f = executor.submit(call, "test", test="value")
    assert executor.run() is True
    call.assert_called_once_with("test", test="value")
    with pytest.raises(Exception, match="expected fail"):
        f.result()
    executor.client.backend.process_event.assert_not_called()
