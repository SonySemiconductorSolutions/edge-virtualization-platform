# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0
from unittest.mock import MagicMock
import pytest

from evp.app.client import Client
from evp.app.command import CommandHandler
from evp.app.backend import Backend


def backend_patch(mocker, cls=None):
    cls = MagicMock(spec=Backend) if cls is None else cls
    return mocker.patch(
        "evp.app.client.Backend",
        cls,
    )


@pytest.fixture
def backend(mocker):
    backend = backend_patch(mocker)
    return backend


@pytest.fixture
def client(backend):
    yield Client()


@pytest.fixture
def commands(client):
    return CommandHandler(client)
