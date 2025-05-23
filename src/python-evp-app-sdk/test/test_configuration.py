# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0
import pytest
from unittest.mock import MagicMock

from evp.app.configuration import ConfigHandlerBase


@pytest.fixture
def conf(client):
    conf = ConfigHandlerBase(client)
    conf.handle = MagicMock()
    return conf


def test_configuration_handler(conf):
    conf("empty", "{}")
    conf.handle.assert_called_once_with("empty", "{}")


def test_configuration_unimplemented(client):
    with pytest.raises(NotImplementedError):
        conf = ConfigHandlerBase(client)
        conf("fails", "dummy")
