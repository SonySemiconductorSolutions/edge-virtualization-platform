# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
from unittest.mock import MagicMock
import pytest

from evp.app.blob import (
    BlobFileReader,
    BlobFileWriter,
    BlobMemoryReader,
    BlobMemoryWriter,
    BlobOperationGet,
    BlobOperationPut,
    BlobReason,
    BlobResult,
)


@pytest.fixture
def upload_file(tmp_path) -> Path:
    file = tmp_path / "upload-file.txt"
    with file.open("w+") as f:
        f.write("uploaded content")
    return file


@pytest.fixture
def download_file(tmp_path) -> Path:
    file = tmp_path / "download-file.txt"
    return file


def setup_upload(httpserver, content, endpoint="/upload"):
    httpserver.expect_request(
        endpoint, method="PUT", data=content
    ).respond_with_data("")
    return httpserver.url_for(endpoint)


def setup_download(httpserver, content, endpoint="/download"):
    httpserver.expect_request(endpoint, method="GET").respond_with_data(
        content, status=200
    )
    return httpserver.url_for(endpoint)


def run_operation(cls, client, url, stream):
    op = cls(client, url, stream)
    op.complete = MagicMock()
    op.start()
    while not op.complete.called:
        client.run(100)
    return op


def assert_complete(
    op,
    reason=BlobReason.DONE,
    result=BlobResult.SUCCESS,
    http_status=200,
    error=0,
):
    reason, res = op.complete.call_args[0]
    assert reason == BlobReason.DONE
    assert res.result == BlobResult.SUCCESS
    assert res.http_status == 200
    assert res.error == 0


@pytest.mark.timeout(5)
def test_blob_put_file(client, upload_file, httpserver):
    content = upload_file.read_bytes()
    url = setup_upload(httpserver, content)

    stream = BlobFileReader(client, upload_file)
    op = run_operation(BlobOperationPut, client, url, stream)

    httpserver.check()
    assert_complete(op)


@pytest.mark.timeout(5)
def test_blob_put_memory(client, httpserver):
    content = b"uploaded content"

    url = setup_upload(httpserver, content)

    stream = BlobMemoryReader(client, len(content))
    stream.handle = MagicMock(return_value=content)
    op = run_operation(BlobOperationPut, client, url, stream)

    assert_complete(op)
    httpserver.check()


@pytest.mark.timeout(5)
def test_blob_get_file(client, download_file, httpserver):
    content = b"downloaded content to file"

    url = setup_download(httpserver, content)

    stream = BlobFileWriter(client, download_file)
    op = run_operation(BlobOperationGet, client, url, stream)

    httpserver.check()
    assert_complete(op)
    with download_file.open("rb") as f:
        assert content == f.read()


@pytest.mark.timeout(5)
def test_blob_get_memory(client, download_file, httpserver):
    content = b"downloaded content to memory"

    url = setup_download(httpserver, content)

    stream = BlobMemoryWriter(client, len(content))
    stream.handle = MagicMock(return_value=len(content))
    op = run_operation(BlobOperationGet, client, url, stream)

    httpserver.check()
    assert_complete(op)
    stream.handle.assert_called_once_with(content)
