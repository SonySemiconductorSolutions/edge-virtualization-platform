# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

"""
EVP blob
"""

from enum import Enum
from io import BufferedIOBase
from os import environ
from threading import Thread
from urllib.request import urlopen, Request
from urllib.error import HTTPError
from ssl import SSLContext
from pathlib import Path

from .client import Client


class BlobReason(Enum):
    DONE = 0
    EXIT = 1
    DENIED = 2


class BlobResult(Enum):
    SUCCESS = 0
    ERROR = 1
    ERROR_HTTP = 2


class BlobIoBase(BufferedIOBase):
    """
    BlobIOBase provides a ground base for derived Blob IO streams.
    """

    def __init__(self, client: "Client"):
        super().__init__()
        self.client = client
        self._size = None

    @property
    def executor(self):
        return self.client.executor

    @property
    def size(self):
        if self._size is None:
            self._size = self.get_size()
        return self._size

    def get_size(self):
        return None


class BlobFileBase(BlobIoBase):
    """
    BlobFileBase provides a ground base for derived Blob File streams.
    """

    def __init__(self, client: "Client", path: str):
        """
        Initialize a BlobFileBase object

        Args:
            client (Client): the `evp.app.Client` object
            path (str): the path to the file.
        """
        super().__init__(client)
        self.path = Path(path)
        self.pos = 0
        self.file = self.path.open(self.MODE)

    def close(self):
        self.file.close()

    def write(self, buf):
        raise NotImplementedError()

    def read(self, size):
        raise NotImplementedError()


class BlobFileReader(BlobFileBase):
    """
    BlobFileReader provides ability to read from a file as a stream.
    """

    MODE = "rb"

    def get_size(self):
        return self.path.stat().st_size

    def read(self, size):
        if self.pos >= self.size:
            return None

        result = self.file.read(size)
        self.pos += len(result)
        return result


class BlobFileWriter(BlobFileBase):
    """
    BlobFileWriter provides ability to write to file as a stream.
    """

    MODE = "wb"

    def write(self, buf):
        return self.file.write(buf)


class BlobMemoryBase(BlobIoBase):
    """
    BlobMemoryBase provides a ground base for derived BlobMemory streams.
    """

    def __init__(self, client: "Client", size: int = None):
        """
        Initialize a BlobMemoryBase object

        Args:
            client (Client): the `evp.app.Client` object
            size (int, optional): the defined blob size (for reading).
                Defaults to None (writing).
        """
        super().__init__(client)
        self.pos = 0
        self._size = size

    def handle(self, *args, **kwarg):
        """
        Implement handle
        """
        raise NotImplementedError()


class BlobMemoryReader(BlobMemoryBase):
    """
    BlobMemoryReader provides ability to read from memory as a stream.
    """

    def read(self, size: int):
        """
        Reads from the user implemented `handle`

        Args:
            size (int): the byte size to read from

        Returns:
            bytearray: the read data
            None: if all bytes were consumed
        """
        if self.pos >= self.size:
            return None

        f = self.executor.submit(self.handle, size)
        buf = f.result()
        self.pos += len(buf)
        return buf


class BlobMemoryWriter(BlobMemoryBase):
    """
    BlobMemoryWriter provides ability to write to memory as a stream.
    """

    def write(self, buf: bytearray):
        """
        Writes to the user implemented `handle`

        Args:
            buf (bytearray): _description_

        Returns:
            int: size of the written data
        """
        f = self.executor.submit(self.handle, buf)
        return f.result()


class BlobResultHttpExt:
    def __init__(self, result, http_status: int, error: int = 0):
        self.result = result
        self.http_status = http_status
        self.error = error


class BlobOperationBase:
    """
    BlobOperationBase provides ground base for derived http operations
    (GET and PUT).
    """

    METHOD = None

    def __init__(
        self,
        client: "Client",
        url: str,
        stream: BlobIoBase,
        headers={},
    ):
        """
        Initialize BlobOperationBase.

        Args:
            client (Client): the `evp.app.Client` object
            url (str): the remote URL to connect to
            stream (BlobIoBase): the I/O stream to process the operation
                from/to
            headers (dict, optional): a dictionary of http headers.
                Defaults to {}.

        Raises:
            TypeError: If stream is not of `BlobIoBase`
        """
        if not isinstance(stream, BlobIoBase):
            raise TypeError(f"Unexpected stream type: {stream}")

        self.client = client
        self.url = url
        self.headers = headers
        self.stream = stream
        self.thread = Thread(target=self._run)

    @property
    def executor(self):
        return self.client.executor

    def start(self):
        """
        Start the blob thread.
        """
        self.thread.start()

    def request(self):
        """
        Create the request.

        This method may be overloaded in derived clases.

        urllib.request.urlopen will make use of 'Transfer-Encoding: chunked'
        if a regular file is passed as data. Since some HTTP servers
        do not support such encoding, define a file-like object that simply
        prints the Content-Length and the whole body into the request body
        i.e., without chunks.
        """
        return Request(
            url=self.url,
            headers=self.headers,
            method=self.METHOD,
        )

    def _run(self):
        try:
            sslcontext = None
            tls_ca = environ.get("EVP_HTTPS_CA_CERT")

            if tls_ca:
                sslcontext = SSLContext()
                sslcontext.load_verify_locations(tls_ca)

            with urlopen(self.request(), context=sslcontext) as response:
                result = BlobResultHttpExt(
                    BlobResult.SUCCESS, response.status, 0
                )
                self.respond(response)
                self._complete(BlobReason.DONE, result)
        except HTTPError as e:
            result = BlobResultHttpExt(BlobResult.ERROR_HTTP, e.code, 0)
            self._complete(BlobReason.DENIED, result)
        except Exception:
            result = BlobResultHttpExt(BlobResult.ERROR, 0, 0)
            self._complete(BlobReason.DENIED, result)
            raise
        finally:
            self.stream.close()

    def _complete(self, reason, result):
        self.executor.submit(self.complete, reason, result)

    def complete(self, reason, result):
        """
        Implement completion
        """

    def respond(self, response):
        """
        Implement respond
        """


class BlobOperationGet(BlobOperationBase):
    """
    Provides GET blob operation.
    """

    METHOD = "GET"

    def respond(self, response):
        while True:
            # Arbitrary value
            buf = response.read(1024)
            if not buf:
                break

            self.stream.write(buf)


class BlobOperationPut(BlobOperationBase):
    """
    Provides PUT blob operation.
    """

    METHOD = "PUT"

    def request(self):
        return Request(
            url=self.url,
            data=self.stream,
            headers=self.headers | {"Content-Length": self.stream.size},
            method=self.METHOD,
        )
