# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

import time
from queue import Queue, Empty
from threading import Semaphore
from concurrent.futures import Future

from .exceptions import TimedOut


class WorkItem:
    def __init__(self, future: Future, fn: callable, args=(), kwargs={}):
        self.future = future
        self.fn = fn
        self.args = args
        self.kwargs = kwargs

    def run(self):
        try:
            result = self.fn(*self.args, **self.kwargs)
        except Exception as e:
            self.future.set_exception(e)
        else:
            self.future.set_result(result)


class ClientExecutor:
    def __init__(self, client):
        self.client = client
        self.queue = Queue()
        self.sem = Semaphore(0)

    def submit(self, fn, *args, **kwargs):
        f = Future()
        w = WorkItem(f, fn, args, kwargs)

        self.queue.put(w)
        return f

    def notify(self):
        self.sem.release()

    def wait(self):
        self.sem.acquire()

    def _process_event(self):
        try:
            self.client.backend.process_event(0)
        except TimedOut:
            # No event queued, wait and return
            # TODO: handle minimum delay in an async way, save the current time
            # and sleep only if elapsed time between two iterations is below a
            # threshold.
            time.sleep(0.001)
            return True
        return False

    def run(self):
        try:
            w = self.queue.get_nowait()
        except Empty:
            return self._process_event()
        else:
            w.run()
        return True
