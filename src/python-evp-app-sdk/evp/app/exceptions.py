# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

"""
Exceptions module
"""

from . import _backend as _be

exception_registry = {}


def register(code):
    def wrap(cls):
        exception_registry[code] = cls
        return cls

    return wrap


def get_exception(code):
    return exception_registry.get(code, ErrorBase)


class ErrorBase(Exception):
    """
    Base error class.
    """


@register(_be.EVP_SHOULDEXIT)
class ShouldExit(ErrorBase):
    """
    The module instance is requested to stop.
    It should exit performing cleanup as soon as possible.
    """


@register(_be.EVP_TIMEDOUT)
class TimedOut(ErrorBase):
    """
    The specified period has elapsed without any events.
    """


@register(_be.EVP_ERROR)
class UnknownError(ErrorBase):
    """
    An error ocurred.
    """


@register(_be.EVP_INVAL)
class Invalid(ErrorBase):
    """
    Invalid parameter.
    """


@register(_be.EVP_NOMEM)
class NoMem(ErrorBase):
    """
    Memory allocation failed.
    """


@register(_be.EVP_TOOBIG)
class TooBig(ErrorBase):
    """
    Too big payload.
    """


@register(_be.EVP_AGAIN)
class Again(ErrorBase):
    """
    Failure because of temporary conditions.
    """


@register(_be.EVP_AGENT_PROTOCOL_ERROR)
class AgentProtocolError(ErrorBase):
    """
    Protocol error when communicating with the agent.
    """


@register(_be.EVP_EXIST)
class Exist(ErrorBase):
    """
    The request failed bacause of conflicting existing entries.
    """


@register(_be.EVP_FAULT)
class Fault(ErrorBase):
    """
    Invalid address was detected.

    Note: An application should not rely on such a detection.
    It's the responsibility of applications to always specify
    vaild addresses.
    """


@register(_be.EVP_DENIED)
class Denied(ErrorBase):
    """
    A request was denied. It could mean the agent cannot be
    transmitting due to a full queue.
    """


@register(_be.EVP_NOTSUP)
class NotSupported(ErrorBase):
    """
    The request is still not supported by the implementation.
    """
