"""Exceptions raised by the library"""

from __future__ import annotations

from typing import Any


class UconnectError(Exception):
    """Base class for all errors raised by the library"""


class UconnectConnectionError(UconnectError):
    """The server could not be reached or the request timed out"""


class AuthenticationError(UconnectError):
    """Login failed (wrong credentials, account problems, token exchange errors)"""


class PinAuthenticationError(AuthenticationError):
    """The PIN was rejected or PIN authentication failed"""


class APIError(UconnectError):
    """The API returned an unexpected HTTP status or an invalid response"""

    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        url: str | None = None,
        body: Any = None,
    ):
        super().__init__(message)
        self.status = status
        self.url = url
        self.body = body


class CommandError(UconnectError):
    """A remote command was rejected by the API or reported as failed by the car"""


class CommandTimeoutError(CommandError):
    """The result of a remote command was not reported within the timeout"""
