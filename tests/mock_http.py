"""A minimal fake of aiohttp.ClientSession for tests.

The clients accept a session, so tests inject this instead of patching aiohttp.
Routes are matched by method and URL (without the query string) in the order
they were added; a non-repeating route is used once.
"""

from __future__ import annotations

import json as jsonlib
import re
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from types import TracebackType
from typing import Any

from yarl import URL


@dataclass
class Call:
    method: str
    url: URL
    headers: dict[str, str]
    body: bytes | None
    cookies: dict[str, str] | None

    @property
    def json(self) -> Any:
        return jsonlib.loads(self.body) if self.body else None

    @property
    def query(self) -> dict[str, str]:
        return dict(self.url.query)


@dataclass
class Route:
    method: str
    url: str | re.Pattern[str]
    status: int = 200
    body: str = ""
    cookies: dict[str, str] = field(default_factory=dict)
    exception: BaseException | None = None
    repeat: bool = False
    used: bool = False

    def matches(self, method: str, url: URL) -> bool:
        if method != self.method or (self.used and not self.repeat):
            return False

        bare = str(url.with_query(None))
        if isinstance(self.url, re.Pattern):
            return self.url.fullmatch(bare) is not None

        return bare == self.url


class FakeResponse:
    def __init__(self, route: Route):
        self.status = route.status
        self._body = route.body
        self.cookies: SimpleCookie = SimpleCookie()
        for k, v in route.cookies.items():
            self.cookies[k] = v

    async def text(self) -> str:
        return self._body

    async def __aenter__(self) -> FakeResponse:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        pass


class _RequestContext:
    def __init__(self, session: MockSession, call: Call):
        self.session = session
        self.call = call

    async def __aenter__(self) -> FakeResponse:
        self.session.calls.append(self.call)

        for route in self.session.routes:
            if route.matches(self.call.method, self.call.url):
                route.used = True
                if route.exception is not None:
                    raise route.exception
                return FakeResponse(route)

        raise AssertionError(f"unexpected request: {self.call.method} {self.call.url}")

    async def __aexit__(self, *args: Any) -> None:
        pass


class MockSession:
    def __init__(self) -> None:
        self.routes: list[Route] = []
        self.calls: list[Call] = []
        self.closed = False

    def add(
        self,
        method: str,
        url: str | re.Pattern[str],
        *,
        status: int = 200,
        payload: Any = None,
        body: str | None = None,
        cookies: dict[str, str] | None = None,
        exception: BaseException | None = None,
        repeat: bool = False,
    ) -> None:
        if body is None:
            body = jsonlib.dumps(payload) if payload is not None else ""

        self.routes.append(
            Route(
                method=method,
                url=url,
                status=status,
                body=body,
                cookies=cookies or {},
                exception=exception,
                repeat=repeat,
            )
        )

    def get(self, url: str | re.Pattern[str], **kwargs: Any) -> None:
        self.add("GET", url, **kwargs)

    def post(self, url: str | re.Pattern[str], **kwargs: Any) -> None:
        self.add("POST", url, **kwargs)

    def put(self, url: str | re.Pattern[str], **kwargs: Any) -> None:
        self.add("PUT", url, **kwargs)

    def delete(self, url: str | re.Pattern[str], **kwargs: Any) -> None:
        self.add("DELETE", url, **kwargs)

    def calls_to(self, method: str, url: str | re.Pattern[str]) -> list[Call]:
        """Returns the recorded calls matching the method and URL"""

        probe = Route(method=method, url=url, repeat=True)
        return [c for c in self.calls if probe.matches(c.method, c.url)]

    def request(
        self,
        method: str,
        url: str | URL,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        data: bytes | None = None,
        json: Any = None,
        cookies: dict[str, str] | None = None,
        timeout: Any = None,
    ) -> _RequestContext:
        u = URL(url) if isinstance(url, str) else url
        if params:
            u = u.update_query({k: str(v) for k, v in params.items()})

        body = data if data is not None else None
        if json is not None:
            body = jsonlib.dumps(json).encode()

        return _RequestContext(
            self,
            Call(
                method=method,
                url=u,
                headers=dict(headers or {}),
                body=body,
                cookies=dict(cookies) if cookies is not None else None,
            ),
        )

    async def close(self) -> None:
        self.closed = True
