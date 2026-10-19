from __future__ import annotations

import json
import re
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from py_uconnect import API, Client
from py_uconnect.brands import FIAT_EU, Brand

from .mock_http import MockSession

FIXTURES = Path(__file__).parent / "fixtures"

UID = "0123456789abcdef0123456789abcdef"
VIN = "ZFAEFAC39MX000001"
PIN = "1234"
PIN_TOKEN = "PIN-AUTH-TOKEN"
AWS_ACCESS_KEY = "ASIAEXAMPLE"
AWS_SESSION_TOKEN = "SESSION-TOKEN"

BRAND = FIAT_EU


def load_fixture(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text())


def gigya_url(brand: Brand, call: str) -> str:
    return f"{brand.login_url}/{call}"


def cognito_url(brand: Brand) -> str:
    return f"https://cognito-identity.{brand.region}.amazonaws.com/"


def mock_login(
    http: MockSession,
    brand: Brand = BRAND,
    expires_in: float = 3600,
    repeat: bool = False,
    skip: tuple[str, ...] = (),
) -> None:
    """Mocks the calls of a successful login, except the ``skip``ped ones
    (``token``, ``cognito``)"""

    http.get(
        gigya_url(brand, "accounts.webSdkBootstrap"),
        payload={"statusCode": 200, "errorCode": 0},
        cookies={"gmid": "GMID"},
        repeat=repeat,
    )
    http.post(
        gigya_url(brand, "accounts.login"),
        payload={
            "statusCode": 200,
            "errorCode": 0,
            "UID": UID,
            "sessionInfo": {"login_token": "LOGIN-TOKEN"},
        },
        repeat=repeat,
    )
    http.post(
        gigya_url(brand, "accounts.getJWT"),
        payload={"statusCode": 200, "errorCode": 0, "id_token": "GIGYA-JWT"},
        repeat=repeat,
    )
    if "token" not in skip:
        http.post(
            brand.token_url,
            payload={
                "Token": "OPENID-TOKEN",
                "IdentityId": f"{brand.region}:identity",
            },
            repeat=repeat,
        )
    if "cognito" not in skip:
        http.post(
            cognito_url(brand),
            payload={
                "IdentityId": f"{brand.region}:identity",
                "Credentials": {
                    "AccessKeyId": AWS_ACCESS_KEY,
                    "SecretKey": "SECRET",
                    "SessionToken": AWS_SESSION_TOKEN,
                    "Expiration": time.time() + expires_in,
                },
            },
            repeat=repeat,
        )


def pin_auth_url(brand: Brand = BRAND) -> str:
    return f"{brand.mfa.url}/v1/accounts/{UID}/ignite/pin/authenticate"


def mock_pin_auth(http: MockSession, brand: Brand = BRAND, **kwargs: Any) -> None:
    kwargs.setdefault("payload", {"token": PIN_TOKEN})
    http.post(pin_auth_url(brand), **kwargs)


def api_url(path: str, brand: Brand = BRAND) -> str:
    return f"{brand.api.url}{path.replace('{uid}', UID)}"


def vehicle_url(version: str, suffix: str = "", vin: str = VIN) -> str:
    return api_url(f"/{version}/accounts/{{uid}}/vehicles/{vin}/{suffix}")


def any_vehicle_url(version: str, suffix: str) -> re.Pattern[str]:
    return re.compile(
        re.escape(vehicle_url(version, "", "VIN")).replace("VIN", "[^/]+")
        + re.escape(suffix)
    )


@pytest.fixture
def http() -> MockSession:
    return MockSession()


@pytest.fixture
async def api(http: MockSession) -> AsyncIterator[API]:
    async with API(
        "user@example.com",
        "secret",
        PIN,
        BRAND,
        session=http,  # type: ignore[arg-type]
    ) as api:
        yield api


@pytest.fixture
async def client(http: MockSession) -> AsyncIterator[Client]:
    async with Client(
        "user@example.com",
        "secret",
        PIN,
        BRAND,
        session=http,  # type: ignore[arg-type]
    ) as client:
        yield client
