from __future__ import annotations

import pytest

from py_uconnect import API, BRANDS
from py_uconnect.brands import (
    FIAT_LATAM,
    JEEP_LATAM,
    JEEP_US,
    RAM_LATAM,
    Brand,
)

from .conftest import UID, gigya_url, mock_login
from .mock_http import MockSession


def test_brand_names_match_keys() -> None:
    assert all(name == brand.name for name, brand in BRANDS.items())


@pytest.mark.parametrize("brand", [JEEP_LATAM, FIAT_LATAM, RAM_LATAM], ids=str)
def test_latam_uses_the_north_american_backend(brand: Brand) -> None:
    """The LATAM app is the North American one with its own login site"""

    assert BRANDS[brand.name] is brand
    for attr in ("region", "token_url", "api", "mfa", "brand_code"):
        assert getattr(brand, attr) == getattr(JEEP_US, attr), attr

    assert brand.login_url == "https://accounts.us1.gigya.com"
    assert brand.login_api_key == JEEP_LATAM.login_api_key
    assert brand.login_api_key != JEEP_US.login_api_key
    assert brand.locale == "pt_br"


async def test_latam_login(http: MockSession) -> None:
    mock_login(http, brand=JEEP_LATAM)

    async with API(
        "user@example.com",
        "secret",
        None,
        JEEP_LATAM,
        session=http,  # type: ignore[arg-type]
    ) as api:
        await api.login()

    assert api.uid == UID
    (login,) = http.calls_to("POST", gigya_url(JEEP_LATAM, "accounts.login"))
    assert login.query["APIKey"] == JEEP_LATAM.login_api_key
