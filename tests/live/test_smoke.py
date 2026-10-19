"""Read-only smoke test against the real API.

Skipped unless credentials are given in the environment:

    UCONNECT_EMAIL=... UCONNECT_PASSWORD=... UCONNECT_BRAND=FIAT_EU \\
        pytest tests/live -v

Set UCONNECT_PIN as well to also check PIN authentication (no command is sent).
"""

from __future__ import annotations

import logging
import os
from collections.abc import AsyncIterator

import pytest

from py_uconnect import BRANDS, APIError, Client

pytestmark = pytest.mark.skipif(
    not all(os.environ.get(f"UCONNECT_{x}") for x in ("EMAIL", "PASSWORD", "BRAND")),
    reason="UCONNECT_EMAIL, UCONNECT_PASSWORD and UCONNECT_BRAND are not set",
)

_LOGGER = logging.getLogger(__name__)


@pytest.fixture
async def client() -> AsyncIterator[Client]:
    async with Client(
        os.environ["UCONNECT_EMAIL"],
        os.environ["UCONNECT_PASSWORD"],
        os.environ.get("UCONNECT_PIN"),
        BRANDS[os.environ["UCONNECT_BRAND"]],
    ) as client:
        yield client


async def test_refresh(client: Client) -> None:
    vehicles = await client.refresh()

    assert vehicles, "no vehicles in the account"
    for v in vehicles.values():
        _LOGGER.info("%s", v.to_json(indent=2))
        assert v.make


async def test_read_endpoints(client: Client) -> None:
    vehicles = await client.refresh()

    for vin in vehicles:
        for name in (
            "get_vehicle_health_report",
            "get_maintenance_history",
            "get_vehicle_notifications",
            "get_vehicle_subscription",
            "get_vehicle_image",
        ):
            try:
                _LOGGER.info("%s: %s", name, await getattr(client.api, name)(vin))
            except APIError as err:
                # Not every vehicle supports every endpoint
                _LOGGER.warning("%s: %s", name, err)


@pytest.mark.skipif(not os.environ.get("UCONNECT_PIN"), reason="no UCONNECT_PIN")
async def test_pin_auth(client: Client) -> None:
    assert await client.api.pin_auth()
