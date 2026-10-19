from __future__ import annotations

import pytest

from py_uconnect import (
    AuthenticationError,
    ChargingLevel,
    Client,
    CommandTimeoutError,
)
from py_uconnect.command import COMMAND_DOORS_LOCK

from .conftest import (
    VIN,
    api_url,
    gigya_url,
    mock_login,
    mock_pin_auth,
    vehicle_url,
)
from .mock_http import MockSession

VIN2 = "1C4HJXEN5MW000002"

VEHICLES_URL = api_url("/v4/accounts/{uid}/vehicles")


def mock_vehicle(
    http: MockSession,
    vin: str,
    info: dict | int = 200,
    location: dict | int = 200,
    remote: dict | int = 200,
) -> None:
    for version, suffix, r in (
        ("v3", "status/", info),
        ("v1", "location/lastknown", location),
        ("v1", "remote/status", remote),
    ):
        url = vehicle_url(version, suffix, vin)
        if isinstance(r, int):
            http.get(url, status=r, payload={"message": "error"})
            if version == "v3" and r in (400, 404, 502):
                http.get(vehicle_url("v4", suffix, vin), status=r)
        else:
            http.get(url, payload=r)


async def test_refresh(http: MockSession, client: Client) -> None:
    mock_login(http)
    http.get(
        VEHICLES_URL,
        payload={
            "vehicles": [
                {"vin": VIN, "nickname": "500e", "make": "FIAT"},
                {"vin": VIN2, "nickname": "Jeep", "make": "JEEP"},
            ]
        },
    )
    mock_vehicle(
        http,
        VIN,
        info={"vehicleInfo": {"odometer": {"odometer": {"value": "1841"}}}},
        location={"latitude": 1.5, "longitude": 2.5, "timeStamp": 1738660203634},
        remote={"doors": {"driver": {"status": "LOCKED"}}},
    )
    # The second vehicle doesn't support the detailed status nor location
    mock_vehicle(http, VIN2, info=404, location=500, remote={})

    vehicles = await client.refresh()

    assert set(vehicles) == {VIN, VIN2}
    assert client.get_vehicles() is vehicles

    v = vehicles[VIN]
    assert v.nickname == "500e"
    assert v.odometer == 1841
    assert v.door_driver_locked is True
    assert v.location is not None
    assert v.location.latitude == 1.5

    v2 = vehicles[VIN2]
    assert v2.make == "JEEP"
    assert v2.odometer is None
    assert v2.location is None
    assert v2.raw_info is None


async def test_refresh_keeps_data_on_partial_failure(
    http: MockSession, client: Client
) -> None:
    mock_login(http)
    http.get(VEHICLES_URL, payload={"vehicles": [{"vin": VIN}]}, repeat=True)
    mock_vehicle(http, VIN, location={"latitude": 1.5})
    mock_vehicle(http, VIN, location=503)

    await client.refresh()
    await client.refresh()

    location = client.vehicles[VIN].location
    assert location is not None
    assert location.latitude == 1.5


async def test_refresh_removes_vehicles(http: MockSession, client: Client) -> None:
    mock_login(http)
    http.get(VEHICLES_URL, payload={"vehicles": [{"vin": VIN}, {"vin": VIN2}]})
    http.get(VEHICLES_URL, payload={"vehicles": [{"vin": VIN2}]})
    mock_vehicle(http, VIN, {}, {}, {})
    mock_vehicle(http, VIN2, {}, {}, {})
    mock_vehicle(http, VIN2, {}, {}, {})

    await client.refresh()
    assert set(client.vehicles) == {VIN, VIN2}

    v2 = client.vehicles[VIN2]
    await client.refresh()
    assert set(client.vehicles) == {VIN2}
    # Existing objects are updated in place
    assert client.vehicles[VIN2] is v2


async def test_refresh_raises_auth_errors(http: MockSession, client: Client) -> None:
    http.get(
        gigya_url(client.api.brand, "accounts.webSdkBootstrap"),
        payload={"statusCode": 403, "errorCode": 403042, "errorMessage": "bad"},
    )

    with pytest.raises(AuthenticationError):
        await client.refresh()


async def test_command_verify_success(http: MockSession, client: Client) -> None:
    mock_login(http)
    mock_pin_auth(http)
    http.post(
        vehicle_url("v1", "remote"),
        payload={"responseStatus": "pending", "correlationId": "CID"},
    )
    http.get(vehicle_url("v1", "remote/CID/status/"), payload={"status": "PENDING"})
    http.get(vehicle_url("v1", "notifications"), payload={})
    http.get(vehicle_url("v1", "remote/CID/status/"), payload={"status": "SUCCESS"})

    assert await client.command_verify(VIN, COMMAND_DOORS_LOCK, interval=0) is True


@pytest.mark.parametrize("status", ["FAILURE", "failed", "Rejected"])
async def test_wait_for_operation_failure(
    http: MockSession, client: Client, status: str
) -> None:
    mock_login(http)
    http.get(vehicle_url("v1", "remote/CID/status/"), payload={"status": status})

    assert await client.wait_for_operation(VIN, "CID", interval=0) is False


async def test_wait_for_operation_uses_notifications(
    http: MockSession, client: Client
) -> None:
    mock_login(http)
    # The status endpoint is not available for every brand
    http.get(vehicle_url("v1", "remote/CID/status/"), status=404)
    http.get(
        vehicle_url("v1", "notifications"),
        payload={
            "notifications": {
                "items": [
                    {
                        "correlationId": "OTHER",
                        "notification": {"data": {"status": "failure"}},
                    },
                    {
                        "correlationId": "CID",
                        "notification": {"data": {"status": "pending"}},
                    },
                ]
            }
        },
    )
    http.get(
        vehicle_url("v1", "notifications"),
        payload={
            "notifications": {
                "items": [
                    {
                        "correlationId": "CID",
                        "notification": {"data": {"status": "success"}},
                    }
                ]
            }
        },
    )

    assert await client.wait_for_operation(VIN, "CID", interval=0) is True
    # After a 404 the status endpoint is not polled anymore
    assert len(http.calls_to("GET", vehicle_url("v1", "remote/CID/status/"))) == 1


async def test_wait_for_operation_timeout(http: MockSession, client: Client) -> None:
    mock_login(http)
    http.get(
        vehicle_url("v1", "remote/CID/status/"),
        payload={"status": "PENDING"},
        repeat=True,
    )
    http.get(
        vehicle_url("v1", "notifications"),
        status=500,
        repeat=True,
    )

    with pytest.raises(CommandTimeoutError, match="HTTP 500"):
        await client.wait_for_operation(VIN, "CID", timeout=0.05, interval=0.01)


async def test_set_charging_level_verify(http: MockSession, client: Client) -> None:
    mock_login(http)
    mock_pin_auth(http)
    http.put(
        vehicle_url("v2", "ev/charge/preference/"), payload={"correlationId": "CID"}
    )
    http.get(vehicle_url("v1", "remote/CID/status/"), payload={"status": "SUCCESS"})

    assert await client.set_charging_level_verify(
        VIN, ChargingLevel.LEVEL_FIVE, interval=0
    )


def test_set_pin(client: Client) -> None:
    client.set_pin("9999")
    assert client.api.pin == "9999"
