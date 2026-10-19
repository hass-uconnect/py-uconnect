from __future__ import annotations

from typing import Any

import pytest

from py_uconnect import (
    AuthenticationError,
    ChargingLevel,
    Client,
    CommandTimeoutError,
)
from py_uconnect.command import (
    COMMAND_CHARGE,
    COMMAND_DEEP_REFRESH,
    COMMAND_DOORS_LOCK,
    COMMAND_HVAC_ON,
    hvac_params,
)

from .conftest import (
    PIN_TOKEN,
    VIN,
    api_url,
    gigya_url,
    load_fixture,
    mock_login,
    mock_pin_auth,
    pin_auth_url,
    vehicle_url,
)
from .mock_http import MockSession

VIN2 = "1C4HJXEN5MW000002"

VEHICLES_URL = api_url("/v4/accounts/{uid}/vehicles/")
PENDING = {"responseStatus": "pending", "correlationId": "CID"}


def mock_vehicle(
    http: MockSession,
    vin: str,
    info: dict[str, Any] | int = 200,
    location: dict[str, Any] | int = 200,
    remote: dict[str, Any] | int = 200,
    status_version: str = "v3",
) -> None:
    other = "v4" if status_version == "v3" else "v3"

    for version, suffix, r in (
        (status_version, "status/", info),
        ("v1", "location/lastknown/", location),
        ("v1", "remote/status/", remote),
    ):
        url = vehicle_url(version, suffix, vin)
        if isinstance(r, int):
            http.get(url, status=r, payload={"message": "error"})
            if suffix == "status/" and r in (400, 404, 502):
                http.get(vehicle_url(other, suffix, vin), status=r)
        else:
            http.get(url, payload=r)


async def refresh_with_fixtures(http: MockSession, client: Client) -> None:
    mock_login(http)
    http.get(VEHICLES_URL, payload=load_fixture("vehicles.json"))
    mock_vehicle(
        http,
        VIN,
        info=load_fixture("status_ev.json"),
        location=load_fixture("location.json"),
        remote=load_fixture("remote_status.json"),
    )
    # The second vehicle doesn't support the detailed status nor the location
    mock_vehicle(http, VIN2, info=404, location=500, remote={})

    await client.refresh()


async def test_refresh(http: MockSession, client: Client) -> None:
    await refresh_with_fixtures(http, client)

    vehicles = client.get_vehicles()
    assert set(vehicles) == {VIN, VIN2}

    v = vehicles[VIN]
    assert v.nickname == "500"
    assert v.odometer == 1841
    assert v.state_of_charge == 63
    assert v.door_driver_locked is True
    assert v.location is not None
    assert v.location.latitude == 45.0703
    assert v.raw_location == load_fixture("location.json")

    # Kept with the data from the vehicle list
    v2 = vehicles[VIN2]
    assert v2.make == "JEEP"
    assert v2.odometer == 11990
    assert v2.raw_info is None
    assert v2.location is not None
    assert v2.location.latitude == 42.3


async def test_refresh_uses_v4_status_for_cpcoop(
    http: MockSession, client: Client
) -> None:
    mock_login(http)
    http.get(
        VEHICLES_URL,
        payload={
            "vehicles": [
                {
                    "vin": VIN,
                    "services": [
                        {
                            "service": "CPCOOP",
                            "vehicleCapable": True,
                            "serviceEnabled": True,
                        }
                    ],
                }
            ]
        },
    )
    mock_vehicle(http, VIN, {"vehicleInfo": {}}, {}, {}, status_version="v4")

    await client.refresh()

    assert not http.calls_to("GET", vehicle_url("v3", "status/"))


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


# Commands


async def test_command_resolves_variant(http: MockSession, client: Client) -> None:
    await refresh_with_fixtures(http, client)
    mock_pin_auth(http, sdp="IGNITE")
    http.post(vehicle_url("v4", "ev/chargenow/"), payload=PENDING)
    http.post(vehicle_url("v2", "ev/"), payload=PENDING)

    # The vehicle has CNOW2 and DEEPREFRESH2
    assert await client.command(VIN, COMMAND_CHARGE) == "CID"
    assert await client.command(VIN, COMMAND_DEEP_REFRESH) == "CID"

    assert not http.calls_to("POST", vehicle_url("v1", "ev/chargenow/"))
    (call,) = http.calls_to("POST", vehicle_url("v4", "ev/chargenow/"))
    assert call.json == {"command": "START_CHARGE", "pinAuth": PIN_TOKEN}
    (call,) = http.calls_to("POST", vehicle_url("v2", "ev/"))
    assert call.json == {"command": "DEEPREFRESH", "pinAuth": PIN_TOKEN}


async def test_command_unknown_vehicle(http: MockSession, client: Client) -> None:
    mock_login(http)
    mock_pin_auth(http)
    http.post(vehicle_url("v1", "ev/chargenow/"), payload=PENDING)

    assert await client.command(VIN, COMMAND_CHARGE) == "CID"


async def test_command_verify_success(http: MockSession, client: Client) -> None:
    mock_login(http)
    mock_pin_auth(http)
    http.post(vehicle_url("v2", "remote/"), payload=PENDING)
    http.get(
        vehicle_url("v1", "remote/CID/last-status/"), payload={"status": "PENDING"}
    )
    http.get(vehicle_url("v1", "remote/CID/status/"), payload={})
    http.get(vehicle_url("v1", "notifications/"), payload={})
    http.get(
        vehicle_url("v1", "remote/CID/last-status/"), payload={"status": "SUCCESS"}
    )

    assert await client.command_verify(
        VIN, COMMAND_HVAC_ON, hvac_params(20), interval=0
    )

    (call,) = http.calls_to("POST", vehicle_url("v2", "remote/"))
    assert call.json["params"]["targetTemp"] == 20


@pytest.mark.parametrize("status", ["FAILURE", "failed", "Rejected"])
async def test_wait_for_operation_failure(
    http: MockSession, client: Client, status: str
) -> None:
    mock_login(http)
    http.get(vehicle_url("v1", "remote/CID/last-status/"), status=404)
    http.get(
        vehicle_url("v1", "remote/CID/status/"), payload={"responseStatus": status}
    )

    assert await client.wait_for_operation(VIN, "CID", interval=0) is False


async def test_wait_for_operation_uses_notifications(
    http: MockSession, client: Client
) -> None:
    mock_login(http)
    # The status endpoints are not available everywhere
    http.get(vehicle_url("v1", "remote/CID/last-status/"), status=404)
    http.get(vehicle_url("v1", "remote/CID/status/"), status=404)
    http.get(
        vehicle_url("v1", "notifications/"),
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
        vehicle_url("v1", "notifications/"),
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
    # After a 404 the status endpoints are not polled anymore
    for suffix in ("remote/CID/last-status/", "remote/CID/status/"):
        assert len(http.calls_to("GET", vehicle_url("v1", suffix))) == 1


async def test_wait_for_operation_timeout(http: MockSession, client: Client) -> None:
    mock_login(http)
    http.get(
        vehicle_url("v1", "remote/CID/last-status/"),
        payload={"status": "PENDING"},
        repeat=True,
    )
    http.get(vehicle_url("v1", "remote/CID/status/"), payload={}, repeat=True)
    http.get(vehicle_url("v1", "notifications/"), status=500, repeat=True)

    with pytest.raises(CommandTimeoutError, match="HTTP 500"):
        await client.wait_for_operation(VIN, "CID", timeout=0.05, interval=0.01)


# EV


async def test_set_charging_level_verify(http: MockSession, client: Client) -> None:
    mock_login(http)
    mock_pin_auth(http)
    http.put(
        vehicle_url("v2", "ev/charge/preference/"), payload={"correlationId": "CID"}
    )
    http.get(
        vehicle_url("v1", "remote/CID/last-status/"), payload={"status": "SUCCESS"}
    )

    assert await client.set_charging_level_verify(
        VIN, ChargingLevel.LEVEL_FIVE, interval=0
    )


async def test_set_charge_schedules(http: MockSession, client: Client) -> None:
    await refresh_with_fixtures(http, client)
    mock_pin_auth(http, sdp="IGNITE")
    http.post(vehicle_url("v3", "ev/schedule/"), payload=PENDING)
    http.get(
        vehicle_url("v1", "remote/CID/last-status/"), payload={"status": "SUCCESS"}
    )

    schedules = client.vehicles[VIN].charge_schedules
    assert schedules is not None
    schedules[0]["startTime"] = "02:00"

    assert await client.set_charge_schedules_verify(VIN, schedules, interval=0)

    (call,) = http.calls_to("POST", vehicle_url("v3", "ev/schedule/"))
    assert call.json["command"] == "CPPLUSBEV"
    assert call.json["chargeSchedulesV3"][0]["startTime"] == "02:00"


async def test_set_charge_schedules_without_service(client: Client) -> None:
    with pytest.raises(ValueError, match="no schedule service"):
        await client.set_charge_schedules(VIN, [])


async def test_set_pin(http: MockSession, client: Client) -> None:
    mock_login(http)
    mock_pin_auth(http, repeat=True)
    http.post(vehicle_url("v1", "remote/"), payload=PENDING, repeat=True)

    await client.command(VIN, COMMAND_DOORS_LOCK)
    client.set_pin("9999")
    await client.command(VIN, COMMAND_DOORS_LOCK)

    assert client.api.pin == "9999"
    # The cached PIN token is dropped with the PIN change
    assert len(http.calls_to("POST", pin_auth_url())) == 2
