from __future__ import annotations

import base64
from typing import Any

import aiohttp
import pytest

from py_uconnect import (
    API,
    APIError,
    ChargingLevel,
    CommandError,
    PinAuthenticationError,
    UconnectConnectionError,
)
from py_uconnect.brands import FIAT_EU
from py_uconnect.command import (
    COMMAND_CHARGE,
    COMMAND_DOORS_LOCK,
    COMMAND_HVAC_ON,
    COMMAND_REFRESH_LOCATION,
)

from .conftest import (
    AWS_ACCESS_KEY,
    AWS_SESSION_TOKEN,
    BRAND,
    PIN,
    PIN_TOKEN,
    UID,
    VIN,
    api_url,
    mock_login,
    mock_pin_auth,
    pin_auth_url,
    vehicle_url,
)
from .mock_http import MockSession

PENDING = {"responseStatus": "pending", "correlationId": "CID"}

# (API method, args, HTTP method, URL, request body, query)
READ_ENDPOINTS: list[tuple[str, tuple[Any, ...], str, str, Any, dict[str, str]]] = [
    (
        "get_remote_status",
        (VIN,),
        "GET",
        vehicle_url("v1", "remote/status"),
        None,
        {},
    ),
    (
        "get_vehicle_location",
        (VIN,),
        "GET",
        vehicle_url("v1", "location/lastknown"),
        None,
        {},
    ),
    (
        "get_vehicle_health_report",
        (VIN,),
        "GET",
        vehicle_url("v1", "vhr/"),
        None,
        {},
    ),
    (
        "get_maintenance_history",
        (VIN,),
        "GET",
        vehicle_url("v1", "maintenance/history/"),
        None,
        {},
    ),
    (
        "get_vehicle_image",
        (VIN, 100, 50),
        "POST",
        vehicle_url("v4", "image/"),
        {"imageURLs": [{"id": VIN, "width": 100, "height": 50, "resp": "png"}]},
        {},
    ),
    (
        "get_vehicle_notifications",
        (VIN, 10),
        "GET",
        vehicle_url("v1", "notifications"),
        None,
        {"limit": "10"},
    ),
    (
        "get_stolen_vehicle_status",
        (VIN,),
        "GET",
        vehicle_url("v1", "svla/status/"),
        None,
        {},
    ),
    (
        "get_vehicle_subscription",
        (VIN,),
        "GET",
        vehicle_url("v1", "subscription/"),
        None,
        {},
    ),
    (
        "set_vehicle_nickname",
        (VIN, "My car"),
        "POST",
        vehicle_url("v1", "nickname/"),
        {"nickname": "My car"},
        {},
    ),
    (
        "get_remote_operation_status",
        (VIN, "CID"),
        "GET",
        vehicle_url("v1", "remote/CID/status/"),
        None,
        {},
    ),
    (
        "get_charge_schedules",
        (VIN,),
        "GET",
        vehicle_url("v4", "ev/schedule/"),
        None,
        {},
    ),
]


@pytest.mark.parametrize(
    ("name", "args", "method", "url", "body", "query"),
    READ_ENDPOINTS,
    ids=[x[0] for x in READ_ENDPOINTS],
)
async def test_endpoint(
    http: MockSession,
    api: API,
    name: str,
    args: tuple[Any, ...],
    method: str,
    url: str,
    body: Any,
    query: dict[str, str],
) -> None:
    mock_login(http)
    http.add(method, url, payload={"result": name})

    assert await getattr(api, name)(*args) == {"result": name}

    (call,) = http.calls_to(method, url)
    assert call.json == body
    assert call.query == query


async def test_request_headers(http: MockSession, api: API) -> None:
    mock_login(http)
    http.get(vehicle_url("v1", "remote/status"), payload={})

    await api.get_remote_status(VIN)

    (call,) = http.calls_to("GET", vehicle_url("v1", "remote/status"))
    h = call.headers
    assert h["x-api-key"] == BRAND.api.key
    assert h["locale"] == BRAND.locale
    assert h["x-clientapp-name"] == "CWP"
    assert h["x-originator-type"] == "web"
    assert len(h["clientrequestid"]) == 16
    assert h["X-Amz-Security-Token"] == AWS_SESSION_TOKEN
    assert h["Authorization"].startswith(
        f"AWS4-HMAC-SHA256 Credential={AWS_ACCESS_KEY}/"
    )
    assert f"/{BRAND.region}/execute-api/aws4_request" in h["Authorization"]


async def test_list_vehicles(http: MockSession, api: API) -> None:
    mock_login(http)
    url = api_url("/v4/accounts/{uid}/vehicles")
    http.get(url, payload={"userid": UID, "vehicles": [{"vin": VIN}]})

    assert await api.list_vehicles() == [{"vin": VIN}]

    (call,) = http.calls_to("GET", url)
    assert call.query == {"stage": "ALL", "sdp": "ALL", "brand": FIAT_EU.brand_code}


async def test_list_vehicles_invalid_response(http: MockSession, api: API) -> None:
    mock_login(http)
    http.get(api_url("/v4/accounts/{uid}/vehicles"), payload={"foo": 1})

    with pytest.raises(APIError, match="no vehicles"):
        await api.list_vehicles()


async def test_http_error(http: MockSession, api: API) -> None:
    mock_login(http)
    http.get(vehicle_url("v1", "vhr/"), status=500, payload={"message": "boom"})

    with pytest.raises(APIError) as err:
        await api.get_vehicle_health_report(VIN)

    assert err.value.status == 500
    assert err.value.body == {"message": "boom"}
    assert err.value.url == vehicle_url("v1", "vhr/")


async def test_invalid_json(http: MockSession, api: API) -> None:
    mock_login(http)
    http.get(vehicle_url("v1", "vhr/"), body="<html>")

    with pytest.raises(APIError, match="invalid JSON"):
        await api.get_vehicle_health_report(VIN)


async def test_empty_response(http: MockSession, api: API) -> None:
    mock_login(http)
    http.get(vehicle_url("v1", "vhr/"), body="")

    assert await api.get_vehicle_health_report(VIN) == {}


async def test_unexpected_json_type(http: MockSession, api: API) -> None:
    mock_login(http)
    http.get(vehicle_url("v1", "vhr/"), payload=[1, 2])

    with pytest.raises(APIError, match="expected a JSON object"):
        await api.get_vehicle_health_report(VIN)


async def test_connection_error(http: MockSession, api: API) -> None:
    mock_login(http)
    http.get(vehicle_url("v1", "vhr/"), exception=aiohttp.ServerDisconnectedError())

    with pytest.raises(UconnectConnectionError):
        await api.get_vehicle_health_report(VIN)


async def test_raw_request(http: MockSession, api: API) -> None:
    mock_login(http)
    url = vehicle_url("v2", "something/")
    http.put(url, payload={"ok": 1})

    r = await api.request(
        "PUT",
        f"/v2/accounts/{{uid}}/vehicles/{VIN}/something/",
        params={"a": 1},
        body={"b": 2},
    )

    assert r == {"ok": 1}
    (call,) = http.calls_to("PUT", url)
    assert call.query == {"a": "1"}
    assert call.json == {"b": 2}


# Vehicle status


async def test_vehicle_info_v3(http: MockSession, api: API) -> None:
    mock_login(http)
    http.get(vehicle_url("v3", "status/"), payload={"v": 3})

    assert await api.get_vehicle_info(VIN) == {"v": 3}


@pytest.mark.parametrize("status", [400, 404, 502])
async def test_vehicle_info_falls_back_to_v4(
    http: MockSession, api: API, status: int
) -> None:
    mock_login(http)
    http.get(vehicle_url("v3", "status/"), status=status)
    http.get(vehicle_url("v4", "status/"), payload={"v": 4}, repeat=True)

    assert await api.get_vehicle_info(VIN) == {"v": 4}
    # The working version is remembered
    assert await api.get_vehicle_info(VIN) == {"v": 4}
    assert len(http.calls_to("GET", vehicle_url("v3", "status/"))) == 1


async def test_vehicle_info_other_errors_are_raised(
    http: MockSession, api: API
) -> None:
    mock_login(http)
    http.get(vehicle_url("v3", "status/"), status=500)

    with pytest.raises(APIError) as err:
        await api.get_vehicle_info(VIN)

    assert err.value.status == 500
    assert not http.calls_to("GET", vehicle_url("v4", "status/"))


async def test_vehicle_info_unsupported(http: MockSession, api: API) -> None:
    mock_login(http)
    http.get(vehicle_url("v3", "status/"), status=404)
    http.get(vehicle_url("v4", "status/"), status=404)

    with pytest.raises(APIError) as err:
        await api.get_vehicle_info(VIN)

    assert err.value.status == 404


# PIN authentication


async def test_pin_auth(http: MockSession, api: API) -> None:
    mock_login(http)
    mock_pin_auth(http)

    assert await api.pin_auth() == PIN_TOKEN

    (call,) = http.calls_to("POST", pin_auth_url())
    assert call.json == {"pin": base64.b64encode(PIN.encode()).decode()}
    assert call.headers["x-api-key"] == BRAND.mfa.key
    assert call.headers["Authorization"].startswith("AWS4-HMAC-SHA256")


async def test_pin_auth_without_pin(http: MockSession, api: API) -> None:
    api.pin = None

    with pytest.raises(PinAuthenticationError, match="PIN is required"):
        await api.pin_auth()

    assert not http.calls


@pytest.mark.parametrize(
    ("status", "payload"), [(401, {"message": "wrong pin"}), (200, {"x": 1})]
)
async def test_pin_auth_rejected(
    http: MockSession, api: API, status: int, payload: Any
) -> None:
    mock_login(http)
    mock_pin_auth(http, status=status, payload=payload)

    with pytest.raises(PinAuthenticationError):
        await api.pin_auth()


# Commands


@pytest.mark.parametrize(
    ("cmd", "url"),
    [
        (COMMAND_DOORS_LOCK, vehicle_url("v1", "remote")),
        (COMMAND_HVAC_ON, vehicle_url("v2", "remote")),
        (COMMAND_CHARGE, vehicle_url("v1", "ev/chargenow")),
        (COMMAND_REFRESH_LOCATION, vehicle_url("v1", "location")),
    ],
    ids=str,
)
async def test_command(http: MockSession, api: API, cmd: Any, url: str) -> None:
    mock_login(http)
    mock_pin_auth(http)
    http.post(url, payload=PENDING)

    assert await api.command(VIN, cmd) == "CID"

    (call,) = http.calls_to("POST", url)
    assert call.json == {"command": cmd.name, "pinAuth": PIN_TOKEN}


async def test_command_not_accepted(http: MockSession, api: API) -> None:
    mock_login(http)
    mock_pin_auth(http)
    http.post(
        vehicle_url("v1", "remote"),
        payload={"responseStatus": "failure", "debugMsg": "vehicle asleep"},
    )

    with pytest.raises(CommandError, match="vehicle asleep"):
        await api.command(VIN, COMMAND_DOORS_LOCK)


async def test_command_fallback_on_403(http: MockSession, api: API) -> None:
    mock_login(http)
    mock_pin_auth(http)
    http.post(vehicle_url("v1", "ev/chargenow"), status=403)
    http.post(vehicle_url("v4", "ev/chargenow"), payload=PENDING)

    assert await api.command(VIN, COMMAND_CHARGE) == "CID"

    (call,) = http.calls_to("POST", vehicle_url("v4", "ev/chargenow"))
    assert call.json == {"command": "START_CHARGE", "pinAuth": PIN_TOKEN}


async def test_command_403_without_fallback(http: MockSession, api: API) -> None:
    mock_login(http)
    mock_pin_auth(http)
    http.post(vehicle_url("v1", "remote"), status=403)

    with pytest.raises(APIError) as err:
        await api.command(VIN, COMMAND_DOORS_LOCK)

    assert err.value.status == 403


# EV


async def test_set_charging_level(http: MockSession, api: API) -> None:
    mock_login(http)
    mock_pin_auth(http)
    url = vehicle_url("v2", "ev/charge/preference/")
    http.put(url, payload={"correlationId": "CID"})

    assert await api.set_charging_level(VIN, ChargingLevel.LEVEL_TWO, 80) == "CID"

    (call,) = http.calls_to("PUT", url)
    assert call.json == {
        "preference": "LEVEL_TWO",
        "pinAuth": PIN_TOKEN,
        "maxSOC": "80",
    }


@pytest.mark.parametrize("max_soc", [0, 101])
async def test_set_charging_level_invalid_max_soc(api: API, max_soc: int) -> None:
    with pytest.raises(ValueError, match="max_soc"):
        await api.set_charging_level(VIN, ChargingLevel.LEVEL_TWO, max_soc)


async def test_set_charge_schedule(http: MockSession, api: API) -> None:
    mock_login(http)
    mock_pin_auth(http)
    url = vehicle_url("v4", "ev/schedule/")
    http.post(url, payload={"correlationId": "CID"})

    schedule = {"schedules": [{"startTime": "01:00"}]}
    assert await api.set_charge_schedule(VIN, schedule) == "CID"

    (call,) = http.calls_to("POST", url)
    assert call.json == schedule | {"pinAuth": PIN_TOKEN}


async def test_set_charge_schedule_rejected(http: MockSession, api: API) -> None:
    mock_login(http)
    mock_pin_auth(http)
    http.post(vehicle_url("v4", "ev/schedule/"), payload={"debugMsg": "nope"})

    with pytest.raises(CommandError, match="nope"):
        await api.set_charge_schedule(VIN, {})
