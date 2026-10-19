from __future__ import annotations

import base64
from datetime import UTC, datetime
from typing import Any

import aiohttp
import pytest

from py_uconnect import (
    API,
    APIError,
    ChargingLevel,
    CommandError,
    PinAuthenticationError,
    TheftAlarmSuppression,
    UconnectConnectionError,
)
from py_uconnect.brands import FIAT_EU
from py_uconnect.command import (
    COMMAND_CHARGE,
    COMMAND_DEEP_REFRESH,
    COMMAND_DOORS_LOCK,
    COMMAND_HVAC_ON,
    COMMAND_REFRESH_LOCATION,
    hvac_params,
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

NOW = datetime(2026, 1, 1, tzinfo=UTC)
NOW_MS = 1767225600000
WEEK_MS = 7 * 24 * 3600 * 1000

# (API method, args, HTTP method, URL, request body, query)
ENDPOINTS: list[tuple[str, tuple[Any, ...], str, str, Any, dict[str, str]]] = [
    ("get_remote_status", (VIN,), "GET", vehicle_url("v1", "remote/status/"), None, {}),
    (
        "get_vehicle_location",
        (VIN,),
        "GET",
        vehicle_url("v1", "location/lastknown/"),
        None,
        {},
    ),
    ("get_vehicle_health_report", (VIN,), "GET", vehicle_url("v1", "vhr/"), None, {}),
    (
        "get_vehicle_image",
        (VIN, 100, 50),
        "POST",
        vehicle_url("v4", "image/"),
        {"imageURLs": [{"id": VIN, "width": 100, "height": 50, "resp": "png"}]},
        {},
    ),
    (
        "get_vehicle_equipment",
        (VIN,),
        "GET",
        vehicle_url("v1", "digitalglovebox/vehicleequipment/equipment/"),
        None,
        {},
    ),
    (
        "get_vehicle_preferences",
        (VIN,),
        "GET",
        vehicle_url("v1", "preferences/"),
        None,
        {},
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
        "get_maintenance_history",
        (VIN,),
        "GET",
        vehicle_url("v1", "maintenance/history/"),
        None,
        {},
    ),
    (
        "get_recommended_maintenance",
        ("IT", "it", "FIAT", "500e", 2023),
        "GET",
        api_url("/v1/maintenance/recommended/"),
        None,
        {
            "market": "IT",
            "language": "it",
            "brand": "FIAT",
            "model": "500e",
            "year": "2023",
        },
    ),
    ("get_recalls", (VIN,), "GET", vehicle_url("v1", "recall/"), None, {}),
    (
        "dismiss_recalls",
        (VIN, ["C1", "C2"]),
        "POST",
        vehicle_url("v1", "recall/dismiss/"),
        {"dismissItems": ["C1", "C2"]},
        {},
    ),
    (
        "get_vehicle_notifications",
        (VIN,),
        "GET",
        vehicle_url("v1", "notifications/"),
        None,
        {},
    ),
    (
        "get_vehicle_notifications",
        (VIN, 20),
        "GET",
        vehicle_url("v1", "notifications/"),
        None,
        {"offset": "20"},
    ),
    (
        "get_account_notifications",
        (NOW, NOW_MS + 1),
        "GET",
        api_url("/v2/accounts/{uid}/notifications/"),
        None,
        {"brand": "FIAT", "since": str(NOW_MS), "till": str(NOW_MS + 1)},
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
        "get_remote_operation_last_status",
        (VIN, "CID"),
        "GET",
        vehicle_url("v1", "remote/CID/last-status/"),
        None,
        {},
    ),
    (
        "get_remote_climate_configuration",
        (VIN,),
        "GET",
        vehicle_url("v1", "remote/custom/configurations/"),
        None,
        {},
    ),
    (
        "get_trips",
        (VIN, {"a": 1}),
        "GET",
        vehicle_url("v2", "tripreport/trips/"),
        None,
        {"a": "1"},
    ),
    (
        "get_last_trip",
        (VIN,),
        "GET",
        vehicle_url("v2", "tripreport/trips/last/"),
        None,
        {},
    ),
    (
        "get_trip",
        (VIN, "T1"),
        "GET",
        vehicle_url("v2", "tripreport/trips/T1/"),
        None,
        {},
    ),
    (
        "get_trip_summary",
        (VIN, "weekly"),
        "GET",
        vehicle_url("v2", "tripreport/summary/weekly/"),
        None,
        {},
    ),
    (
        "get_trip_report_settings",
        (VIN,),
        "GET",
        vehicle_url("v2", "tripreport/settings/"),
        None,
        {},
    ),
    (
        "get_eco_coaching_profiles",
        (VIN,),
        "GET",
        vehicle_url("v2", "ecocoaching/profiles/"),
        None,
        {},
    ),
    (
        "get_eco_coaching_last_trip",
        (VIN,),
        "POST",
        vehicle_url("v2", "ecocoaching/get-last-trip/"),
        {},
        {},
    ),
    (
        "get_eco_coaching_last_trip",
        (VIN, "ECO"),
        "POST",
        vehicle_url("v2", "ecocoaching/get-last-trip/"),
        {"profile": "ECO"},
        {},
    ),
    (
        "get_eco_coaching_best_trip",
        (VIN, "ECO"),
        "POST",
        vehicle_url("v2", "ecocoaching/get-best-trip/"),
        {"profile": "ECO"},
        {},
    ),
    (
        "get_eco_coaching_trips",
        (VIN, None, NOW),
        "POST",
        vehicle_url("v2", "ecocoaching/get-trips/"),
        {"since": NOW_MS - WEEK_MS, "till": NOW_MS, "offset": 0, "size": 100},
        {},
    ),
    (
        "get_eco_coaching_trips",
        (VIN, 1, 2, 3, 4, "P"),
        "POST",
        vehicle_url("v2", "ecocoaching/get-trips/"),
        {"since": 1, "till": 2, "offset": 3, "size": 4, "profile": "P"},
        {},
    ),
    (
        "get_eco_coaching_monthly",
        (VIN, NOW),
        "POST",
        vehicle_url("v2", "ecocoaching/get-trips/monthly/"),
        {"since": 0, "till": NOW_MS, "offset": 0, "size": 100},
        {},
    ),
    (
        "get_eco_coaching_daily",
        (VIN,),
        "POST",
        vehicle_url("v2", "ecocoaching/get-trips/daily/"),
        None,
        {},
    ),
    (
        "get_eco_coaching_suggestions",
        (VIN,),
        "GET",
        vehicle_url("v2", "ecocoaching/suggestions/"),
        None,
        {},
    ),
    (
        "get_eco_coaching_history",
        (VIN, "month", None, 5, 0, 100),
        "GET",
        vehicle_url("v1", "ecocoaching/"),
        None,
        {"groupby": "month", "till": "5", "offset": "0", "limit": "100"},
    ),
    (
        "get_drive_alerts",
        (VIN,),
        "GET",
        vehicle_url("v3", "parentalcontrols/config/"),
        None,
        {},
    ),
    (
        "get_theft_alarm_status",
        (VIN,),
        "GET",
        vehicle_url("v1", "theft/status/"),
        None,
        {},
    ),
]


@pytest.mark.parametrize(
    ("name", "args", "method", "url", "body", "query"),
    ENDPOINTS,
    ids=[f"{x[0]}-{i}" for i, x in enumerate(ENDPOINTS)],
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


def test_all_endpoints_are_tested() -> None:
    tested = {x[0] for x in ENDPOINTS}
    others = {
        # Tested separately below
        "list_vehicles",
        "get_vehicle_info",
        "pin_auth",
        "command",
        "send_destination",
        "set_charge_schedules",
        "set_charging_level",
        "set_drive_alerts",
        "set_theft_alarm_notifications",
        # Not endpoints
        "request",
        "login",
        "close",
    }
    public = {
        x for x in dir(API) if not x.startswith("_") and callable(getattr(API, x))
    }

    assert public - tested - others == set()


async def test_request_headers(http: MockSession, api: API) -> None:
    mock_login(http)
    http.get(vehicle_url("v1", "remote/status/"), payload={})

    await api.get_remote_status(VIN)

    (call,) = http.calls_to("GET", vehicle_url("v1", "remote/status/"))
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
    url = api_url("/v4/accounts/{uid}/vehicles/")
    http.get(url, payload={"userid": UID, "vehicles": [{"vin": VIN}]})

    assert await api.list_vehicles() == [{"vin": VIN}]

    (call,) = http.calls_to("GET", url)
    assert call.query == {"stage": "ALL", "sdp": "ALL", "brand": FIAT_EU.brand_code}


async def test_list_vehicles_invalid_response(http: MockSession, api: API) -> None:
    mock_login(http)
    http.get(api_url("/v4/accounts/{uid}/vehicles/"), payload={"foo": 1})

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
    http.put(url, payload=[1])

    r = await api.request(
        "PUT",
        f"/v2/accounts/{{uid}}/vehicles/{VIN}/something/",
        params={"a": 1},
        body={"b": 2},
    )

    assert r == [1]
    (call,) = http.calls_to("PUT", url)
    assert call.query == {"a": "1"}
    assert call.json == {"b": 2}


# Vehicle status


async def test_vehicle_info_v3(http: MockSession, api: API) -> None:
    mock_login(http)
    http.get(vehicle_url("v3", "status/"), payload={"v": 3})

    assert await api.get_vehicle_info(VIN) == {"v": 3}


async def test_vehicle_info_preferred_version(http: MockSession, api: API) -> None:
    mock_login(http)
    http.get(vehicle_url("v4", "status/"), payload={"v": 4})

    assert await api.get_vehicle_info(VIN, "v4") == {"v": 4}


@pytest.mark.parametrize("status", [400, 404, 502])
async def test_vehicle_info_falls_back(
    http: MockSession, api: API, status: int
) -> None:
    mock_login(http)
    http.get(vehicle_url("v3", "status/"), status=status)
    http.get(vehicle_url("v4", "status/"), payload={"v": 4}, repeat=True)

    assert await api.get_vehicle_info(VIN) == {"v": 4}
    # The working version is remembered
    assert await api.get_vehicle_info(VIN, "v3") == {"v": 4}
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


async def test_pin_auth_token_is_cached(http: MockSession, api: API) -> None:
    mock_login(http)
    mock_pin_auth(http, repeat=True)

    assert await api.pin_auth() == PIN_TOKEN
    assert await api.pin_auth() == PIN_TOKEN
    assert len(http.calls_to("POST", pin_auth_url())) == 1

    # Changing the PIN drops the cached token
    api.pin = "9999"
    assert await api.pin_auth() == PIN_TOKEN
    assert len(http.calls_to("POST", pin_auth_url())) == 2


async def test_pin_auth_without_expiry_is_not_cached(
    http: MockSession, api: API
) -> None:
    mock_login(http)
    mock_pin_auth(http, payload={"token": PIN_TOKEN}, repeat=True)

    await api.pin_auth()
    await api.pin_auth()

    assert len(http.calls_to("POST", pin_auth_url())) == 2


async def test_pin_auth_uses_vehicle_sdp(http: MockSession, api: API) -> None:
    mock_login(http)
    http.get(
        api_url("/v4/accounts/{uid}/vehicles/"),
        payload={"vehicles": [{"vin": VIN, "sdp": "SXM"}, {"vin": "OTHER"}]},
    )
    mock_pin_auth(http, sdp="SXM")
    mock_pin_auth(http, sdp="ignite")

    await api.list_vehicles()
    await api.pin_auth(VIN)
    await api.pin_auth("OTHER")

    assert len(http.calls_to("POST", pin_auth_url(sdp="SXM"))) == 1
    assert len(http.calls_to("POST", pin_auth_url(sdp="ignite"))) == 1


async def test_pin_auth_without_pin(http: MockSession, api: API) -> None:
    api.pin = None

    with pytest.raises(PinAuthenticationError, match="PIN is required"):
        await api.pin_auth()

    assert not http.calls


@pytest.mark.parametrize(
    ("status", "payload"),
    [(401, {"message": "wrong pin"}), (423, {"message": "locked"}), (200, {"x": 1})],
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
        (COMMAND_DOORS_LOCK, vehicle_url("v1", "remote/")),
        (COMMAND_HVAC_ON, vehicle_url("v2", "remote/")),
        (COMMAND_CHARGE, vehicle_url("v1", "ev/chargenow/")),
        (COMMAND_DEEP_REFRESH, vehicle_url("v1", "ev/")),
        (COMMAND_REFRESH_LOCATION, vehicle_url("v1", "location/")),
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


async def test_command_with_params(http: MockSession, api: API) -> None:
    mock_login(http)
    mock_pin_auth(http)
    http.post(vehicle_url("v2", "remote/"), payload=PENDING)

    await api.command(VIN, COMMAND_HVAC_ON, hvac_params(21.5))

    (call,) = http.calls_to("POST", vehicle_url("v2", "remote/"))
    assert call.json == {
        "command": "ROHVACON",
        "pinAuth": PIN_TOKEN,
        "params": {
            "interiorTemperature": 22,
            "temperatureUOM": "Celsius",
            "fanSpeed": 50,
            "targetTemp": 21.5,
            "timeoutAfterTemp": 0,
            "preTripTimeout": 15,
        },
    }


async def test_command_not_accepted(http: MockSession, api: API) -> None:
    mock_login(http)
    mock_pin_auth(http)
    http.post(
        vehicle_url("v1", "remote/"),
        payload={"responseStatus": "failure", "debugMsg": "vehicle asleep"},
    )

    with pytest.raises(CommandError, match="vehicle asleep"):
        await api.command(VIN, COMMAND_DOORS_LOCK)


@pytest.mark.parametrize("status", [400, 403, 404])
async def test_command_fallback(http: MockSession, api: API, status: int) -> None:
    mock_login(http)
    mock_pin_auth(http)
    http.post(vehicle_url("v1", "ev/chargenow/"), status=status)
    http.post(vehicle_url("v4", "ev/chargenow/"), payload=PENDING)

    assert await api.command(VIN, COMMAND_CHARGE) == "CID"

    (call,) = http.calls_to("POST", vehicle_url("v4", "ev/chargenow/"))
    assert call.json == {"command": "START_CHARGE", "pinAuth": PIN_TOKEN}


async def test_command_fallback_chain(http: MockSession, api: API) -> None:
    mock_login(http)
    mock_pin_auth(http)
    http.post(vehicle_url("v1", "ev/"), status=403)
    http.post(vehicle_url("v2", "ev/"), status=400)
    http.post(vehicle_url("v2", "ev/"), payload=PENDING)

    assert await api.command(VIN, COMMAND_DEEP_REFRESH) == "CID"

    calls = http.calls_to("POST", vehicle_url("v2", "ev/"))
    assert [c.json["command"] for c in calls] == ["DEEPREFRESH", "DEEPREFRESH2"]


async def test_command_error_without_fallback(http: MockSession, api: API) -> None:
    mock_login(http)
    mock_pin_auth(http)
    http.post(vehicle_url("v1", "remote/"), status=403)

    with pytest.raises(APIError) as err:
        await api.command(VIN, COMMAND_DOORS_LOCK)

    assert err.value.status == 403


async def test_command_server_error_does_not_fall_back(
    http: MockSession, api: API
) -> None:
    mock_login(http)
    mock_pin_auth(http)
    http.post(vehicle_url("v1", "ev/chargenow/"), status=500)

    with pytest.raises(APIError):
        await api.command(VIN, COMMAND_CHARGE)

    assert not http.calls_to("POST", vehicle_url("v4", "ev/chargenow/"))


async def test_send_destination(http: MockSession, api: API) -> None:
    mock_login(http)
    url = vehicle_url("v2", "sdv/location/")
    http.post(url, payload={"command": "SDV", **PENDING})

    cid = await api.send_destination(
        VIN, 45.0, 7.6, "Home", address={"cityName": "Turin"}, phoneNumber="123"
    )

    assert cid == "CID"
    (call,) = http.calls_to("POST", url)
    assert call.json == {
        "command": "SDV",
        "params": {
            "location": {
                "latitude": 45.0,
                "longitude": 7.6,
                "name": "Home",
                "address": {"cityName": "Turin"},
                "phoneNumber": "123",
            },
            "routePreference": "Fast",
        },
    }


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


@pytest.mark.parametrize(
    ("command", "url", "field"),
    [
        ("CPCOOP", vehicle_url("v4", "ev/schedule/"), "chargeSchedulesV4"),
        ("CPPLUSBEV", vehicle_url("v3", "ev/schedule/"), "chargeSchedulesV3"),
        ("BCPCHRG", vehicle_url("v3", "ev/schedule/"), "chargeSchedulesV3"),
        ("CPPLUS", vehicle_url("v2", "ev/schedule/"), "schedules"),
        ("CP", vehicle_url("v1", "ev/chargeschedule/"), "chargeSchedules"),
    ],
)
async def test_set_charge_schedules(
    http: MockSession, api: API, command: str, url: str, field: str
) -> None:
    mock_login(http)
    mock_pin_auth(http)
    http.post(url, payload=PENDING)

    schedules = [{"startTime": "01:00", "endTime": "05:00"}]
    assert await api.set_charge_schedules(VIN, command, schedules) == "CID"

    (call,) = http.calls_to("POST", url)
    assert call.json == {"command": command, "pinAuth": PIN_TOKEN, field: schedules}


async def test_set_charge_schedules_unknown_command(api: API) -> None:
    with pytest.raises(ValueError, match="unknown schedule command"):
        await api.set_charge_schedules(VIN, "FOO", [])


async def test_set_charge_schedules_rejected(http: MockSession, api: API) -> None:
    mock_login(http)
    mock_pin_auth(http)
    http.post(vehicle_url("v2", "ev/schedule/"), payload={"debugMsg": "nope"})

    with pytest.raises(CommandError, match="nope"):
        await api.set_charge_schedules(VIN, "CPPLUS", [])


# Drive alerts and theft alarm


async def test_set_drive_alerts(http: MockSession, api: API) -> None:
    mock_login(http)
    mock_pin_auth(http)
    url = vehicle_url("v4", "parentalcontrols/config/")
    http.post(url, payload={"correlationId": "CID", "alertConfigs": []})

    alerts = {"speed": [{"name": "Fast", "thresholdAbsolute": 120}]}
    assert await api.set_drive_alerts(VIN, alerts) == "CID"

    (call,) = http.calls_to("POST", url)
    assert call.json == alerts | {"pinAuth": PIN_TOKEN}


@pytest.mark.parametrize(
    ("enabled", "suppression", "body"),
    [
        (True, None, {"enabled": True}),
        (
            False,
            TheftAlarmSuppression.ONE_DAY,
            {"enabled": False, "suspensionDuration": "TWENTYFOURHRS"},
        ),
    ],
)
async def test_set_theft_alarm_notifications(
    http: MockSession,
    api: API,
    enabled: bool,
    suppression: TheftAlarmSuppression | None,
    body: dict[str, Any],
) -> None:
    mock_login(http)
    mock_pin_auth(http)
    url = vehicle_url("v1", "theft/alarm/")
    http.post(url, payload={"correlationId": "CID", "requestStatus": "PENDING"})

    assert await api.set_theft_alarm_notifications(VIN, enabled, suppression) == "CID"

    (call,) = http.calls_to("POST", url)
    assert call.json == body | {"pinAuth": PIN_TOKEN}
