from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from py_uconnect import ChargingLevel, Vehicle
from py_uconnect.command import COMMAND_CHARGE, COMMAND_DOORS_LOCK, COMMAND_ENGINE_ON
from py_uconnect.models import (
    apply_list_item,
    apply_remote_status,
    apply_vehicle_info,
    get_bool,
    get_eq,
    get_float,
    get_int,
    get_str,
    get_timestamp,
    parse_location,
)

from .conftest import load_fixture

EV_VIN = "ZFAEFAC39MX000001"
ICE_VIN = "1C4HJXEN5MW000002"


def list_item(vin: str) -> dict:
    return next(x for x in load_fixture("vehicles.json")["vehicles"] if x["vin"] == vin)


def ev() -> Vehicle:
    v = Vehicle(vin=EV_VIN)
    apply_list_item(v, list_item(EV_VIN))
    apply_vehicle_info(v, load_fixture("status_ev.json"))
    return v


# Typed getters


@pytest.mark.parametrize(
    ("value", "expected"),
    [("12.5", 12.5), (3, 3.0), ("x", None), (None, None), ("null", None), (True, None)],
)
def test_get_float(value: object, expected: float | None) -> None:
    assert get_float({"a": {"b": value}}, "a", "b") == expected


@pytest.mark.parametrize(
    ("value", "expected"), [("12", 12), ("12.6", 13), (7.2, 7), ("", None)]
)
def test_get_int(value: object, expected: int | None) -> None:
    assert get_int({"a": value}, "a") == expected


def test_get_str_keeps_numeric_strings() -> None:
    assert get_str({"a": "500"}, "a") == "500"
    assert get_str({"a": 500}, "a") == "500"
    assert get_str({"a": {"b": 1}}, "a") is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [(True, True), ("false", False), ("TRUE", True), (1, None), ("yes", None)],
)
def test_get_bool(value: object, expected: bool | None) -> None:
    assert get_bool({"a": value}, "a") == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("LOCKED", True),
        ("locked", True),
        ("UNLOCKED", False),
        ("NA", None),
        (None, None),
    ],
)
def test_get_eq(value: object, expected: bool | None) -> None:
    assert get_eq({"s": value}, "LOCKED", "s") == expected


def test_getters_handle_wrong_types() -> None:
    assert get_float(None, "a") is None
    assert get_float([1], "a") is None
    assert get_float({"a": [10, 20]}, "a", 1) == 20
    assert get_float({"a": [10]}, "a", 5) is None
    assert get_timestamp({"t": 1738660203634}, "t") == datetime(
        2025, 2, 4, 9, 10, 3, 634000, tzinfo=UTC
    )


# Vehicle list


def test_list_item() -> None:
    v = Vehicle(vin=EV_VIN)
    apply_list_item(v, list_item(EV_VIN))

    # Numeric-looking strings are kept as strings
    assert v.nickname == "500"
    assert v.make == "FIAT"
    assert v.model == "Neuer 500"
    assert v.year == 2023
    assert v.region == "EMEA"
    assert v.sdp == "IGNITE"
    assert v.fuel_type == "E"
    assert v.privacy_mode == "INACTIVE"
    assert v.image_url == "https://example.com/vehicle/500e.png"

    # Disabled or incapable services are skipped
    assert "ROHVACON" not in v.enabled_services
    assert "REON" not in v.enabled_services
    assert "SVLA" in v.enabled_services

    # CNOW2 and DEEPREFRESH2 enable the charge and deep refresh commands
    assert v.supported_commands == [
        "RDL",
        "RDU",
        "ROLIGHTS",
        "ROPRECOND",
        "ROPRECOND_OFF",
        "ROTRUNKUNLOCK",
        "VF",
        "DEEPREFRESH",
        "CNOW",
    ]
    assert v.supports(COMMAND_CHARGE)
    assert v.supports(COMMAND_DOORS_LOCK)
    assert not v.supports(COMMAND_ENGINE_ON)


def test_list_item_with_status_snapshot() -> None:
    v = Vehicle(vin=ICE_VIN)
    apply_list_item(v, list_item(ICE_VIN))

    assert v.sdp == "SXM"
    # String booleans are accepted
    assert "VF" in v.enabled_services
    assert v.odometer == 11990
    assert v.odometer_unit == "mi"
    assert v.distance_to_empty == 400
    assert v.fuel_amount == 50.0
    assert v.timestamp_info == datetime.fromtimestamp(1738660000, UTC)
    # The snapshot is not the raw detailed status
    assert v.raw_info is None
    assert v.location is not None
    assert v.location.is_approximate is True


# Vehicle status


def test_vehicle_info_ev() -> None:
    v = ev()

    assert v.raw_info == load_fixture("status_ev.json")
    assert v.battery_voltage == 14.875
    assert v.battery_state_of_charge == "NORMAL"
    assert v.odometer == 1841
    assert v.odometer_unit == "km"
    assert v.days_to_service == 325
    assert v.distance_to_service == 13159
    assert v.distance_to_service_unit == "km"
    # The EV range is preferred over the empty fuel range
    assert v.distance_to_empty == 134
    assert v.distance_to_empty_unit == "km"
    assert v.range_total == 134
    assert v.range_gas is None
    assert v.fuel_amount is None
    assert v.oil_level is None

    assert v.charging is True
    assert v.charging_level == 2
    assert v.charging_level_preference is ChargingLevel.LEVEL_FIVE
    assert v.plugged_in is True
    assert v.state_of_charge == 63
    assert v.time_to_fully_charge_l1 is None
    assert v.time_to_fully_charge_l2 == 96
    assert v.time_to_fully_charge_l3 == 41
    assert v.ev_cabin_cond is True
    assert v.ev_head_seat is False
    assert v.ignition_on is False

    # Schedules come from the field of the vehicle's schedule service
    assert v.charge_schedules is not None
    assert [s["scheduleType"] for s in v.charge_schedules] == ["CHARGE", "CLIMATE"]

    assert v.wheel_front_left_pressure == 250
    assert v.wheel_front_left_pressure_unit == "kPa"
    assert v.wheel_front_left_pressure_warning is False
    assert v.wheel_rear_right_pressure is None
    assert v.timestamp_info == datetime.fromtimestamp(1738660203.634, UTC)


def test_vehicle_info_ice() -> None:
    v = Vehicle(vin=ICE_VIN)
    apply_list_item(v, list_item(ICE_VIN))
    apply_vehicle_info(v, load_fixture("status_ice.json"))

    assert v.odometer == 12000.4
    assert v.days_to_service is None
    assert v.distance_to_empty == 410
    assert v.distance_to_empty_unit == "mi"
    assert v.fuel_amount == 52.5
    assert v.fuel_low is False
    assert v.oil_level == 80
    assert v.ignition_on is True
    assert v.charging is None
    assert v.charging_level is None
    assert v.plugged_in is None
    # NOT_USED_VALUE
    assert v.charging_level_preference is None
    assert v.charge_schedules is None
    assert v.wheel_rear_left_pressure == 28
    assert v.wheel_rear_left_pressure_unit == "psi"
    assert v.wheel_rear_left_pressure_warning is True


def test_vehicle_info_empty() -> None:
    v = Vehicle(vin=EV_VIN)
    apply_vehicle_info(v, {})

    assert v.odometer is None
    assert v.timestamp_info is None


@pytest.mark.parametrize(
    ("battery", "fuel", "expected"),
    [
        # Combustion vehicles and PHEVs with an empty battery report 0
        ({"unit": "km", "value": "0"}, {"unit": "km", "value": "410"}, (410, "km")),
        ({"unit": "mi", "value": 0}, {"unit": "mi", "value": "255"}, (255, "mi")),
        ({"unit": "km", "value": "0"}, {"unit": "km", "value": None}, (None, "km")),
        ({"unit": "km", "value": None}, {"unit": "km", "value": "410"}, (410, "km")),
        (None, {"unit": "km", "value": "410"}, (410, "km")),
        ({"unit": "km", "value": "35"}, {"unit": "km", "value": "410"}, (35, "km")),
        ({"unit": "km", "value": "134"}, None, (134, "km")),
    ],
)
def test_distance_to_empty(
    battery: dict | None, fuel: dict | None, expected: tuple[float | None, str]
) -> None:
    """The battery range unless missing or zero, then the fuel range, like 0.x"""

    v = Vehicle(vin=ICE_VIN)
    apply_vehicle_info(
        v,
        {
            "vehicleInfo": {"fuel": {"distanceToEmpty": fuel}},
            "evInfo": {"battery": {"distanceToEmpty": battery}},
        },
    )

    assert (v.distance_to_empty, v.distance_to_empty_unit) == expected


# Remote status and location


def test_remote_status() -> None:
    v = Vehicle(vin=EV_VIN)
    apply_remote_status(v, load_fixture("remote_status.json"))

    assert v.door_driver_locked is True
    assert v.door_passenger_locked is True
    assert v.door_rear_left_locked is False
    assert v.door_rear_right_locked is None
    assert v.window_driver_closed is True
    assert v.window_passenger_closed is False
    assert v.window_rear_left_closed is True
    assert v.window_rear_right_closed is True
    assert v.sunroof_closed is None
    assert v.trunk_locked is True
    assert v.liftgate_locked is False
    assert v.ignition_on is False
    assert v.ev_running is False
    assert v.hvac_on is True
    assert v.hvac_temperature == 21.5
    assert v.hvac_temperature_unit == "C"
    assert v.timestamp_status == datetime.fromtimestamp(1738660300, UTC)


def test_remote_status_partial() -> None:
    v = Vehicle(vin=EV_VIN, ignition_on=True)
    apply_remote_status(v, {"doors": {"driver": {"status": "UNLOCKED"}}})

    assert v.door_driver_locked is False
    assert v.door_passenger_locked is None
    # Not reported, left as is
    assert v.ignition_on is True


def test_location() -> None:
    loc = parse_location(load_fixture("location.json"))

    assert loc.latitude == 45.0703
    assert loc.longitude == 7.6869
    assert loc.altitude == 239
    assert loc.bearing == 0
    assert loc.is_approximate is False
    assert loc.updated == datetime.fromtimestamp(1738660203.634, UTC)
    assert "45.0703" in repr(loc)


# Serialization


def test_to_dict_and_json() -> None:
    v = ev()
    v.location = parse_location(load_fixture("location.json"))

    d = v.to_dict()
    assert d["vin"] == EV_VIN
    assert d["charging_level_preference"] == "LEVEL_FIVE"
    assert d["timestamp_info"] == "2025-02-04T09:10:03.634000+00:00"
    assert d["location"]["updated"] == "2025-02-04T09:10:03.634000+00:00"
    assert not any(k.startswith("raw_") for k in d)

    assert v.to_dict(raw=True)["raw_info"] == load_fixture("status_ev.json")
    assert json.loads(v.to_json(indent=2)) == d
    assert repr(v) == f"{EV_VIN} (nick: 500)"
