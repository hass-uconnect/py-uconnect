"""Data models and parsing of API responses into them"""

from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum, StrEnum
from typing import Any

from .command import COMMANDS_BY_NAME, Command


class ChargingLevel(StrEnum):
    """Charging power preference of an EV (``chargePowerPreference``)"""

    LEVEL_ONE = "LEVEL_ONE"
    LEVEL_TWO = "LEVEL_TWO"
    LEVEL_THREE = "LEVEL_THREE"
    LEVEL_FOUR = "LEVEL_FOUR"
    LEVEL_FIVE = "LEVEL_FIVE"


# Charging level reported while charging (``evInfo.battery.chargingLevel``)
CHARGING_LEVEL_REPORTED = {
    "DEFAULT": 0,
    "LEVEL_1": 1,
    "LEVEL_2": 2,
    "LEVEL_3": 3,
}


# Typed accessors for the loosely typed JSON returned by the API. Numbers and
# booleans are often sent as strings, missing values sometimes as "null".


def _get(d: Any, *keys: str | int) -> Any:
    for key in keys:
        if isinstance(d, dict):
            d = d.get(key)
        elif isinstance(d, list) and isinstance(key, int) and -len(d) <= key < len(d):
            d = d[key]
        else:
            return None

    return None if d == "null" else d


def get_str(d: Any, *keys: str | int) -> str | None:
    """Gets a nested value as a string"""

    v = _get(d, *keys)
    if v is None or isinstance(v, dict | list):
        return None

    return str(v)


def get_float(d: Any, *keys: str | int) -> float | None:
    """Gets a nested value as a float"""

    v = _get(d, *keys)
    if isinstance(v, bool):
        return None

    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def get_int(d: Any, *keys: str | int) -> int | None:
    """Gets a nested value as an integer (floats are rounded)"""

    v = get_float(d, *keys)
    return round(v) if v is not None else None


def get_bool(d: Any, *keys: str | int) -> bool | None:
    """Gets a nested value as a boolean"""

    v = _get(d, *keys)
    if isinstance(v, bool):
        return v

    if isinstance(v, str) and v.lower() in ("true", "false"):
        return v.lower() == "true"

    return None


def get_eq(d: Any, expected: str, *keys: str | int) -> bool | None:
    """Whether a nested string value equals the expected one (case-insensitive).

    Returns None if the value is missing.
    """

    v = get_str(d, *keys)
    return v.upper() == expected.upper() if v is not None else None


def get_timestamp(d: Any, *keys: str | int) -> datetime | None:
    """Gets a nested millisecond Unix timestamp as a UTC datetime"""

    v = get_float(d, *keys)
    return datetime.fromtimestamp(v / 1000, UTC) if v is not None else None


def _non_negative(v: int | None) -> int | None:
    # Some vehicles report -1 for unavailable values
    return v if v is not None and v >= 0 else None


def _to_jsonable(v: Any) -> Any:
    if isinstance(v, datetime):
        return v.isoformat()
    if isinstance(v, Enum):
        return v.value
    if isinstance(v, dict):
        return {k: _to_jsonable(x) for k, x in v.items()}
    if isinstance(v, list | tuple):
        return [_to_jsonable(x) for x in v]
    return v


class _Serializable:
    def to_dict(self, raw: bool = False) -> dict[str, Any]:
        """Converts to a JSON-compatible dict. ``raw_*`` fields are only
        included if ``raw`` is set."""

        assert dataclasses.is_dataclass(self)
        d = {
            f.name: getattr(self, f.name)
            for f in dataclasses.fields(self)
            if raw or not f.name.startswith("raw_")
        }
        return {
            k: (v.to_dict(raw) if isinstance(v, _Serializable) else _to_jsonable(v))
            for k, v in d.items()
        }

    def to_json(self, raw: bool = False, **kwargs: Any) -> str:
        """Serializes to JSON, keyword arguments are passed to ``json.dumps``"""

        return json.dumps(self.to_dict(raw), **kwargs)


@dataclass
class Location(_Serializable):
    """Last known location of a vehicle"""

    latitude: float | None = None
    longitude: float | None = None
    altitude: float | None = None
    bearing: float | None = None
    is_approximate: bool | None = None
    updated: datetime | None = None

    def __repr__(self) -> str:
        return f"lat: {self.latitude}, lon: {self.longitude} (updated {self.updated})"


@dataclass
class Vehicle(_Serializable):
    """Vehicle data collected from several API endpoints"""

    vin: str

    # General info (vehicle list)
    nickname: str | None = None
    make: str | None = None
    model: str | None = None
    year: int | None = None
    region: str | None = None
    sdp: str | None = None
    image_url: str | None = None
    fuel_type: str | None = None

    # Status
    ignition_on: bool | None = None
    trunk_locked: bool | None = None

    odometer: float | None = None
    odometer_unit: str | None = None
    days_to_service: int | None = None
    distance_to_service: float | None = None
    distance_to_service_unit: str | None = None
    distance_to_empty: float | None = None
    distance_to_empty_unit: str | None = None
    range_gas: float | None = None
    range_gas_unit: str | None = None
    range_total: float | None = None
    range_total_unit: str | None = None
    battery_voltage: float | None = None
    battery_state_of_charge: str | None = None
    oil_level: int | None = None
    fuel_low: bool | None = None
    fuel_amount: int | None = None

    # EV related
    plugged_in: bool | None = None
    ev_running: bool | None = None
    charging: bool | None = None
    charging_level: int | None = None
    charging_level_preference: ChargingLevel | None = None
    state_of_charge: float | None = None
    time_to_fully_charge_l3: int | None = None
    time_to_fully_charge_l2: int | None = None
    time_to_fully_charge_l1: int | None = None
    ev_head_seat: bool | None = None
    ev_cabin_cond: bool | None = None

    # Wheels
    wheel_front_left_pressure: float | None = None
    wheel_front_left_pressure_unit: str | None = None
    wheel_front_left_pressure_warning: bool | None = None
    wheel_front_right_pressure: float | None = None
    wheel_front_right_pressure_unit: str | None = None
    wheel_front_right_pressure_warning: bool | None = None
    wheel_rear_left_pressure: float | None = None
    wheel_rear_left_pressure_unit: str | None = None
    wheel_rear_left_pressure_warning: bool | None = None
    wheel_rear_right_pressure: float | None = None
    wheel_rear_right_pressure_unit: str | None = None
    wheel_rear_right_pressure_warning: bool | None = None

    # Doors
    door_driver_locked: bool | None = None
    door_passenger_locked: bool | None = None
    door_rear_left_locked: bool | None = None
    door_rear_right_locked: bool | None = None

    # Windows
    window_driver_closed: bool | None = None
    window_passenger_closed: bool | None = None

    location: Location | None = None

    # Names of the services that the vehicle is capable of and are enabled
    enabled_services: list[str] = field(default_factory=list)
    # Subset of enabled services that are known remote commands
    supported_commands: list[str] = field(default_factory=list)

    timestamp_info: datetime | None = None
    timestamp_status: datetime | None = None

    # Raw API responses the data was parsed from
    raw_list_item: dict[str, Any] | None = field(default=None, repr=False)
    raw_info: dict[str, Any] | None = field(default=None, repr=False)
    raw_remote_status: dict[str, Any] | None = field(default=None, repr=False)
    raw_location: dict[str, Any] | None = field(default=None, repr=False)

    def __repr__(self) -> str:
        return f"{self.vin} (nick: {self.nickname})"

    def supports(self, cmd: Command) -> bool:
        """Whether the vehicle supports the given command"""

        return cmd.name in self.supported_commands


def apply_list_item(v: Vehicle, p: dict[str, Any]) -> None:
    """Updates the vehicle from its item in the vehicle list"""

    v.raw_list_item = p
    v.nickname = get_str(p, "nickname")
    v.make = get_str(p, "make")
    v.model = get_str(p, "modelDescription")
    v.year = get_int(p, "tsoModelYear")
    v.region = get_str(p, "soldRegion")
    v.sdp = get_str(p, "sdp")
    v.image_url = get_str(p, "vehicleImageURL")
    v.fuel_type = get_str(p, "fuelType")

    services = p.get("services")
    v.enabled_services = [
        s["service"]
        for s in (services if isinstance(services, list) else [])
        if isinstance(s, dict)
        and isinstance(s.get("service"), str)
        and get_bool(s, "vehicleCapable")
        and get_bool(s, "serviceEnabled")
    ]
    v.supported_commands = [s for s in v.enabled_services if s in COMMANDS_BY_NAME]


def _charging_level_preference(v: str | None) -> ChargingLevel | None:
    try:
        return ChargingLevel(v) if v is not None else None
    except ValueError:
        # e.g. NOT_USED_VALUE
        return None


def apply_vehicle_info(v: Vehicle, p: dict[str, Any]) -> None:
    """Updates the vehicle from the vehicle status (``vehicleInfo``/``evInfo``)"""

    v.raw_info = p
    vi = _get(p, "vehicleInfo")
    ev = _get(p, "evInfo")
    batt = _get(ev, "battery")

    v.battery_voltage = get_float(vi, "batteryInfo", "batteryVoltage", "value")
    v.battery_state_of_charge = get_str(vi, "batteryInfo", "batteryStateOfCharge")

    v.charging = get_eq(batt, "CHARGING", "chargingStatus")
    v.charging_level = CHARGING_LEVEL_REPORTED.get(get_str(batt, "chargingLevel") or "")
    v.charging_level_preference = _charging_level_preference(
        get_str(ev, "chargePowerPreference")
    )
    v.plugged_in = get_bool(batt, "plugInStatus")
    v.state_of_charge = get_float(batt, "stateOfCharge")

    v.days_to_service = get_int(vi, "daysToService")
    v.distance_to_service = get_float(
        vi, "distanceToService", "distanceToService", "value"
    )
    v.distance_to_service_unit = get_str(
        vi, "distanceToService", "distanceToService", "unit"
    )

    if get_float(batt, "distanceToEmpty", "value") is not None:
        dte = _get(batt, "distanceToEmpty")
    else:
        dte = _get(vi, "fuel", "distanceToEmpty")
    v.distance_to_empty = get_float(dte, "value")
    v.distance_to_empty_unit = get_str(dte, "unit")

    v.range_gas = get_float(batt, "gasRange")
    v.range_gas_unit = v.distance_to_empty_unit
    v.range_total = get_float(batt, "totalRange")
    v.range_total_unit = v.distance_to_empty_unit

    v.fuel_low = get_bool(vi, "fuel", "isFuelLevelLow")
    v.fuel_amount = get_int(vi, "fuel", "fuelAmountLevel")
    v.oil_level = get_int(vi, "oilLevel", "oilLevel")

    v.ignition_on = get_eq(ev, "ON", "ignitionStatus")

    csai = _get(ev, "chargeScheduleAdditionalInfo")
    v.ev_head_seat = get_bool(csai, "headSeat")
    v.ev_cabin_cond = get_bool(csai, "cabinCond")

    v.time_to_fully_charge_l3 = _non_negative(get_int(batt, "timeToFullyChargeL3"))
    v.time_to_fully_charge_l2 = _non_negative(get_int(batt, "timeToFullyChargeL2"))
    v.time_to_fully_charge_l1 = _non_negative(get_int(batt, "timeToFullyChargeL1"))

    v.odometer = get_float(vi, "odometer", "odometer", "value")
    v.odometer_unit = get_str(vi, "odometer", "odometer", "unit")

    tyres = _get(vi, "tyrePressure")
    if isinstance(tyres, list):
        tp = {t.get("type"): t for t in tyres if isinstance(t, dict)}

        for pos, key in (
            ("front_left", "FL"),
            ("front_right", "FR"),
            ("rear_left", "RL"),
            ("rear_right", "RR"),
        ):
            setattr(v, f"wheel_{pos}_pressure", get_float(tp, key, "pressure", "value"))
            setattr(
                v, f"wheel_{pos}_pressure_unit", get_str(tp, key, "pressure", "unit")
            )
            setattr(v, f"wheel_{pos}_pressure_warning", get_bool(tp, key, "warning"))

    v.timestamp_info = get_timestamp(p, "timestamp")


def apply_remote_status(v: Vehicle, p: dict[str, Any]) -> None:
    """Updates the vehicle from the remote status (doors, windows, engine...)"""

    v.raw_remote_status = p

    if "doors" in p:
        v.door_driver_locked = get_eq(p, "LOCKED", "doors", "driver", "status")
        v.door_passenger_locked = get_eq(p, "LOCKED", "doors", "passenger", "status")
        v.door_rear_left_locked = get_eq(p, "LOCKED", "doors", "leftRear", "status")
        v.door_rear_right_locked = get_eq(p, "LOCKED", "doors", "rightRear", "status")

    if "windows" in p:
        v.window_driver_closed = get_eq(p, "CLOSED", "windows", "driver", "status")
        v.window_passenger_closed = get_eq(
            p, "CLOSED", "windows", "passenger", "status"
        )

    if "engine" in p:
        v.ignition_on = get_eq(p, "ON", "engine", "status")

    v.trunk_locked = get_eq(p, "LOCKED", "trunk", "status")
    v.ev_running = get_eq(p, "ON", "evRunning", "status")
    v.timestamp_status = get_timestamp(p, "timestamp")


def parse_location(p: dict[str, Any]) -> Location:
    """Parses the last known location response"""

    return Location(
        latitude=get_float(p, "latitude"),
        longitude=get_float(p, "longitude"),
        altitude=get_float(p, "altitude"),
        bearing=get_float(p, "bearing"),
        is_approximate=get_bool(p, "isLocationApprox"),
        updated=get_timestamp(p, "timeStamp"),
    )
