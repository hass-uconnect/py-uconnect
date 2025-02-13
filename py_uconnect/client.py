from dataclasses import dataclass, field
from dataclasses_json import dataclass_json
from typing import Dict
from datetime import datetime, timedelta
from time import sleep

from .api import API
from .brands import Brand
from .command import Command, COMMANDS_BY_NAME


def convert(v):
    if not isinstance(v, str):
        return v

    if v == "null":
        return None

    try:
        v = int(v)
    except:
        try:
            v = float(v)
        except:
            pass

    return v


def sg(dct: dict, *keys):
    if not isinstance(dct, dict):
        return None

    for key in keys:
        try:
            dct = dct[key]
        except KeyError:
            return None

    return convert(dct)


def sg_eq(dct: dict, expect, *keys):
    v = sg(dct, *keys)

    if v is None:
        return None

    return v == expect


CHARGING_LEVELS = {
    "DEFAULT": 0,
    "LEVEL_1": 1,
    "LEVEL_2": 2,
    "LEVEL_3": 3,
}

CHARGING_LEVEL_PREFS = {
    "LEVEL_ONE": 1,
    "LEVEL_TWO": 2,
    "LEVEL_THREE": 3,
    "LEVEL_FOUR": 4,
    "LEVEL_FIVE": 5,
}


@dataclass_json
@dataclass
class Location:
    longitude: float = None
    latitude: float = None
    altitude: float = None
    bearing: float = None
    is_approximate: bool = None
    updated: datetime = None

    def __repr__(self):
        return f"lat: {self.latitude}, lon: {self.longitude} (updated {self.updated})"


@dataclass_json
@dataclass
class Vehicle:
    vin: str

    # General info
    nickname: str
    make: str
    model: str
    year: str
    region: str

    # Status
    ignition_on: bool = None
    trunk_locked: bool = None

    odometer: float = None
    odometer_unit: str = None
    days_to_service: int = None
    distance_to_service: int = None
    distance_to_service_unit: str = None
    distance_to_empty: int = None
    distance_to_empty_unit: str = None
    battery_voltage: float = None
    oil_level: int = None
    fuel_low: bool = None
    fuel_amount: int = None

    # EV related
    plugged_in: bool = None
    ev_running: bool = None
    charging: bool = None
    charging_level: int = None
    charging_level_preference: int = None
    state_of_charge: int = None
    time_to_fully_charge_l3: int = None
    time_to_fully_charge_l2: int = None

    # Wheels
    wheel_front_left_pressure: float = None
    wheel_front_left_pressure_unit: str = None
    wheel_front_left_pressure_warning: bool = None
    wheel_front_right_pressure: float = None
    wheel_front_right_pressure_unit: str = None
    wheel_front_right_pressure_warning: bool = None
    wheel_rear_left_pressure: float = None
    wheel_rear_left_pressure_unit: str = None
    wheel_rear_left_pressure_warning: bool = None
    wheel_rear_right_pressure: float = None
    wheel_rear_right_pressure_unit: str = None
    wheel_rear_right_pressure_warning: bool = None

    # Doors
    door_driver_locked: bool = None
    door_passenger_locked: bool = None
    door_rear_left_locked: bool = None
    door_rear_right_locked: bool = None

    # Windows
    window_driver_closed: bool = None
    window_passenger_closed: bool = None

    location: Location = None
    supported_commands: list[str] = field(default_factory=list)
    last_full_update: datetime = None

    def __repr__(self):
        return f"{self.vin} (nick: {self.nickname})"


def _update_vehicle(v: Vehicle, p: dict) -> Vehicle:
    vi = sg(p, "vehicleInfo")
    ev = sg(p, "evInfo")
    batt = sg(ev, "battery")

    v.battery_voltage = sg(vi, "batteryInfo", "batteryVoltage", "value")
    v.charging = sg_eq(batt, "CHARGING", "chargingStatus")
    v.charging_level = CHARGING_LEVELS.get(sg(batt, "chargingLevel"), None)
    v.charging_level_preference = CHARGING_LEVEL_PREFS.get(
        sg(ev, "chargePowerPreference"), None
    )
    v.plugged_in = sg(batt, "plugInStatus")
    v.state_of_charge = sg(batt, "stateOfCharge")

    v.days_to_service = sg(vi, "daysToService")
    v.distance_to_service = sg(vi, "distanceToService", "distanceToService", "value")
    v.distance_to_service_unit = sg(
        vi, "distanceToService", "distanceToService", "unit"
    )
    v.distance_to_empty = sg(vi, "fuel", "distanceToEmpty", "value") or sg(
        ev, "distanceToEmpty", "value"
    )
    v.distance_to_empty_unit = sg(vi, "fuel", "distanceToEmpty", "unit") or sg(
        ev, "distanceToEmpty", "unit"
    )
    v.fuel_low = sg(vi, "fuel", "isFuelLevelLow")
    v.fuel_amount = sg(vi, "fuel", "fuelAmountLevel")
    v.oil_level = sg(vi, "oilLevel", "oilLevel")

    v.ignition_on = sg_eq(ev, "ON", "ignitionStatus")
    v.time_to_fully_charge_l3 = sg(batt, "timeToFullyChargeL3")
    v.time_to_fully_charge_l2 = sg(batt, "timeToFullyChargeL2")
    v.odometer = sg(vi, "odometer", "odometer", "value")
    v.odometer_unit = sg(vi, "odometer", "odometer", "unit")

    if isinstance(vi, dict) and "tyrePressure" in vi:
        tp = {x["type"]: x for x in vi["tyrePressure"]}

        v.wheel_front_left_pressure = sg(tp, "FL", "pressure", "value")
        v.wheel_front_left_pressure_unit = sg(tp, "FL", "pressure", "unit")
        v.wheel_front_left_pressure_warning = sg(tp, "FL", "warning")

        v.wheel_front_right_pressure = sg(tp, "FR", "pressure", "value")
        v.wheel_front_right_pressure_unit = sg(tp, "FR", "pressure", "unit")
        v.wheel_front_right_pressure_warning = sg(tp, "FR", "warning")

        v.wheel_rear_left_pressure = sg(tp, "RL", "pressure", "value")
        v.wheel_rear_left_pressure_unit = sg(tp, "RL", "pressure", "unit")
        v.wheel_rear_left_pressure_warning = sg(tp, "RL", "warning")

        v.wheel_rear_right_pressure = sg(tp, "RR", "pressure", "value")
        v.wheel_rear_right_pressure_unit = sg(tp, "RR", "pressure", "unit")
        v.wheel_rear_right_pressure_warning = sg(tp, "RR", "warning")

    return v


class Client:
    def __init__(
        self,
        email: str,
        password: str,
        pin: str,
        brand: Brand,
        disable_tls_verification: bool = False,
        dev_mode: bool = False,
        debug: bool = False,
    ):
        self.api = API(
            email,
            password,
            pin,
            brand,
            disable_tls_verification=disable_tls_verification,
            dev_mode=dev_mode,
            debug=debug,
        )
        self.vehicles: Dict[str, Vehicle] = {}

    def set_debug(self, debug: bool):
        """Sets debug logging on/off"""

        self.api.set_debug(debug)

    def set_tls_verification(self, verify: bool):
        """Enable or disable TLS certificate verification"""

        self.api.set_tls_verification(verify)

    def refresh(self):
        """Refreshes all the vehicle data and caches it locally"""

        vehicles = self.api.list_vehicles()

        for x in vehicles:
            full_update_done = True
            vin = x["vin"]

            if not vin in self.vehicles:
                vehicle = Vehicle(
                    vin=vin,
                    nickname=sg(x, "nickname"),
                    make=sg(x, "make"),
                    model=sg(x, "modelDescription"),
                    year=sg(x, "tsoModelYear"),
                    region=sg(x, "soldRegion"),
                )
                self.vehicles[vin] = vehicle
            else:
                vehicle = self.vehicles[vin]

            info = self.api.get_vehicle(vin)
            if not set(["vehicleInfo", "evInfo"]).intersection(info.keys()):
                full_update_done = False

            _update_vehicle(vehicle, info)

            try:
                loc = self.api.get_vehicle_location(vin)

                vehicle.location = Location(
                    longitude=sg(loc, "longitude"),
                    latitude=sg(loc, "latitude"),
                    altitude=sg(loc, "altitude"),
                    bearing=sg(loc, "bearing"),
                    is_approximate=sg(loc, "isLocationApprox"),
                    updated=datetime.fromtimestamp(loc["timeStamp"] / 1000),
                )
            except:
                full_update_done = False

            try:
                s = self.api.get_vehicle_status(vin)

                # Check at least one key is present in the response
                if not set(["doors", "windows", "trunk", "evRunning"]).intersection(
                    set(s.keys())
                ):
                    full_update_done = False

                if "doors" in s:
                    vehicle.door_driver_locked = sg_eq(
                        s, "LOCKED", "doors", "driver", "status"
                    )
                    vehicle.door_passenger_locked = sg_eq(
                        s, "LOCKED", "doors", "passenger", "status"
                    )
                    vehicle.door_rear_left_locked = sg_eq(
                        s, "LOCKED", "doors", "leftRear", "status"
                    )
                    vehicle.door_rear_right_locked = sg_eq(
                        s, "LOCKED", "doors", "rightRear", "status"
                    )

                if "windows" in s:
                    vehicle.window_driver_closed = sg_eq(
                        s, "CLOSED", "windows", "driver", "status"
                    )
                    vehicle.window_passenger_closed = sg_eq(
                        s, "CLOSED", "windows", "passenger", "status"
                    )

                vehicle.trunk_locked = sg_eq(s, "LOCKED", "trunk", "status")
                vehicle.ev_running = sg_eq(s, "ON", "evRunning", "status")
            except:
                full_update_done = False

            enabled_services = []
            if "services" in x:
                enabled_services = [
                    v["service"]
                    for v in x["services"]
                    if sg(v, "vehicleCapable") and sg(v, "serviceEnabled")
                ]

            vehicle.supported_commands = [
                v for v in enabled_services if v in COMMANDS_BY_NAME
            ]

            if full_update_done:
                vehicle.last_full_update = datetime.now().astimezone()

    def get_vehicles(self):
        """Returns all vehicles data. Must execute refresh method before."""

        return self.vehicles

    def command(self, vin: str, cmd: Command):
        """Execute a given command against a car with a given VIN"""

        return self.api.command(vin, cmd)

    def _get_commands_statuses(self, vin: str) -> dict:
        r = self.api.get_vehicle_notifications(vin)

        return {
            x["correlationId"]: (
                x["notification"]["data"]["status"].lower() == "success"
            )
            for x in r["notifications"]["items"]
        }

    def command_verify(
        self,
        vin: str,
        cmd: Command,
        timeout: timedelta = timedelta(seconds=60),
        interval: timedelta = timedelta(seconds=2),
    ):
        """Execute a given command against a car with a given VIN and poll for the status"""

        id = self.command(vin, cmd)

        start = datetime.now()
        while datetime.now() - start < timeout:
            sleep(interval.seconds)
            r = self._get_commands_statuses(vin)
            if id in r:
                return r[id]

        raise Exception(f"unable to obtain command status: timed out (id {id})")
