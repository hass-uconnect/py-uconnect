from dataclasses import dataclass, field
from typing import Dict
from datetime import datetime

from .api import API
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


@dataclass
class ChargingLevel:
    name: str

    def __repr__(self):
        return self.name


CHARGING_LEVEL_DEFAULT = ChargingLevel("DEFAULT")
CHARGING_LEVEL_1 = ChargingLevel("LEVEL_1")
CHARGING_LEVEL_2 = ChargingLevel("LEVEL_2")
CHARGING_LEVEL_3 = ChargingLevel("LEVEL_3")

CHARGING_LEVELS = {
    "DEFAULT": CHARGING_LEVEL_DEFAULT,
    "LEVEL_1": CHARGING_LEVEL_1,
    "LEVEL_2": CHARGING_LEVEL_2,
    "LEVEL_3": CHARGING_LEVEL_3,
}


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
    days_to_service: int = None
    distance_to_service: int = None
    distance_to_empty: int = None
    battery_voltage: float = None

    # EV related
    plugged_in: bool = None
    charging_status: str = None
    charging_level: ChargingLevel = None
    state_of_charge: int = None
    time_to_fully_charge_l3: int = None
    time_to_fully_charge_l2: int = None
    charge_power_preference: str = None
    ev_running: bool = None

    # Wheels
    wheel_front_left_pressure: float = None
    wheel_front_left_pressure_warning: bool = None
    wheel_front_right_pressure: float = None
    wheel_front_right_pressure_warning: bool = None
    wheel_rear_left_pressure: float = None
    wheel_rear_left_pressure_warning: bool = None
    wheel_rear_right_pressure: float = None
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

    def __repr__(self):
        return f"{self.vin} (nick: {self.nickname})"


def _update_vehicle(v: Vehicle, p: dict) -> Vehicle:
    vi = sg(p, "vehicleInfo")
    ev = sg(p, "evInfo")
    batt = sg(ev, "battery")

    v.battery_voltage = sg(vi, "batteryInfo", "batteryVoltage", "value")
    v.charging_status = sg(batt, "chargingStatus")
    v.days_to_service = sg(vi, "daysToService")
    v.distance_to_service = sg(
        vi, "distanceToService", "distanceToService", "value")
    v.distance_to_empty = sg(batt, "distanceToEmpty", "value")
    v.plugged_in = sg(batt, "plugInStatus")
    v.state_of_charge = sg(batt, "stateOfCharge")
    v.ignition_on = sg(ev, "ignitionStatus") == "ON"
    v.charging_level = CHARGING_LEVELS.get(sg(batt, "chargingLevel"), None)
    v.time_to_fully_charge_l3 = sg(batt, "timeToFullyChargeL3")
    v.time_to_fully_charge_l2 = sg(batt, "timeToFullyChargeL2")
    v.charge_power_preference = sg(ev, "chargePowerPreference")
    v.odometer = sg(vi, "odometer", "odometer", "value")

    if "tyrePressure" in vi:
        tp = {x["type"]: x for x in vi["tyrePressure"]}
        v.wheel_front_left_pressure = sg(tp, "FL", "pressure", "value")
        v.wheel_front_left_pressure_warning = sg(tp, "FL", "warning")
        v.wheel_front_right_pressure = sg(tp, "FR", "pressure", "value")
        v.wheel_front_right_pressure_warning = sg(tp, "FR", "warning")
        v.wheel_rear_left_pressure = sg(tp, "RL", "pressure", "value")
        v.wheel_rear_left_pressure_warning = sg(tp, "RL", "warning")
        v.wheel_rear_right_pressure = sg(tp, "RR", "pressure", "value")
        v.wheel_rear_right_pressure_warning = sg(tp, "RR", "warning")

    return v


class Client:
    def __init__(self, email: str, password: str, pin: str, dev_mode: bool = False):
        self.api = API(email, password, pin, dev_mode)
        self.vehicles: Dict[str, Vehicle] = {}

    def _load_vehicles(self):
        for x in self.api.list_vehicles():
            vin = x['vin']

            if not vin in self.vehicles:
                vehicle = Vehicle(vin=vin, nickname=sg(x, 'nickname'), make=sg(x, 'make'), model=sg(
                    x, 'modelDescription'), year=sg(x, 'tsoModelYear'), region=sg(x, 'soldRegion'))
                self.vehicles[vin] = vehicle
            else:
                vehicle = self.vehicles[vin]

            info = self.api.get_vehicle(vin)
            _update_vehicle(vehicle, info)

            try:
                loc = self.api.get_vehicle_location(vin)
                ts = datetime.fromtimestamp(loc['timeStamp'] / 1000)
                vehicle.location = Location(longitude=sg(loc, 'longitude'), latitude=sg(loc, 'latitude'),
                                            altitude=sg(loc, 'altitude'), bearing=sg(loc, 'bearing'), is_approximate=sg(loc, 'isLocationApprox'), updated=ts)
            except:
                pass

            try:
                s = self.api.get_vehicle_status(vin)

                vehicle.door_driver_locked = sg(
                    s, 'doors', 'driver', 'status') == "LOCKED"
                vehicle.door_passenger_locked = sg(
                    s, 'doors', 'passenger', 'status') == "LOCKED"
                vehicle.door_rear_left_locked = sg(
                    s, 'doors', 'leftRear', 'status') == "LOCKED"
                vehicle.door_rear_right_locked = sg(
                    s, 'doors', 'rightRear', 'status') == "LOCKED"

                vehicle.window_driver_closed = sg(
                    s, 'windows', 'driver', 'status') == "CLOSED"
                vehicle.window_passenger_closed = sg(
                    s, 'windows', 'passenger', 'status') == "CLOSED"

                vehicle.trunk_locked = sg(s, 'trunk', 'status') != "UNLOCKED"
                vehicle.ev_running = sg(s, 'evRunning', 'status') != "OFF"
            except:
                pass

            enabled_services = []
            if 'services' in x:
                enabled_services = [v['service'] for v in x['services']
                                    if sg(v, 'vehicleCapable') and sg(v, 'serviceEnabled')]

            vehicle.supported_commands = [
                v for v in enabled_services if v in COMMANDS_BY_NAME]

    def refresh(self):
        self._load_vehicles()

    def get_vehicles(self):
        return self.vehicles

    def command(self, cmd: Command):
        self.api.command(cmd)
