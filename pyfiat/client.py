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
class Wheel:
    type: str
    pressure: int = None
    status_normal: bool = None

    def __repr__(self):
        return f"wheel: {self.type}, pressure: {self.pressure}, status normal: {self.status_normal}"


@dataclass
class Door:
    type: str
    locked: bool

    def __repr__(self):
        return f"door: {self.type}, locked: {self.locked}"


@dataclass
class Window:
    type: str
    closed: bool

    def __repr__(self):
        return f"window: {self.type}, closed: {self.closed}"


@dataclass
class Vehicle:
    vin: str

    # General info
    nickname: str = None
    make: str = None
    model: str = None
    year: str = None
    region: str = None

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

    wheels: dict[Wheel] = field(default_factory=dict)
    doors: dict[Door] = field(default_factory=dict)
    windows: dict[Door] = field(default_factory=dict)

    location: Location = None
    supported_commands: list[str] = field(default_factory=list)

    def __repr__(self):
        return f"{self.vin} (nick: {self.nickname})"


def _create_vehicle(vin: str, p: dict) -> Vehicle:
    v = Vehicle(vin)

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

    if vi is not None and "tyrePressure" in vi:
        for w in vi["tyrePressure"]:
            if "type" in w:
                v.wheels[w["type"]] = Wheel(
                    w["type"], sg(w, "pressure", "value"), sg(w, "status") == "NORMAL")

    return v


class Client:
    def __init__(self, email: str, password: str, pin: str, dev_mode: bool = False):
        self.api = API(email, password, pin, dev_mode)
        self.vehicles: Dict[str, Vehicle] = {}

    def _load_vehicles(self):
        for x in self.api.list_vehicles():
            enabled_services = []
            if 'services' in x:
                enabled_services = [v['service'] for v in x['services']
                                    if sg(v, 'vehicleCapable') and sg(v, 'serviceEnabled')]

            vin = x['vin']
            info = self.api.get_vehicle(vin)

            v = _create_vehicle(vin, info)
            v.make = sg(x, 'make')
            v.nickname = sg(x, 'nickname')
            v.model = sg(x, 'modelDescription')
            v.year = sg(x, 'tsoModelYear')
            v.region = sg(x, 'soldRegion')

            try:
                loc = self.api.get_vehicle_location(vin)
                ts = datetime.fromtimestamp(loc['timeStamp'] / 1000)
                v.location = Location(longitude=sg(loc, 'longitude'), latitude=sg(loc, 'latitude'),
                                      altitude=sg(loc, 'altitude'), bearing=sg(loc, 'bearing'), is_approximate=sg(loc, 'isLocationApprox'), updated=ts)
            except:
                # Use old location if available
                if vin in self.vehicles:
                    loc = self.vehicles[vin].location

            try:
                s = self.api.get_vehicle_status(vin)

                doors = [
                    Door("DRIVER", sg(s, 'doors', 'driver', 'status') == "LOCKED"),
                    Door("PASSENGER", sg(s, 'doors',
                         'passenger', 'status') == "LOCKED"),
                    Door("REAR_LEFT", sg(s, 'doors',
                         'leftRear', 'status') == "LOCKED"),
                    Door("REAR_RIGHT", sg(s, 'doors',
                         'rightRear', 'status') == "LOCKED"),
                ]
                v.doors = {x.type: x for x in doors}

                windows = [
                    Window("DRIVER", sg(s, 'windows',
                           'driver', 'status') == "CLOSED"),
                    Window("PASSENGER", sg(s, 'windows',
                           'passenger', 'status') == "CLOSED"),
                ]
                v.windows = {x.type: x for x in windows}

                v.trunk_locked = sg(s, 'trunk', 'status') != "UNLOCKED"
                v.ev_running = sg(s, 'evRunning', 'status') != "OFF"
            except:
                pass

            v.supported_commands = [
                v for v in enabled_services if v in COMMANDS_BY_NAME]

            self.vehicles[vin] = v

    def refresh(self):
        self._load_vehicles()

    def get_vehicles(self):
        return self.vehicles

    def command(self, cmd: Command):
        self.api.command(cmd)
