from dataclasses import dataclass, field
from dataclasses_json import dataclass_json
from typing import Any, Dict
from datetime import datetime, timedelta
from time import sleep

from .api import API, ChargingLevel
from .brands import Brand
from .command import Command, COMMANDS_BY_NAME


def convert(v: Any) -> Any:
    if not isinstance(v, str):
        return v

    if v == "null":
        return None

    try:
        v = int(v)
    except (ValueError, TypeError):
        try:
            v = float(v)
        except (ValueError, TypeError):
            pass

    return v


def sg(dct: Any, *keys: str) -> Any:
    if not isinstance(dct, dict):
        return None

    for key in keys:
        try:
            dct = dct[key]
        except KeyError:
            return None

    return convert(dct)


def sg_eq(dct: Any, expect: Any, *keys: str) -> bool | None:
    v = sg(dct, *keys)

    if v is None:
        return None

    return v == expect


def sg_eq_str(dct: Any, expect: str, *keys: str) -> bool:
    v = sg(dct, *keys)

    if not isinstance(v, str):
        return False

    return v.lower() == expect.lower()


CHARGING_LEVELS = {
    "DEFAULT": 0,
    "LEVEL_1": 1,
    "LEVEL_2": 2,
    "LEVEL_3": 3,
}


@dataclass_json
@dataclass
class Location:
    longitude: float | None = None
    latitude: float | None = None
    altitude: float | None = None
    bearing: float | None = None
    is_approximate: bool | None = None
    updated: datetime | None = None

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

    sdp: str | None = None
    image_url: str | None = None
    fuel_type: str | None = None

    # Status
    ignition_on: bool | None = None
    trunk_locked: bool | None = None

    odometer: float | None = None
    odometer_unit: str | None = None
    days_to_service: int | None = None
    distance_to_service: int | None = None
    distance_to_service_unit: str | None = None
    distance_to_empty: int | None = None
    distance_to_empty_unit: str | None = None
    range_gas: int | None = None
    range_gas_unit: str | None = None
    range_total: int | None = None
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
    charging_level_preference: str | None = None
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
    supported_commands: list[str] = field(default_factory=list)
    enabled_services: list[str] = field(default_factory=list)

    timestamp_info: datetime | None = None
    timestamp_status: datetime | None = None

    def __repr__(self):
        return f"{self.vin} (nick: {self.nickname})"


def _update_vehicle(v: Vehicle, p: dict) -> Vehicle:
    vi = sg(p, "vehicleInfo")
    ev = sg(p, "evInfo")
    batt = sg(ev, "battery")

    v.battery_voltage = sg(vi, "batteryInfo", "batteryVoltage", "value")
    v.battery_state_of_charge = sg(vi, "batteryInfo", "batteryStateOfCharge")
    v.charging = sg_eq(batt, "CHARGING", "chargingStatus")
    v.charging_level = CHARGING_LEVELS.get(sg(batt, "chargingLevel"), None)
    v.charging_level_preference = sg(ev, "chargePowerPreference")
    if v.charging_level_preference == "NOT_USED_VALUE":
        v.charging_level_preference = None

    v.plugged_in = sg(batt, "plugInStatus")
    v.state_of_charge = sg(batt, "stateOfCharge")

    v.days_to_service = sg(vi, "daysToService")
    v.distance_to_service = sg(vi, "distanceToService", "distanceToService", "value")
    v.distance_to_service_unit = sg(
        vi, "distanceToService", "distanceToService", "unit"
    )
    v.distance_to_empty = sg(batt, "distanceToEmpty", "value") or sg(
        vi, "fuel", "distanceToEmpty", "value"
    )
    v.distance_to_empty_unit = sg(batt, "distanceToEmpty", "unit") or sg(
        vi, "fuel", "distanceToEmpty", "unit"
    )
    v.range_gas = sg(batt, "gasRange")
    v.range_gas_unit = v.distance_to_empty_unit
    v.range_total = sg(batt, "totalRange")
    v.range_total_unit = v.distance_to_empty_unit

    v.fuel_low = sg(vi, "fuel", "isFuelLevelLow")
    v.fuel_amount = sg(vi, "fuel", "fuelAmountLevel")
    v.oil_level = sg(vi, "oilLevel", "oilLevel")

    v.ignition_on = sg_eq(ev, "ON", "ignitionStatus")

    csai = sg(ev, "chargeScheduleAdditionalInfo")
    v.ev_head_seat = sg(csai, "headSeat")
    v.ev_cabin_cond = sg(csai, "cabinCond")

    v.time_to_fully_charge_l3 = sg(batt, "timeToFullyChargeL3")
    v.time_to_fully_charge_l2 = sg(batt, "timeToFullyChargeL2")
    v.time_to_fully_charge_l1 = sg(batt, "timeToFullyChargeL1")

    # Some vehicles report -1
    if v.time_to_fully_charge_l3 is not None and v.time_to_fully_charge_l3 < 0:
        v.time_to_fully_charge_l3 = None
    if v.time_to_fully_charge_l2 is not None and v.time_to_fully_charge_l2 < 0:
        v.time_to_fully_charge_l2 = None
    if v.time_to_fully_charge_l1 is not None and v.time_to_fully_charge_l1 < 0:
        v.time_to_fully_charge_l1 = None

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

    v.timestamp_info = (
        datetime.fromtimestamp(p["timestamp"] / 1000).astimezone()
        if "timestamp" in p
        else None
    )

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
        trace: bool = False,
    ):
        self.api = API(
            email,
            password,
            pin,
            brand,
            disable_tls_verification=disable_tls_verification,
            dev_mode=dev_mode,
            trace=trace,
        )
        self.vehicles: Dict[str, Vehicle] = {}

    def set_debug(self, debug: bool):
        """Sets debug logging on/off"""

        self.api.set_debug(debug)

    def set_tls_verification(self, verify: bool):
        """Enable or disable TLS certificate verification"""

        self.api.set_tls_verification(verify)

    def set_pin(self, pin: str):
        self.api.set_pin(pin)

    def refresh(self):
        """Refreshes all the vehicle data and caches it locally"""

        vehicles = self.api.list_vehicles()

        for x in vehicles:
            vin = x["vin"]

            if vin not in self.vehicles:
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

            vehicle.sdp = sg(x, "sdp")
            vehicle.image_url = sg(x, "vehicleImageURL")
            vehicle.fuel_type = sg(x, "fuelType")

            info = self.api.get_vehicle(vin)
            _update_vehicle(vehicle, info)

            try:
                loc = self.api.get_vehicle_location(vin)

                updated = (
                    datetime.fromtimestamp(loc["timeStamp"] / 1000).astimezone()
                    if "timeStamp" in loc
                    else None
                )

                vehicle.location = Location(
                    longitude=sg(loc, "longitude"),
                    latitude=sg(loc, "latitude"),
                    altitude=sg(loc, "altitude"),
                    bearing=sg(loc, "bearing"),
                    is_approximate=sg(loc, "isLocationApprox"),
                    updated=updated,
                )
            except Exception:
                pass

            try:
                s = self.api.get_vehicle_status(vin)

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

                if "engine" in s:
                    vehicle.ignition_on = sg_eq(s, "ON", "engine", "status")

                vehicle.trunk_locked = sg_eq(s, "LOCKED", "trunk", "status")
                vehicle.ev_running = sg_eq(s, "ON", "evRunning", "status")

                vehicle.timestamp_status = (
                    datetime.fromtimestamp(s["timestamp"] / 1000).astimezone()
                    if "timestamp" in s
                    else None
                )
            except Exception:
                pass

            enabled_services = []
            if "services" in x:
                enabled_services = [
                    v["service"]
                    for v in x["services"]
                    if sg(v, "vehicleCapable") and sg(v, "serviceEnabled")
                ]

            vehicle.enabled_services = enabled_services
            vehicle.supported_commands = [
                v for v in enabled_services if v in COMMANDS_BY_NAME
            ]

    def get_vehicles(self):
        """Returns all vehicles data. Must execute refresh method before."""

        return self.vehicles

    def _get_commands_statuses(self, vin: str) -> dict:
        r = self.api.get_vehicle_notifications(vin)

        if "notifications" not in r or "items" not in r["notifications"]:
            return {}

        return {
            x["correlationId"]: sg_eq_str(
                x, "success", "notification", "data", "status"
            )
            for x in r["notifications"]["items"]
            if "correlationId" in x
        }

    def _poll_correlation_id(
        self,
        vin: str,
        id: str,
        timeout: timedelta = timedelta(seconds=60),
        interval: timedelta = timedelta(seconds=2),
    ) -> bool:
        start = datetime.now()
        while datetime.now() - start < timeout:
            sleep(interval.seconds)
            r = self._get_commands_statuses(vin)
            if id in r:
                return r[id]

        raise Exception(f"unable to obtain execution status: timed out (id {id})")

    def get_remote_operation_status(self, vin: str, correlation_id: str) -> dict:
        """Get the status of a remote operation by its correlation ID"""

        return self.api.get_remote_operation_status(vin, correlation_id)

    def command(self, vin: str, cmd: Command):
        """Execute a given command against a car with a given VIN"""

        return self.api.command(vin, cmd)

    def command_verify(
        self,
        vin: str,
        cmd: Command,
    ) -> bool:
        """Execute a given command against a car with a given VIN and poll for the status"""

        id = self.command(vin, cmd)
        return self._poll_correlation_id(vin, id)

    def get_stolen_vehicle_status(self, vin: str) -> dict:
        """Get stolen vehicle locator (SVLA) status for a vehicle with a given VIN"""

        return self.api.get_stolen_vehicle_status(vin)

    def get_vehicle_subscription(self, vin: str) -> dict:
        """Get subscription status for a vehicle with a given VIN"""

        return self.api.get_vehicle_subscription(vin)

    def set_vehicle_nickname(self, vin: str, nickname: str) -> dict:
        """Set a nickname for a vehicle with a given VIN"""

        return self.api.set_vehicle_nickname(vin, nickname)

    def update_location(self, vin: str) -> str:
        """Trigger a fresh location update for a vehicle with a given VIN.

        Returns the correlation ID to poll for completion.
        """

        return self.api.update_location(vin)

    def get_eco_coaching_last_trip(self, vin: str) -> dict:
        """Get eco-coaching data for the last trip of a vehicle with a given VIN"""

        return self.api.get_eco_coaching_last_trip(vin)

    def get_eco_coaching_trips(self, vin: str) -> dict:
        """Get eco-coaching trip list for a vehicle with a given VIN"""

        return self.api.get_eco_coaching_trips(vin)

    def get_maintenance_history(self, vin: str) -> dict:
        """Get maintenance history for a vehicle with a given VIN"""

        return self.api.get_maintenance_history(vin)

    def get_vehicle_health_report(self, vin: str) -> dict:
        """Get vehicle health report for a vehicle with a given VIN"""

        return self.api.get_vehicle_health_report(vin)

    def get_vehicle_image(self, vin: str) -> dict:
        """Get vehicle image URL for a vehicle with a given VIN"""

        return self.api.get_vehicle_image(vin)

    def get_charge_schedules(self, vin: str) -> dict:
        """Get EV charge schedules for a vehicle with a given VIN"""

        return self.api.get_charge_schedules(vin)

    def set_charge_schedule(self, vin: str, schedule: dict):
        """Set an EV charge schedule on the vehicle with a given VIN"""

        return self.api.set_charge_schedule(vin, schedule)

    def set_charge_schedule_verify(self, vin: str, schedule: dict) -> bool:
        """Set an EV charge schedule and poll for the status"""

        id = self.api.set_charge_schedule(vin, schedule)
        return self._poll_correlation_id(vin, id)

    def set_charging_level(
        self, vin: str, level: ChargingLevel, max_soc: str | None = None
    ):
        """Set the charging level on the vehicle with a given VIN"""

        return self.api.set_charging_level(vin, level, max_soc=max_soc)

    def set_charging_level_verify(
        self, vin: str, level: ChargingLevel, max_soc: str | None = None
    ):
        """Set the charging level on the vehicle with a given VIN and poll for the status"""

        id = self.api.set_charging_level(vin, level, max_soc=max_soc)
        return self._poll_correlation_id(vin, id)
