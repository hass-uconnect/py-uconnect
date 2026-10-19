"""Remote commands that can be sent to a vehicle.

A command is POSTed as ``{"command": <name>, "pinAuth": <token>}`` (plus an
optional ``params`` object) to ``/<api_version>/accounts/<uid>/vehicles/<vin>/<url>``.
The API answers with a correlation ID which can be used to poll for the result.

A vehicle supports a command if one of the command's services is enabled for
it (see ``Vehicle.enabled_services``). Routing follows the official apps
(version 1.99.705): the eight classic commands use ``/v1/.../remote/``, all
other remote operations ``/v2/.../remote/``.
"""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


@dataclass(frozen=True)
class Command:
    """A remote command"""

    name: str
    url: str = "remote/"
    api_version: str = "v1"
    # Sent instead if the API rejects this command with HTTP 400, 403 or 404
    # (some vehicles only accept a newer variant)
    fallback: Command | None = None
    # Services that enable the command, defaults to the command name
    services: tuple[str, ...] = field(default=())

    def __str__(self) -> str:
        return self.name

    def enabled_by(self, services: Collection[str]) -> bool:
        """Whether one of the given enabled services enables this command"""

        return any(s in services for s in (self.services or (self.name,)))


COMMAND_DOORS_LOCK = Command(name="RDL")
COMMAND_DOORS_UNLOCK = Command(name="RDU")
COMMAND_ENGINE_ON = Command(name="REON")
COMMAND_ENGINE_OFF = Command(name="REOFF")
COMMAND_LIGHTS_HORN = Command(name="HBLF")
COMMAND_LIGHTS = Command(name="ROLIGHTS")
COMMAND_PRECOND_ON = Command(name="ROPRECOND")
COMMAND_PRECOND_OFF = Command(name="ROPRECOND_OFF")

# Climate. A target temperature can be passed with hvac_params()
COMMAND_HVAC_ON = Command(name="ROHVACON", api_version="v2")
COMMAND_HVAC_OFF = Command(name="ROHVACOFF", api_version="v2")
# Not sent by the current apps, kept for vehicles that might still accept them
COMMAND_COMFORT_ON = Command(name="ROCOMFORTON", api_version="v2")
COMMAND_COMFORT_OFF = Command(name="ROCOMFORTOFF", api_version="v2")
COMMAND_CABIN_VENTILATION = Command(name="ACV", api_version="v2")

COMMAND_TRUNK_LOCK = Command(name="ROTRUNKLOCK", api_version="v2")
COMMAND_TRUNK_UNLOCK = Command(name="ROTRUNKUNLOCK", api_version="v2")
COMMAND_LIFTGATE_LOCK = Command(name="ROLIFTGATELOCK", api_version="v2")
COMMAND_LIFTGATE_UNLOCK = Command(name="ROLIFTGATEUNLOCK", api_version="v2")

# Clears the personal data (contacts, destinations...) stored in the head unit
COMMAND_CLEAR_PERSONAL_DATA = Command(name="ROCLRPERSDATA", api_version="v2")

COMMAND_REFRESH_LOCATION = Command(name="VF", url="location/")
COMMAND_REFRESH_LOCATION_B = Command(name="VF_B", url="location/")

# Asks the vehicle to upload a fresh (EV) status. Vehicles with the
# DEEPREFRESH2 service use the v2 endpoint: Client.command() picks it directly.
# The command name sent to it is not certain, both variants are tried.
COMMAND_DEEP_REFRESH_V2_ALT = Command(name="DEEPREFRESH2", url="ev/", api_version="v2")
COMMAND_DEEP_REFRESH_V2 = Command(
    name="DEEPREFRESH",
    url="ev/",
    api_version="v2",
    fallback=COMMAND_DEEP_REFRESH_V2_ALT,
)
COMMAND_DEEP_REFRESH = Command(
    name="DEEPREFRESH",
    url="ev/",
    fallback=COMMAND_DEEP_REFRESH_V2,
    services=("DEEPREFRESH", "DEEPREFRESH2"),
)

# Starts charging. Vehicles with the CNOW2 service use START_CHARGE on v4:
# Client.command() picks it directly.
COMMAND_CHARGE_V4 = Command(name="START_CHARGE", url="ev/chargenow/", api_version="v4")
COMMAND_CHARGE = Command(
    name="CNOW",
    url="ev/chargenow/",
    fallback=COMMAND_CHARGE_V4,
    services=("CNOW", "CNOW2"),
)

# Commands as they are offered to users. The *_V2/*_V4 variants are selected
# automatically and are not listed.
COMMANDS = [
    COMMAND_DOORS_LOCK,
    COMMAND_DOORS_UNLOCK,
    COMMAND_ENGINE_ON,
    COMMAND_ENGINE_OFF,
    COMMAND_LIGHTS_HORN,
    COMMAND_LIGHTS,
    COMMAND_PRECOND_ON,
    COMMAND_PRECOND_OFF,
    COMMAND_HVAC_ON,
    COMMAND_HVAC_OFF,
    COMMAND_COMFORT_ON,
    COMMAND_COMFORT_OFF,
    COMMAND_CABIN_VENTILATION,
    COMMAND_TRUNK_LOCK,
    COMMAND_TRUNK_UNLOCK,
    COMMAND_LIFTGATE_LOCK,
    COMMAND_LIFTGATE_UNLOCK,
    COMMAND_CLEAR_PERSONAL_DATA,
    COMMAND_REFRESH_LOCATION,
    COMMAND_REFRESH_LOCATION_B,
    COMMAND_DEEP_REFRESH,
    COMMAND_CHARGE,
]

COMMANDS_BY_NAME = {x.name: x for x in COMMANDS}


def supported_commands(services: Collection[str]) -> list[str]:
    """Names of the commands enabled by the given enabled services"""

    return [c.name for c in COMMANDS if c.enabled_by(services)]


def resolve_command(cmd: Command, services: Collection[str]) -> Command:
    """Picks the variant of a command that fits the vehicle's enabled services,
    the way the official apps do.
    """

    if cmd == COMMAND_CHARGE and "CNOW2" in services:
        return COMMAND_CHARGE_V4

    if cmd == COMMAND_DEEP_REFRESH and "DEEPREFRESH2" in services:
        return COMMAND_DEEP_REFRESH_V2

    # Vehicles that only support preconditioning get it instead of engine start
    if cmd == COMMAND_ENGINE_ON and "REON" not in services and "ROPRECOND" in services:
        return COMMAND_PRECOND_ON

    if (
        cmd == COMMAND_ENGINE_OFF
        and "REOFF" not in services
        and "ROPRECOND_OFF" in services
    ):
        return COMMAND_PRECOND_OFF

    return cmd


class TemperatureUnit(StrEnum):
    """Unit of temperatures sent with climate commands"""

    CELSIUS = "Celsius"
    FAHRENHEIT = "Fahrenheit"


def hvac_params(
    target_temp: float, unit: TemperatureUnit = TemperatureUnit.CELSIUS
) -> dict[str, Any]:
    """Builds the ``params`` of ``ROHVACON`` that set the target temperature.

    The values besides the target temperature are the ones the official app
    sends. The temperature range supported depends on the vehicle.
    """

    unit = TemperatureUnit(unit)
    return {
        "interiorTemperature": 22 if unit == TemperatureUnit.CELSIUS else 72,
        "temperatureUOM": unit.value,
        "fanSpeed": 50,
        "targetTemp": target_temp,
        "timeoutAfterTemp": 0,
        "preTripTimeout": 15,
    }


# EV charge/climate schedules. The service enabling them determines the
# command, the endpoint and the field holding the schedules. Ordered by
# preference, the first enabled one is used.
@dataclass(frozen=True)
class ScheduleEndpoint:
    """How the schedules of a vehicle with a given schedule service are set"""

    command: str
    api_version: str
    url: str
    # Field of the request body holding the schedules
    field: str
    # Field of evInfo in the vehicle status holding the current schedules
    status_field: str


SCHEDULE_ENDPOINTS = [
    ScheduleEndpoint(
        "CPCOOP", "v4", "ev/schedule/", "chargeSchedulesV4", "chargeSchedulesV4"
    ),
    *(
        ScheduleEndpoint(
            c, "v3", "ev/schedule/", "chargeSchedulesV3", "chargeSchedulesV3"
        )
        for c in ("BCPCHRG", "BCPPLUS", "CPCHRG2", "CPPLUSPHEV", "CPPLUSBEV")
    ),
    ScheduleEndpoint("CPPLUS", "v2", "ev/schedule/", "schedules", "schedules"),
    ScheduleEndpoint(
        "CP", "v1", "ev/chargeschedule/", "chargeSchedules", "chargeSchedules"
    ),
]

SCHEDULE_ENDPOINTS_BY_COMMAND = {x.command: x for x in SCHEDULE_ENDPOINTS}


def schedule_endpoint(services: Collection[str]) -> ScheduleEndpoint | None:
    """The schedule endpoint to use for a vehicle with the given enabled services"""

    return next((x for x in SCHEDULE_ENDPOINTS if x.command in services), None)
