from __future__ import annotations

import pytest

from py_uconnect.command import (
    COMMAND_CHARGE,
    COMMAND_CHARGE_V4,
    COMMAND_DEEP_REFRESH,
    COMMAND_DEEP_REFRESH_V2,
    COMMAND_DOORS_LOCK,
    COMMAND_ENGINE_OFF,
    COMMAND_ENGINE_ON,
    COMMAND_PRECOND_OFF,
    COMMAND_PRECOND_ON,
    COMMANDS,
    COMMANDS_BY_NAME,
    Command,
    TemperatureUnit,
    hvac_params,
    resolve_command,
    schedule_endpoint,
    supported_commands,
)

# The commands the apps send to /v1/.../remote/, all other remote operations
# go to /v2/.../remote/
V1_REMOTE = {
    "HBLF",
    "RDL",
    "RDU",
    "REOFF",
    "REON",
    "ROPRECOND",
    "ROPRECOND_OFF",
    "ROLIGHTS",
}


def test_command_names_are_unique() -> None:
    assert len(COMMANDS_BY_NAME) == len(COMMANDS)


@pytest.mark.parametrize("cmd", [c for c in COMMANDS if c.url == "remote/"], ids=str)
def test_remote_routing(cmd: Command) -> None:
    assert cmd.api_version == ("v1" if cmd.name in V1_REMOTE else "v2")


@pytest.mark.parametrize(
    ("cmd", "services", "expected"),
    [
        (COMMAND_CHARGE, {"CNOW"}, COMMAND_CHARGE),
        (COMMAND_CHARGE, {"CNOW", "CNOW2"}, COMMAND_CHARGE_V4),
        (COMMAND_DEEP_REFRESH, {"DEEPREFRESH"}, COMMAND_DEEP_REFRESH),
        (COMMAND_DEEP_REFRESH, {"DEEPREFRESH2"}, COMMAND_DEEP_REFRESH_V2),
        (COMMAND_ENGINE_ON, {"REON", "ROPRECOND"}, COMMAND_ENGINE_ON),
        (COMMAND_ENGINE_ON, {"ROPRECOND"}, COMMAND_PRECOND_ON),
        (COMMAND_ENGINE_ON, set(), COMMAND_ENGINE_ON),
        (COMMAND_ENGINE_OFF, {"ROPRECOND_OFF"}, COMMAND_PRECOND_OFF),
        (COMMAND_DOORS_LOCK, {"RDL", "CNOW2"}, COMMAND_DOORS_LOCK),
    ],
)
def test_resolve_command(cmd: Command, services: set[str], expected: Command) -> None:
    assert resolve_command(cmd, services) == expected


def test_deep_refresh_v2_tries_both_names() -> None:
    assert COMMAND_DEEP_REFRESH_V2.api_version == "v2"
    assert COMMAND_DEEP_REFRESH_V2.name == "DEEPREFRESH"
    assert COMMAND_DEEP_REFRESH_V2.fallback is not None
    assert COMMAND_DEEP_REFRESH_V2.fallback.name == "DEEPREFRESH2"


def test_supported_commands() -> None:
    assert supported_commands({"RDL", "CNOW2", "DEEPREFRESH2", "SVLA"}) == [
        "RDL",
        "DEEPREFRESH",
        "CNOW",
    ]


@pytest.mark.parametrize(
    ("services", "command"),
    [
        ({"CPPLUSBEV", "CPCOOP"}, "CPCOOP"),
        ({"CPPLUSBEV", "BCPCHRG"}, "BCPCHRG"),
        ({"CPPLUS", "CP"}, "CPPLUS"),
        ({"CP"}, "CP"),
        ({"RDL"}, None),
    ],
)
def test_schedule_endpoint(services: set[str], command: str | None) -> None:
    ep = schedule_endpoint(services)
    assert (ep.command if ep else None) == command


def test_hvac_params_fahrenheit() -> None:
    p = hvac_params(70, TemperatureUnit.FAHRENHEIT)

    assert p["interiorTemperature"] == 72
    assert p["temperatureUOM"] == "Fahrenheit"
    assert p["targetTemp"] == 70
