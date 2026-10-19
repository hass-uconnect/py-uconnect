# py-uconnect

Async Python client for the FCA/Stellantis Uconnect cloud API, used by the
official apps of Fiat, Jeep, Alfa Romeo, Maserati, Chrysler, Dodge and Ram to
show the vehicle state and send remote commands.

It powers the [Uconnect Home Assistant integration](https://github.com/hass-uconnect/hass-uconnect).
Version 1.0 is an async rewrite. If you are upgrading from 0.x, see the
migration guide in [CHANGELOG.md](CHANGELOG.md).

## Installation

```sh
pip install py-uconnect
```

Python 3.11 or newer is required. The only dependency is `aiohttp`.

## Quick start

```python
import asyncio

from py_uconnect import Client
from py_uconnect.brands import FIAT_EU


async def main() -> None:
    async with Client(
        "foo@bar.com", "very_secret", pin="1234", brand=FIAT_EU
    ) as client:
        vehicles = await client.refresh()

        for vehicle in vehicles.values():
            print(vehicle.to_json(indent=2))


asyncio.run(main())
```

`Client` logs in on the first request and renews the credentials before they
expire. The PIN is only needed for remote commands and settings changes and
can be `None` otherwise.

To reuse an existing `aiohttp.ClientSession`, such as Home Assistant's shared
session, pass it as `session=`. A session passed in is not closed by the client:

```python
client = Client(email, password, pin, FIAT_EU, session=session)
```

### Brands

Pick the configuration matching the brand of the app you use and the region
of your account from `py_uconnect.brands` (or `BRANDS` by name):

| Brand | Configurations |
| --- | --- |
| Fiat | `FIAT_EU`, `FIAT_US`, `FIAT_CANADA`, `FIAT_ASIA` |
| Jeep | `JEEP_EU`, `JEEP_US`, `JEEP_ASIA` |
| Alfa Romeo | `ALFA_ROMEO_EU`, `ALFA_ROMEO_US_CANADA`, `ALFA_ROMEO_ASIA` |
| Maserati | `MASERATI_EU`, `MASERATI_US_CANADA`, `MASERATI_ASIA` |
| Chrysler | `CHRYSLER_US`, `CHRYSLER_CANADA` |
| Dodge | `DODGE_US` |
| Ram | `RAM_US` |

## Vehicle data

`Client.refresh()` loads the vehicles of the account into `client.vehicles`
(a dict keyed by VIN) and returns it. Each `Vehicle` combines the vehicle list,
the detailed status, the remote status and the last known location. Fields are
`None` when the vehicle does not report them:

| Group | Fields |
| --- | --- |
| General | `vin`, `nickname`, `make`, `model`, `year`, `region`, `sdp`, `image_url`, `fuel_type`, `privacy_mode` |
| Status | `ignition_on`, `odometer`, `days_to_service`, `distance_to_service`, `distance_to_empty`, `range_gas`, `range_total`, `battery_voltage`, `battery_state_of_charge`, `oil_level`, `fuel_low`, `fuel_amount` (distances have a matching `*_unit` field) |
| EV | `plugged_in`, `ev_running`, `charging`, `charging_level`, `charging_level_preference`, `state_of_charge`, `time_to_fully_charge_l1`/`_l2`/`_l3`, `ev_head_seat`, `ev_cabin_cond`, `charge_schedules` |
| Tyres | `wheel_<front/rear>_<left/right>_pressure`, `_pressure_unit`, `_pressure_warning` |
| Doors, windows | `door_driver_locked`, `door_passenger_locked`, `door_rear_left_locked`, `door_rear_right_locked`, `trunk_locked`, `liftgate_locked`, `window_driver_closed`, `window_passenger_closed`, `window_rear_left_closed`, `window_rear_right_closed`, `sunroof_closed` |
| Climate | `hvac_on`, `hvac_temperature`, `hvac_temperature_unit` |
| Location | `location` (`latitude`, `longitude`, `altitude`, `bearing`, `is_approximate`, `updated`) |
| Services | `enabled_services` (all services that are capable and enabled), `supported_commands` (names of the commands they enable) |
| Timestamps | `timestamp_info`, `timestamp_status` |

The raw responses are kept in `raw_list_item`, `raw_info`, `raw_remote_status`
and `raw_location`, in case you need a value that is not parsed.
`to_dict(raw=True)` and `to_json(raw=True)` include them.

Not every vehicle supports every endpoint. If an endpoint fails with an API
error, the vehicle is kept with the data that is available, including the
status snapshot some vehicles have in the vehicle list. Authentication and
connection errors are raised.

## Remote commands

```python
from py_uconnect.command import COMMAND_DOORS_LOCK

vehicle = client.vehicles[vin]
if vehicle.supports(COMMAND_DOORS_LOCK):
    # Send the command and wait for the result reported by the vehicle
    ok = await client.command_verify(vin, COMMAND_DOORS_LOCK)

    # Or just send it, and wait later if needed
    correlation_id = await client.command(vin, COMMAND_DOORS_LOCK)
    ok = await client.wait_for_operation(vin, correlation_id, timeout=60)
```

`command_verify()` and `wait_for_operation()` return `True` if the vehicle
reports success and `False` if it reports failure. If there is no result within
`timeout` seconds they raise `CommandTimeoutError`. The result is polled from
the remote operation status endpoint and, because that endpoint is not
available in every region, from the vehicle notifications.

| Command | Name | Description |
| --- | --- | --- |
| `COMMAND_DOORS_LOCK` / `_UNLOCK` | `RDL` / `RDU` | Lock / unlock the doors |
| `COMMAND_ENGINE_ON` / `_OFF` | `REON` / `REOFF` | Remote engine start / stop |
| `COMMAND_LIGHTS_HORN` | `HBLF` | Flash the lights and sound the horn |
| `COMMAND_LIGHTS` | `ROLIGHTS` | Flash the lights |
| `COMMAND_TRUNK_LOCK` / `_UNLOCK` | `ROTRUNKLOCK` / `ROTRUNKUNLOCK` | Lock / unlock the trunk |
| `COMMAND_LIFTGATE_LOCK` / `_UNLOCK` | `ROLIFTGATELOCK` / `ROLIFTGATEUNLOCK` | Lock / unlock the liftgate |
| `COMMAND_PRECOND_ON` / `_OFF` | `ROPRECOND` / `ROPRECOND_OFF` | EV cabin preconditioning on / off |
| `COMMAND_HVAC_ON` / `_OFF` | `ROHVACON` / `ROHVACOFF` | Climate control on / off |
| `COMMAND_COMFORT_ON` / `_OFF` | `ROCOMFORTON` / `ROCOMFORTOFF` | Comfort on / off (not sent by the current apps) |
| `COMMAND_CABIN_VENTILATION` | `ACV` | Cabin ventilation |
| `COMMAND_CHARGE` | `CNOW` | Start charging now |
| `COMMAND_DEEP_REFRESH` | `DEEPREFRESH` | Ask the vehicle to report a fresh EV status |
| `COMMAND_REFRESH_LOCATION` | `VF` | Ask the vehicle to report its location (`VF_B` is a variant) |
| `COMMAND_CLEAR_PERSONAL_DATA` | `ROCLRPERSDATA` | Clear the personal data stored in the head unit |

`Client.command()` sends the variant of a command that fits the vehicle, like
the official apps: `START_CHARGE` instead of `CNOW` for vehicles with the
`CNOW2` service, the v2 deep refresh for vehicles with `DEEPREFRESH2`, and
preconditioning instead of engine start/stop for vehicles that only support
that. If the API rejects a command with HTTP 400, 403 or 404 and it has a newer
variant, the variant is tried as well.

Vehicles with the `ROHVACTMP` service accept a target temperature for the
climate control:

```python
from py_uconnect import TemperatureUnit, hvac_params
from py_uconnect.command import COMMAND_HVAC_ON

await client.command_verify(vin, COMMAND_HVAC_ON, hvac_params(21.5))
await client.command_verify(
    vin, COMMAND_HVAC_ON, hvac_params(70, TemperatureUnit.FAHRENHEIT)
)
```

### EV charging

```python
from py_uconnect import ChargingLevel

await client.set_charging_level_verify(vin, ChargingLevel.LEVEL_THREE)

# Disable the first schedule
schedules = client.vehicles[vin].charge_schedules
schedules[0]["enableScheduleType"] = False
await client.set_charge_schedules_verify(vin, schedules)
```

`max_soc` is only supported by vehicles with the `CSETTING2` service. The
schedule format depends on the vehicle's schedule service, see
[docs/API.md](docs/API.md#schedules); the client picks the right endpoint.

## Other endpoints

`client.api` is the low-level `API` client: one method per endpoint, returning
the decoded JSON as-is. For example:

```python
report = await client.api.get_vehicle_health_report(vin)
recalls = await client.api.get_recalls(vin)
trip = await client.api.get_last_trip(vin)
alerts = await client.api.get_drive_alerts(vin)
await client.api.send_destination(vin, 45.0703, 7.6869, "Office")
```

| Area | Methods |
| --- | --- |
| Vehicle | `list_vehicles`, `get_vehicle_info`, `get_remote_status`, `get_vehicle_location`, `get_vehicle_health_report`, `get_vehicle_image`, `get_vehicle_equipment`, `get_vehicle_preferences`, `get_stolen_vehicle_status`, `get_vehicle_subscription`, `set_vehicle_nickname` |
| Maintenance | `get_maintenance_history`, `get_recommended_maintenance`, `get_recalls`, `dismiss_recalls` |
| Notifications | `get_vehicle_notifications`, `get_account_notifications` |
| Remote operations | `command`, `pin_auth`, `get_remote_operation_status`, `get_remote_operation_last_status`, `get_remote_climate_configuration`, `send_destination` |
| EV | `set_charging_level`, `set_charge_schedules` |
| Trips | `get_trips`, `get_last_trip`, `get_trip`, `get_trip_summary`, `get_trip_report_settings` |
| Eco-coaching | `get_eco_coaching_profiles`, `get_eco_coaching_last_trip`, `get_eco_coaching_best_trip`, `get_eco_coaching_trips`, `get_eco_coaching_monthly`, `get_eco_coaching_daily`, `get_eco_coaching_suggestions`, `get_eco_coaching_history` |
| Alerts | `get_drive_alerts`, `set_drive_alerts`, `get_theft_alarm_status`, `set_theft_alarm_notifications` |

Methods that change something require the PIN and return the correlation ID
of the operation, which can be passed to `client.wait_for_operation()`.

See [docs/API.md](docs/API.md) for the endpoints behind them. Endpoints without a method
can be called with `client.api.request()`. `{uid}` in the path is replaced with
the account UID:

```python
r = await client.api.request("GET", f"/v1/accounts/{{uid}}/vehicles/{vin}/vhr/")
```

## Errors

All errors derive from `py_uconnect.UconnectError`:

| Exception | Raised when |
| --- | --- |
| `AuthenticationError` | The login was rejected (wrong credentials, account problems) |
| `PinAuthenticationError` | The PIN is missing or was rejected |
| `APIError` | The API returned an unexpected status or response (`status`, `url` and `body` attributes) |
| `UconnectConnectionError` | Network error or timeout |
| `CommandError` | A command was not accepted |
| `CommandTimeoutError` | No command result was reported in time |

## Logging

The library logs to the `py_uconnect` logger. At `DEBUG` level it logs the API
responses, which include vehicle data and location.

```python
logging.getLogger("py_uconnect").setLevel(logging.DEBUG)
```

## Command line

```sh
export UCONNECT_BRAND=FIAT_EU UCONNECT_EMAIL=foo@bar.com UCONNECT_PASSWORD=very_secret

uconnect vehicles                       # vehicles and their state as JSON
uconnect get get_vehicle_health_report VIN
uconnect --pin 1234 command VIN RDL     # lock the doors and wait for the result
uconnect raw GET '/v1/accounts/{uid}/vehicles/VIN/vhr/'
```

`python -m py_uconnect` works the same. Run `uconnect --help` for all options.

## Service delivery platform

North American vehicles report an `sdp` field naming the connected services
provider: `SXM` (SiriusXM Guardian) or `SPRINT` (Uconnect Access). It is `None`
in the other regions. The provider does not change the API: all vehicles of a
region use the same endpoints.

PIN authentication depends on the provider: the library uses the `sdp` of the
vehicle, as the apps do, so call `refresh()` (or `api.list_vehicles()`) before
sending commands.

If a SiriusXM Guardian vehicle does not show up, the account may still be a
legacy Mopar account. Log in once with the official app for your brand and
complete the account migration if it asks you to, then use the same
credentials with this library.

## Development

```sh
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
ruff check . && ruff format --check . && mypy && pytest
```

The tests use a fake HTTP session and don't need network access. To run a
read-only smoke test against your own account:

```sh
UCONNECT_EMAIL=... UCONNECT_PASSWORD=... UCONNECT_BRAND=FIAT_EU pytest tests/live -v
```
