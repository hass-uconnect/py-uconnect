# Changelog

## 1.0.2

### Added

- LATAM (Brazil) configurations `JEEP_LATAM`, `FIAT_LATAM` and `RAM_LATAM`:
  the login site of the LATAM app with the North American backend.

### Fixed

- `Vehicle.distance_to_empty` is the fuel range again when the battery range
  is zero, as reported by vehicles with a combustion engine and by plug-in
  hybrids with an empty battery. 1.0.0 reported 0 for them.

## 1.0.0

A rewrite of the library as an asyncio client. It is not backwards compatible,
see the migration guide below.

### Changed

- The library is async and based on `aiohttp`. `Client` and `API` accept an
  optional `aiohttp.ClientSession` (e.g. Home Assistant's shared session);
  otherwise they create one and close it in `close()` / `async with`.
- `boto3`, `requests`, `requests-auth-aws-sigv4` and `dataclasses_json` are no
  longer dependencies, `aiohttp` is the only one. Cognito credentials are
  obtained with a plain HTTPS call and requests are signed by a built-in SigV4
  implementation.
- Errors are reported with a dedicated exception hierarchy instead of bare
  `Exception`s (see below).
- Python 3.11 or newer is required.
- `Vehicle`: `year` is an `int`, `charging_level_preference` is a
  `ChargingLevel` and numeric-looking strings such as a nickname of `"500"`
  are no longer converted to numbers. Timestamps are timezone-aware (UTC).
  The raw API responses are available as `raw_list_item`, `raw_info`,
  `raw_remote_status` and `raw_location`.
- `Client.refresh()` loads all vehicles concurrently, returns the vehicles,
  removes vehicles that are no longer in the account and keeps vehicles whose
  detailed status endpoint is not supported, with the data that is available.
- `wait_for_operation()` (used by the `*_verify()` methods) accepts float
  intervals and raises `CommandTimeoutError` on timeout.

### Updated to the current official apps

The endpoints were checked against the decompiled FIAT and Jeep (North America)
Android apps, version 1.99.705. See [docs/API.md](docs/API.md).

- Eco-coaching requests send the body the apps send (they had none).
- PIN authentication uses the vehicle's service delivery platform (`sdp`) in
  the path instead of always `ignite`, and the PIN token is reused until it
  expires.
- `ROHVACON` accepts a target temperature (`hvac_params()`). `ROHVACTMP` is a
  capability, not a command.
- `Client.command()` sends the variant of a command that fits the vehicle:
  `START_CHARGE` for vehicles with `CNOW2`, the v2 deep refresh for vehicles
  with `DEEPREFRESH2`, preconditioning instead of engine start/stop where only
  that is supported. Fallbacks also apply to HTTP 400 and 404.
- Charge schedules are set through the endpoint matching the vehicle's
  schedule service (v1 to v4) and are read from the vehicle status.
- The status endpoint version is chosen by the `CPCOOP` service.
- Operation results are also polled from the `last-status` endpoint the apps
  use for remote commands.
- Vehicle notifications page with `offset`.
- Paths have the trailing slashes the apps use.

### Added

- Endpoints: trip reports, more eco-coaching, drive alerts (geofence, curfew,
  speed, valet), recalls, account notifications, send a destination to the
  vehicle, theft alarm notifications, climate target temperature, vehicle
  preferences and equipment, recommended maintenance.
- Commands: `COMMAND_CLEAR_PERSONAL_DATA` (`ROCLRPERSDATA`) and
  `COMMAND_REFRESH_LOCATION_B` (`VF_B`).
- `Vehicle`: `window_rear_left_closed`, `window_rear_right_closed`,
  `sunroof_closed`, `liftgate_locked`, `hvac_on`, `hvac_temperature`,
  `charge_schedules`, `privacy_mode`. `NA` states are reported as `None`
  instead of `False`. Status snapshots included in the vehicle list are used
  when the detailed status is not available.
- `Vehicle.supports(cmd)`, `API.request()` for arbitrary endpoints, the
  `uconnect` command line tool.

### Removed

- `dev_mode`, `trace`, `set_debug()`, `disable_tls_verification` and
  `set_tls_verification()`. Configure logging with
  `logging.getLogger("py_uconnect")` and TLS through the session you pass in.
- `update_location()`: send `COMMAND_REFRESH_LOCATION` instead.
- `COMMAND_HVAC_TARGET_TEMP`: send `COMMAND_HVAC_ON` with `hvac_params()`.
- `get_charge_schedules()`, which used an endpoint the apps don't use: the
  schedules are in `Vehicle.charge_schedules`.
- `COMMAND_CHARGE_V4` and `COMMAND_DEEP_REFRESH_V2` are no longer in
  `COMMANDS`; they are selected automatically.
- The pass-through methods on `Client` for single endpoints: call them on
  `client.api`.
- `cli.py`: use `python -m py_uconnect` or the `uconnect` command.

### Migration guide

| 0.x | 1.0 |
| --- | --- |
| `client = Client(...)` | `async with Client(..., session=session) as client:` |
| `client.refresh()` | `await client.refresh()` |
| `client.command_verify(vin, cmd)` | `await client.command_verify(vin, cmd)` |
| `client.get_vehicle_health_report(vin)` (and other endpoint helpers) | `await client.api.get_vehicle_health_report(vin)` |
| `api.get_vehicle(vin)` | `await api.get_vehicle_info(vin)` |
| `api.get_vehicle_status(vin)` | `await api.get_remote_status(vin)` |
| `api.update_location(vin)` | `await api.command(vin, COMMAND_REFRESH_LOCATION)` |
| `api.get_vehicle_notifications(vin, limit=30)` | `await api.get_vehicle_notifications(vin, offset=0)` |
| `api.get_charge_schedules(vin)` | `client.vehicles[vin].charge_schedules` |
| `client.set_charge_schedule(vin, schedule)` | `await client.set_charge_schedules(vin, schedules)` |
| `client.command(vin, COMMAND_HVAC_TARGET_TEMP)` | `await client.command(vin, COMMAND_HVAC_ON, hvac_params(21))` |
| `cmd.name in vehicle.supported_commands` | unchanged, or `vehicle.supports(cmd)`; `CNOW2`/`DEEPREFRESH2` now enable `CNOW`/`DEEPREFRESH` |
| `from py_uconnect.api import CHARGING_LEVEL_ONE, CHARGING_LEVELS_BY_NAME` | `from py_uconnect import ChargingLevel`; `ChargingLevel.LEVEL_ONE`, `ChargingLevel[name]` |
| `brand.auth.url` / `brand.auth.token` | `brand.mfa.url` / `brand.mfa.key` |
| `vehicle.to_json(indent=2)` | unchanged; `vehicle.to_dict()` is new |
| `except Exception` | `except UconnectError` (or a subclass) |

Exceptions:

- `UconnectError`: base class
- `AuthenticationError`: the account login was rejected
- `PinAuthenticationError`: the PIN was rejected or is missing
- `APIError`: unexpected HTTP status or response, with `status`, `url` and `body`
- `UconnectConnectionError`: network error or timeout
- `CommandError`: a command was not accepted
- `CommandTimeoutError`: no command result within the timeout
