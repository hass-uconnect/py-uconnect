# Uconnect cloud API reference

This describes the API used by the library, as implemented by the official
Android apps. The reference is the FIAT (`com.fca.myconnect.fiat`) and Jeep
North America (`com.fca.myconnect.nafta`) apps, version 1.99.705. Both apps
register the same endpoints; the other brand apps are built from the same code.

Paths, methods and JSON field names come from the decompiled apps and are
exact. Header values and API keys are encrypted in the apps; the library uses
the keys and headers of the web portal, which the API accepts as well.

## Hosts

| Purpose | EMEA, APAC | North America, LATAM |
| --- | --- | --- |
| Vehicle API | `https://channels.sdpr-01.fcagcv.com` | `https://channels.sdpr-02.fcagcv.com` |
| PIN authentication (MFA) | `https://mfa.fcl-01.fcagcv.com` | `https://mfa.fcl-02.fcagcv.com` |
| Token exchange | `https://authz.sdpr-01.fcagcv.com` | `https://authz.sdpr-02.fcagcv.com` |
| Cognito, AWS region | `eu-west-1` | `us-east-1` |

The login (Gigya / SAP Customer Data Cloud) site and API key differ per brand
and region, see `py_uconnect/brands.py`. The LATAM app
(`com.fca.myconnect.latam`) is the North American app with its own login site
(on `accounts.us1.gigya.com`), shared by all brands.

## Authentication

1. Gigya `accounts.webSdkBootstrap`, `accounts.login` (email, password) and
   `accounts.getJWT` return the account UID and a JWT.
2. `POST {authz}/v2/cognito/identity/token` with `{"gigya_token": <JWT>}`
   returns a Cognito `IdentityId` and `Token`. This request is not signed.
3. Cognito `GetCredentialsForIdentity` with
   `Logins: {"cognito-identity.amazonaws.com": <Token>}` returns temporary AWS
   credentials, valid for about an hour.
4. All vehicle API and MFA requests are signed with AWS Signature Version 4
   (service `execute-api`) and carry the `x-api-key` of the host.

The apps keep the Gigya session and only repeat steps 2-3 when the AWS
credentials expire. The library repeats the whole login, which is equivalent.

Remote commands and other changes need a PIN token:
`POST {mfa}/v1/accounts/{uid}/{sdp}/pin/authenticate/` with
`{"pin": <base64 of the PIN>}` returns `{"token", "expiry"}`. `{sdp}` is the
vehicle's `sdp` from the vehicle list (`ignite` if it has none). `expiry` is the
lifetime of the token in milliseconds; the token is reused until then. HTTP 423
means the PIN is locked.

## Asynchronous operations

Commands and settings changes return a `correlationId` (and usually
`responseStatus: "pending"`). The result is reported by:

- `GET /v1/accounts/{uid}/vehicles/{vin}/remote/{correlationId}/last-status/`
  (`status`), used by the apps for remote commands,
- `GET /v1/accounts/{uid}/vehicles/{vin}/remote/{correlationId}/status/`
  (`responseStatus`), used for location and deep refresh requests,
- the vehicle notifications, whose items carry the `correlationId` and
  `notification.data.status`.

`Client.wait_for_operation()` polls all three.

## Endpoints

`{uid}` is the account UID, `{vin}` the VIN. All paths are on the vehicle API
host unless noted.

### Vehicles

| Method | Path | Library | Notes |
| --- | --- | --- | --- |
| GET | `/v4/accounts/{uid}/vehicles/?stage=ALL&sdp=ALL&brand=<code>` | `list_vehicles` | Items include `services`, `sdp` and may include `vehicleInfo`, `phevInfo`, `location` |
| GET | `/v3/accounts/{uid}/vehicles/{vin}/status/` | `get_vehicle_info` | `vehicleInfo` and `evInfo` (including schedules) |
| GET | `/v4/accounts/{uid}/vehicles/{vin}/status/` | `get_vehicle_info(vin, "v4")` | Used for vehicles with the `CPCOOP` service |
| GET | `/v1/accounts/{uid}/vehicles/{vin}/remote/status/` | `get_remote_status` | Doors, windows, sunroof, trunk, liftgate, engine, climate. States: `LOCKED`, `UNLOCKED`, `OPENED`, `CLOSED`, `ON`, `OFF`, `AUTO`, `NA` |
| GET | `/v1/accounts/{uid}/vehicles/{vin}/location/lastknown/` | `get_vehicle_location` | |
| GET | `/v1/accounts/{uid}/vehicles/{vin}/vhr/` | `get_vehicle_health_report` | |
| POST | `/v4/accounts/{uid}/vehicles/{vin}/image/` | `get_vehicle_image` | `{"imageURLs": [{"id", "width", "height", "resp": "png"}]}` |
| GET | `/v1/accounts/{uid}/vehicles/{vin}/digitalglovebox/vehicleequipment/equipment/` | `get_vehicle_equipment` | |
| GET | `/v1/accounts/{uid}/vehicles/{vin}/preferences/` | `get_vehicle_preferences` | Emergency contacts, language, licence plate, units |
| GET | `/v1/accounts/{uid}/vehicles/{vin}/svla/status/` | `get_stolen_vehicle_status` | |
| GET | `/v1/accounts/{uid}/vehicles/{vin}/subscription/` | `get_vehicle_subscription` | |
| POST | `/v1/accounts/{uid}/vehicles/{vin}/nickname/` | `set_vehicle_nickname` | `{"nickname"}` |

### Maintenance and recalls

| Method | Path | Library | Notes |
| --- | --- | --- | --- |
| GET | `/v1/accounts/{uid}/vehicles/{vin}/maintenance/history/` | `get_maintenance_history` | |
| GET | `/v1/maintenance/recommended/?market&language&brand&model&year` | `get_recommended_maintenance` | |
| GET | `/v1/accounts/{uid}/vehicles/{vin}/recall/` | `get_recalls` | |
| POST | `/v1/accounts/{uid}/vehicles/{vin}/recall/dismiss/` | `dismiss_recalls` | `{"dismissItems": [<fcaCampaignId>]}` |

### Notifications

| Method | Path | Library | Notes |
| --- | --- | --- | --- |
| GET | `/v1/accounts/{uid}/vehicles/{vin}/notifications/?offset=N` | `get_vehicle_notifications` | |
| GET | `/v2/accounts/{uid}/notifications/?brand&since&till` | `get_account_notifications` | All vehicles; `since`/`till` in ms |

### Remote operations

| Method | Path | Library | Notes |
| --- | --- | --- | --- |
| POST | `/v1/accounts/{uid}/vehicles/{vin}/remote/` | `command` | See [commands](#remote-commands) |
| POST | `/v2/accounts/{uid}/vehicles/{vin}/remote/` | `command` | |
| POST | `/v1/accounts/{uid}/vehicles/{vin}/location/` | `command` | `VF`, `VF_B` |
| POST | `/v1/accounts/{uid}/vehicles/{vin}/ev/` | `command` | `DEEPREFRESH` |
| POST | `/v2/accounts/{uid}/vehicles/{vin}/ev/` | `command` | Deep refresh for vehicles with `DEEPREFRESH2` |
| POST | `/v1/accounts/{uid}/vehicles/{vin}/ev/chargenow/` | `command` | `CNOW` |
| POST | `/v4/accounts/{uid}/vehicles/{vin}/ev/chargenow/` | `command` | `START_CHARGE`, for vehicles with `CNOW2` |
| GET | `/v1/accounts/{uid}/vehicles/{vin}/remote/{correlationId}/last-status/` | `get_remote_operation_last_status` | |
| GET | `/v1/accounts/{uid}/vehicles/{vin}/remote/{correlationId}/status/` | `get_remote_operation_status` | |
| GET | `/v1/accounts/{uid}/vehicles/{vin}/remote/custom/configurations/` | `get_remote_climate_configuration` | Last climate target temperature |
| POST | `/v2/accounts/{uid}/vehicles/{vin}/sdv/location/` | `send_destination` | `{"command": "SDV", "params": {"location", "routePreference"}}`, no PIN |
| POST | `{mfa}/v1/accounts/{uid}/{sdp}/pin/authenticate/` | `pin_auth` | |

### EV

| Method | Path | Library | Notes |
| --- | --- | --- | --- |
| PUT | `/v2/accounts/{uid}/vehicles/{vin}/ev/charge/preference/` | `set_charging_level` | `{"preference": "LEVEL_ONE".."LEVEL_FIVE", "pinAuth", "maxSOC"?}`. `maxSOC` only for vehicles with `CSETTING2` |
| POST | `/v4/accounts/{uid}/vehicles/{vin}/ev/schedule/` | `set_charge_schedules` | See [schedules](#schedules) |
| POST | `/v3/accounts/{uid}/vehicles/{vin}/ev/schedule/` | `set_charge_schedules` | |
| POST | `/v2/accounts/{uid}/vehicles/{vin}/ev/schedule/` | `set_charge_schedules` | |
| POST | `/v1/accounts/{uid}/vehicles/{vin}/ev/chargeschedule/` | `set_charge_schedules` | |

### Trips and eco-coaching

| Method | Path | Library | Notes |
| --- | --- | --- | --- |
| GET | `/v2/accounts/{uid}/vehicles/{vin}/tripreport/trips/` | `get_trips` | `TRIPREPORT` service. The app passes a time range and paging whose parameter names are encrypted |
| GET | `/v2/accounts/{uid}/vehicles/{vin}/tripreport/trips/last/` | `get_last_trip` | |
| GET | `/v2/accounts/{uid}/vehicles/{vin}/tripreport/trips/{tripId}/` | `get_trip` | |
| GET | `/v2/accounts/{uid}/vehicles/{vin}/tripreport/summary/{daily,weekly,monthly}/` | `get_trip_summary` | Same parameter caveat as `trips/` |
| GET | `/v2/accounts/{uid}/vehicles/{vin}/tripreport/settings/` | `get_trip_report_settings` | |
| GET | `/v2/accounts/{uid}/vehicles/{vin}/ecocoaching/profiles/` | `get_eco_coaching_profiles` | |
| POST | `/v2/accounts/{uid}/vehicles/{vin}/ecocoaching/get-last-trip/` | `get_eco_coaching_last_trip` | `{"profile"?}` |
| POST | `/v2/accounts/{uid}/vehicles/{vin}/ecocoaching/get-best-trip/` | `get_eco_coaching_best_trip` | `{"profile"?}` |
| POST | `/v2/accounts/{uid}/vehicles/{vin}/ecocoaching/get-trips/` | `get_eco_coaching_trips` | `{"since", "till", "offset", "size", "profile"?}`, ms timestamps; the app asks for the last 7 days |
| POST | `/v2/accounts/{uid}/vehicles/{vin}/ecocoaching/get-trips/monthly/` | `get_eco_coaching_monthly` | `since` is 0 |
| POST | `/v2/accounts/{uid}/vehicles/{vin}/ecocoaching/get-trips/daily/` | `get_eco_coaching_daily` | No body |
| GET | `/v2/accounts/{uid}/vehicles/{vin}/ecocoaching/suggestions/` | `get_eco_coaching_suggestions` | |
| GET | `/v1/accounts/{uid}/vehicles/{vin}/ecocoaching/?groupby&since&till&offset&limit` | `get_eco_coaching_history` | Older vehicles (`ECODRIVE`, `ECOCOACHINGR1`); `groupby` is `trips`, `day` or `month` |

### Drive alerts and theft alarm

| Method | Path | Library | Notes |
| --- | --- | --- | --- |
| GET | `/v3/accounts/{uid}/vehicles/{vin}/parentalcontrols/config/` | `get_drive_alerts` | `geofence`, `curfew`, `speed`, `valet` |
| POST | `/v4/accounts/{uid}/vehicles/{vin}/parentalcontrols/config/` | `set_drive_alerts` | Same format plus `pinAuth` |
| GET | `/v1/accounts/{uid}/vehicles/{vin}/theft/status/` | `get_theft_alarm_status` | |
| POST | `/v1/accounts/{uid}/vehicles/{vin}/theft/alarm/` | `set_theft_alarm_notifications` | `{"enabled", "pinAuth", "suspensionDuration"?}` |

## Remote commands

The body is `{"command": <name>, "pinAuth": <token>}` with an optional
`params` object. The apps send these eight commands to `/v1/.../remote/` and
every other remote operation to `/v2/.../remote/`: `HBLF`, `RDL`, `RDU`,
`REON`, `REOFF`, `ROLIGHTS`, `ROPRECOND`, `ROPRECOND_OFF`.

A command is offered when the vehicle has the service of the same name enabled
(`services[].serviceEnabled`). Exceptions:

- `CNOW` is also enabled by `CNOW2`. Vehicles with `CNOW2` get `START_CHARGE`
  on `/v4/.../ev/chargenow/`.
- `DEEPREFRESH` is also enabled by `DEEPREFRESH2`. Vehicles with
  `DEEPREFRESH2` get it on `/v2/.../ev/`. The command name the app sends there
  is encrypted; it is most likely `DEEPREFRESH`, the library falls back to
  `DEEPREFRESH2` if it is rejected.
- `REON`/`REOFF` are replaced by `ROPRECOND`/`ROPRECOND_OFF` on vehicles that
  only support preconditioning.
- `ROHVACTMP` is a capability flag, not a command: vehicles with it accept a
  target temperature in the `params` of `ROHVACON`:
  `{"interiorTemperature": 22 | 72, "temperatureUOM": "Celsius" | "Fahrenheit",
  "fanSpeed": 50, "targetTemp": <temperature>, "timeoutAfterTemp": 0,
  "preTripTimeout": 15}` (`hvac_params()`).
- `ROCOMFORTON`/`ROCOMFORTOFF` exist as services but are not sent by the
  current apps.

`Client.command()` applies these rules for vehicles loaded by `refresh()`.

## Schedules

The current charge and climate schedules are part of the vehicle status
(`evInfo`). They are changed through an endpoint that depends on the vehicle's
schedule service; the first one enabled in this order is used:

| Service (`command`) | Endpoint | Field |
| --- | --- | --- |
| `CPCOOP` | `POST /v4/.../ev/schedule/` | `chargeSchedulesV4` |
| `BCPCHRG`, `BCPPLUS`, `CPCHRG2`, `CPPLUSPHEV`, `CPPLUSBEV` | `POST /v3/.../ev/schedule/` | `chargeSchedulesV3` |
| `CPPLUS` | `POST /v2/.../ev/schedule/` | `schedules` |
| `CP` | `POST /v1/.../ev/chargeschedule/` | `chargeSchedules` |

A v3/v4 schedule has `scheduleType` (`CHARGE`, `CLIMATE`, `NONE`), `startTime`
and `endTime` (`HH:mm`), `scheduledDays` (`monday`..`sunday` booleans),
`enableScheduleType`, `repeatSchedule`, `chargeToFull`, and optionally
`targetSoc`, `minSoc`, `climateParameters` and `climateSettings`
(`{"celsius"}` or `{"fahrenheit"}`). v2 schedules have `cabinPriority` instead
of the climate fields. v1 schedules have `scheduleType` (`WEEKDAY`,
`WEEKEND`), `scheduleStartTime`, `scheduleEndTime`, `chargeUntilFull` and
`enableChargeSchedule` (`ENABLE_SCHEDULE`, `DISABLE_SCHEDULE`).

## Not implemented

These endpoints exist in the apps but have no dedicated method. They can be
called with `API.request()`.

- Dynamic range map: `GET /v1/.../dynamicRangeMap/` and `/dynamic-range-map/`
  (the query parameter names are encrypted), settings at
  `/v1/accounts/{uid}/feature-settings/dynamic-range-mapping/`.
- Alert contacts: `/v2/.../contacts/` and their notification preferences.
- Changing vehicle preferences: `PATCH /v1/.../preferences/`.
- Adding and deleting own maintenance records:
  `PUT /v1/.../maintenance/history/`, `POST /v1/.../maintenance/delete-history/`.
- Trip report settings changes: `POST /v2/.../tripreport/settings/...`.
- Jeep off-road pages: `/v1|v2/.../offroadpages/...`.
- Notification summary: `GET /v1/accounts/{uid}/notifications/summary/`.

Out of scope: account and PIN management, consents and legal documents,
dealers, service appointments, payments and store, digital key, navigation
content, marketing and app configuration.
