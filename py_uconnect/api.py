"""Low-level async client for the Uconnect cloud API.

Every method maps to a single endpoint and returns the decoded JSON response
as-is. Paths, methods and bodies follow the official Android apps (version
1.99.705), see docs/API.md. See :class:`py_uconnect.Client` for a higher-level
interface.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import time
from datetime import UTC, datetime, timedelta
from types import TracebackType
from typing import Any, Literal, Self

import aiohttp
from yarl import URL

from . import auth, sigv4
from ._http import api_headers, parse_json
from .brands import Brand, Endpoint
from .command import SCHEDULE_ENDPOINTS_BY_COMMAND, Command
from .exceptions import (
    APIError,
    CommandError,
    PinAuthenticationError,
    UconnectConnectionError,
)
from .models import ChargingLevel, TheftAlarmSuppression

_LOGGER = logging.getLogger(__name__)

JSON = dict[str, Any]

# Versions of the vehicle status endpoint. The apps use v4 for vehicles with
# the CPCOOP service and v3 otherwise.
STATUS_API_VERSIONS = ("v3", "v4")

# Service delivery platform used in the PIN authentication path when the
# vehicle does not report one
DEFAULT_SDP = "ignite"

# A cached PIN authentication token is renewed this long before it expires
PIN_TOKEN_MARGIN = 15

# Statuses that make a command fall back to its newer variant
FALLBACK_STATUSES = (400, 403, 404)

FAILED_STATUSES = ("failure", "failed", "error", "rejected")

# Time range used by the app when listing eco-coaching trips
ECO_COACHING_TRIPS_RANGE = timedelta(days=7)


def _is_expired_token_error(status: int, body: Any) -> bool:
    if status not in (401, 403):
        return False

    msg = str(body.get("message", "") if isinstance(body, dict) else body).lower()
    return "expired" in msg and ("token" in msg or "signature" in msg)


def _correlation_id(r: JSON, what: str) -> str:
    """Extracts the correlation ID of an accepted asynchronous operation"""

    cid = r.get("correlationId")
    status = r.get("responseStatus") or r.get("requestStatus")

    if (
        not isinstance(cid, str)
        or not cid
        or (isinstance(status, str) and status.lower() in FAILED_STATUSES)
    ):
        reason = r.get("debugMsg") or r.get("message") or status
        raise CommandError(
            f"{what} was not accepted: {reason or 'no correlation ID in response'}"
        )

    return cid


def _ms(v: datetime | int) -> int:
    """Converts a datetime to a millisecond Unix timestamp"""

    return round(v.timestamp() * 1000) if isinstance(v, datetime) else v


def _drop_none(d: JSON) -> JSON:
    return {k: v for k, v in d.items() if v is not None}


class API:
    """Low-level async Uconnect API client.

    If no ``session`` is given, one is created on first use and closed by
    :meth:`close` (or when used as an async context manager). A session passed
    in is never closed by the client.
    """

    def __init__(
        self,
        email: str,
        password: str,
        pin: str | None,
        brand: Brand,
        *,
        session: aiohttp.ClientSession | None = None,
        timeout: float = 30,
    ):
        self.email = email
        self._pin = pin
        self.password = password
        self.brand = brand

        self._session = session
        self._owns_session = session is None
        self._timeout = aiohttp.ClientTimeout(total=timeout)

        self._credentials: auth.Credentials | None = None
        self._login_lock = asyncio.Lock()
        self._status_api_version: dict[str, str] = {}
        # Service delivery platform of the vehicles, from the vehicle list
        self._sdp: dict[str, str] = {}
        # Cached PIN authentication tokens per SDP: (token, monotonic expiry)
        self._pin_tokens: dict[str, tuple[str, float]] = {}

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.close()

    async def close(self) -> None:
        """Closes the HTTP session if it was created by the client"""

        if self._owns_session and self._session is not None:
            await self._session.close()
            self._session = None

    def _http(self) -> aiohttp.ClientSession:
        if self._session is None:
            self._session = aiohttp.ClientSession()
            self._owns_session = True

        return self._session

    @property
    def pin(self) -> str | None:
        """PIN used to authorize remote commands"""

        return self._pin

    @pin.setter
    def pin(self, pin: str | None) -> None:
        self._pin = pin
        self._pin_tokens.clear()

    @property
    def uid(self) -> str | None:
        """Account UID, available after login"""

        return self._credentials.uid if self._credentials else None

    async def login(self) -> None:
        """Logs in and caches the credentials.

        Calling this is optional: the other methods log in automatically and
        renew the credentials when they are about to expire. It is useful to
        check the account credentials.
        """

        async with self._login_lock:
            self._credentials = await auth.login(
                self._http(), self.brand, self.email, self.password, self._timeout
            )

    async def _ensure_credentials(self) -> auth.Credentials:
        creds = self._credentials
        if creds is not None and not creds.expires_soon():
            return creds

        async with self._login_lock:
            creds = self._credentials
            if creds is None or creds.expires_soon():
                creds = await auth.login(
                    self._http(), self.brand, self.email, self.password, self._timeout
                )
                self._credentials = creds

        return creds

    async def request(
        self,
        method: str,
        path: str,
        *,
        endpoint: Endpoint | None = None,
        params: dict[str, Any] | None = None,
        body: Any = None,
        _retry: bool = True,
    ) -> Any:
        """Sends a signed request to the API and returns the decoded JSON response.

        ``{uid}`` in ``path`` is replaced with the account UID. ``endpoint``
        defaults to the brand's vehicle API. This is public to allow calling
        endpoints that do not have a dedicated method.
        """

        creds = await self._ensure_credentials()
        endpoint = endpoint or self.brand.api

        url = URL(endpoint.url).with_path(path.replace("{uid}", creds.uid))
        if params:
            url = url.with_query({k: str(v) for k, v in params.items()})

        data = json.dumps(body).encode() if body is not None else b""
        headers = api_headers(self.brand, endpoint.key)
        headers |= sigv4.sign(
            method,
            str(url),
            headers,
            data,
            creds.aws,
            self.brand.region,
            "execute-api",
        )

        try:
            async with self._http().request(
                method,
                url,
                headers=headers,
                data=data or None,
                timeout=self._timeout,
            ) as resp:
                status = resp.status
                text = await resp.text()
        except (aiohttp.ClientError, TimeoutError) as err:
            raise UconnectConnectionError(f"{method} {url.path}: {err!r}") from err

        _LOGGER.debug("%s %s: HTTP %s: %s", method, url.path, status, text)
        r = parse_json(text) if text else None

        if _retry and _is_expired_token_error(status, r if r is not None else text):
            _LOGGER.debug("Credentials expired, logging in again")
            self._credentials = None
            return await self.request(
                method, path, endpoint=endpoint, params=params, body=body, _retry=False
            )

        if status >= 400:
            raise APIError(
                f"{method} {url.path}: HTTP {status}",
                status=status,
                url=str(url),
                body=r if r is not None else text,
            )

        if text and r is None:
            raise APIError(
                f"{method} {url.path}: invalid JSON response",
                status=status,
                url=str(url),
                body=text,
            )

        return r

    async def _request_json(self, method: str, path: str, **kwargs: Any) -> JSON:
        r = await self.request(method, path, **kwargs)

        if r is None:
            return {}

        if not isinstance(r, dict):
            raise APIError(f"{method} {path}: expected a JSON object", body=r)

        return r

    async def _get(self, version: str, vin: str, suffix: str, **kwargs: Any) -> JSON:
        return await self._request_json(
            "GET", self._vehicle_path(version, vin, suffix), **kwargs
        )

    async def _post(self, version: str, vin: str, suffix: str, **kwargs: Any) -> JSON:
        return await self._request_json(
            "POST", self._vehicle_path(version, vin, suffix), **kwargs
        )

    @staticmethod
    def _vehicle_path(version: str, vin: str, suffix: str = "") -> str:
        return f"/{version}/accounts/{{uid}}/vehicles/{vin}/{suffix}"

    # Vehicles

    async def list_vehicles(self) -> list[JSON]:
        """Lists the vehicles of the account with general information.

        Each item has keys like ``vin``, ``nickname``, ``make``,
        ``modelDescription``, ``year``, ``soldRegion``, ``fuelType``, ``sdp``
        and ``services`` (the services and whether they are enabled). It may
        also contain ``vehicleInfo``, ``phevInfo`` and ``location``.
        """

        r = await self._request_json(
            "GET",
            "/v4/accounts/{uid}/vehicles/",
            params={"stage": "ALL", "sdp": "ALL", "brand": self.brand.brand_code},
        )

        vehicles = r.get("vehicles")
        if not isinstance(vehicles, list):
            raise APIError("list_vehicles: no vehicles in response", body=r)

        for v in vehicles:
            if isinstance(v, dict) and v.get("vin") and v.get("sdp"):
                self._sdp[v["vin"]] = v["sdp"]

        return vehicles

    async def get_vehicle_info(self, vin: str, version: str | None = None) -> JSON:
        """Gets the detailed vehicle status: ``vehicleInfo`` (odometer, fuel,
        battery, tyres, service...) and ``evInfo`` (EV battery, charging and
        schedules).

        The apps use v4 for vehicles with the ``CPCOOP`` service and v3
        otherwise; ``version`` selects it. If the selected version is not
        supported by the vehicle, the other one is tried. The working version
        is remembered per vehicle.
        """

        versions = list(STATUS_API_VERSIONS)
        if (preferred := self._status_api_version.get(vin) or version) is not None:
            versions.remove(preferred)
            versions.insert(0, preferred)

        for i, v in enumerate(versions):
            try:
                r = await self._get(v, vin, "status/")
            except APIError as err:
                if err.status not in (400, 404, 502) or i == len(versions) - 1:
                    raise

                _LOGGER.debug(
                    "%s: status %s failed with HTTP %s, trying the next version",
                    vin,
                    v,
                    err.status,
                )
                continue

            self._status_api_version[vin] = v
            return r

        raise AssertionError("unreachable")

    async def get_remote_status(self, vin: str) -> JSON:
        """Gets the state of doors, windows, trunk, liftgate, engine, climate..."""

        return await self._get("v1", vin, "remote/status/")

    async def get_vehicle_location(self, vin: str) -> JSON:
        """Gets the last known location of the vehicle"""

        return await self._get("v1", vin, "location/lastknown/")

    async def get_vehicle_health_report(self, vin: str) -> JSON:
        """Gets the vehicle health report"""

        return await self._get("v1", vin, "vhr/")

    async def get_vehicle_image(
        self, vin: str, width: int = 600, height: int = 340
    ) -> JSON:
        """Gets a URL of a rendered image of the vehicle
        (``items[].preciseImageURL``)"""

        return await self._post(
            "v4",
            vin,
            "image/",
            body={
                "imageURLs": [
                    {"id": vin, "width": width, "height": height, "resp": "png"}
                ]
            },
        )

    async def get_vehicle_equipment(self, vin: str) -> JSON:
        """Gets the equipment of the vehicle (digital glovebox)"""

        return await self._get("v1", vin, "digitalglovebox/vehicleequipment/equipment/")

    async def get_vehicle_preferences(self, vin: str) -> JSON:
        """Gets the vehicle preferences: emergency contacts, language, licence
        plate and units"""

        return await self._get("v1", vin, "preferences/")

    async def get_stolen_vehicle_status(self, vin: str) -> JSON:
        """Gets the stolen vehicle locator (SVLA) status"""

        return await self._get("v1", vin, "svla/status/")

    async def get_vehicle_subscription(self, vin: str) -> JSON:
        """Gets the connected services subscriptions"""

        return await self._get("v1", vin, "subscription/")

    async def set_vehicle_nickname(self, vin: str, nickname: str) -> JSON:
        """Sets the nickname of the vehicle"""

        return await self._post("v1", vin, "nickname/", body={"nickname": nickname})

    # Maintenance and recalls

    async def get_maintenance_history(self, vin: str) -> JSON:
        """Gets the maintenance history"""

        return await self._get("v1", vin, "maintenance/history/")

    async def get_recommended_maintenance(
        self, market: str, language: str, brand: str, model: str, year: int | str
    ) -> JSON:
        """Gets the recommended maintenance plan for a model"""

        return await self._request_json(
            "GET",
            "/v1/maintenance/recommended/",
            params={
                "market": market,
                "language": language,
                "brand": brand,
                "model": model,
                "year": year,
            },
        )

    async def get_recalls(self, vin: str) -> JSON:
        """Gets the recall campaigns of the vehicle (``recallDetails``)"""

        return await self._get("v1", vin, "recall/")

    async def dismiss_recalls(self, vin: str, campaign_ids: list[str]) -> JSON:
        """Dismisses recalls by their ``fcaCampaignId``"""

        return await self._post(
            "v1", vin, "recall/dismiss/", body={"dismissItems": campaign_ids}
        )

    # Notifications

    async def get_vehicle_notifications(
        self, vin: str, offset: int | None = None
    ) -> JSON:
        """Gets the notifications of the vehicle, including command results.
        Pages through older ones with ``offset``."""

        return await self._get(
            "v1",
            vin,
            "notifications/",
            params={"offset": offset} if offset is not None else None,
        )

    async def get_account_notifications(
        self, since: datetime | int | None = None, till: datetime | int | None = None
    ) -> JSON:
        """Gets the notifications of all vehicles of the account"""

        return await self._request_json(
            "GET",
            "/v2/accounts/{uid}/notifications/",
            params=_drop_none(
                {
                    "brand": self.brand.brand_code,
                    "since": _ms(since) if since is not None else None,
                    "till": _ms(till) if till is not None else None,
                }
            ),
        )

    # Remote operations

    async def get_remote_operation_status(self, vin: str, correlation_id: str) -> JSON:
        """Gets the status of a remote operation (``responseStatus``), used by
        the apps for location and deep refresh requests"""

        return await self._get("v1", vin, f"remote/{correlation_id}/status/")

    async def get_remote_operation_last_status(
        self, vin: str, correlation_id: str
    ) -> JSON:
        """Gets the status of a remote operation (``status``), used by the
        apps for remote commands"""

        return await self._get("v1", vin, f"remote/{correlation_id}/last-status/")

    async def get_remote_climate_configuration(self, vin: str) -> JSON:
        """Gets the last climate target temperature
        (``hvac.targetTemp``, ``hvac.temperatureUOM``)"""

        return await self._get("v1", vin, "remote/custom/configurations/")

    async def pin_auth(self, vin: str | None = None) -> str:
        """Authenticates with the PIN and returns a ``pinAuth`` token.

        The token is required by remote commands and other operations that
        change the state of the vehicle. It is cached until it expires. The
        authentication depends on the service delivery platform of the
        vehicle, which is known for the vehicles returned by
        :meth:`list_vehicles`.
        """

        if not self.pin:
            raise PinAuthenticationError("a PIN is required for this operation")

        sdp = (self._sdp.get(vin) if vin else None) or DEFAULT_SDP

        cached = self._pin_tokens.get(sdp)
        if cached is not None and time.monotonic() < cached[1]:
            return cached[0]

        try:
            r = await self._request_json(
                "POST",
                f"/v1/accounts/{{uid}}/{sdp}/pin/authenticate/",
                endpoint=self.brand.mfa,
                body={"pin": base64.b64encode(self.pin.encode()).decode()},
            )
        except APIError as err:
            if err.status is not None and 400 <= err.status < 500:
                raise PinAuthenticationError(
                    f"PIN authentication failed: HTTP {err.status}: {err.body}"
                ) from err
            raise

        token = r.get("token")
        if not isinstance(token, str) or not token:
            raise PinAuthenticationError(f"PIN authentication failed: {r}")

        # The expiry is a lifetime in milliseconds
        expiry = r.get("expiry")
        if isinstance(expiry, int | float) and expiry / 1000 > PIN_TOKEN_MARGIN:
            self._pin_tokens[sdp] = (
                token,
                time.monotonic() + expiry / 1000 - PIN_TOKEN_MARGIN,
            )

        return token

    async def _send_command(
        self, vin: str, cmd: Command, pin_auth: str, params: JSON | None
    ) -> str:
        body: JSON = {"command": cmd.name, "pinAuth": pin_auth}
        if params is not None:
            body["params"] = params

        r = await self._post(cmd.api_version, vin, cmd.url, body=body)
        return _correlation_id(r, f"command {cmd}")

    async def command(self, vin: str, cmd: Command, params: JSON | None = None) -> str:
        """Sends a remote command and returns the correlation ID of the operation.

        ``params`` is sent along, e.g. the target temperature of ``ROHVACON``
        (see :func:`py_uconnect.command.hvac_params`). If the API rejects the
        command with HTTP 400, 403 or 404 and the command has a fallback, the
        fallback is sent instead.
        """

        pin_auth = await self.pin_auth(vin)

        while True:
            try:
                return await self._send_command(vin, cmd, pin_auth, params)
            except APIError as err:
                if err.status not in FALLBACK_STATUSES or cmd.fallback is None:
                    raise

                _LOGGER.info(
                    "%s: command %s (%s) returned HTTP %s, retrying with %s (%s)",
                    vin,
                    cmd,
                    cmd.api_version,
                    err.status,
                    cmd.fallback,
                    cmd.fallback.api_version,
                )
                cmd = cmd.fallback

    async def send_destination(
        self,
        vin: str,
        latitude: float,
        longitude: float,
        name: str | None = None,
        *,
        address: JSON | None = None,
        route_preference: str = "Fast",
        **location: Any,
    ) -> str:
        """Sends a destination to the navigation system of the vehicle.
        Returns the correlation ID.

        ``address`` may contain ``streetName``, ``houseNumber``,
        ``postalNumber``, ``cityName``, ``provinceName``, ``provinceCode``,
        ``countryName`` and ``countryCode``. Other keyword arguments are added
        to the location (e.g. ``phoneNumber``, ``poiDescription``, ``url``).
        """

        loc = _drop_none(
            {
                "latitude": latitude,
                "longitude": longitude,
                "name": name,
                "address": address,
            }
        )
        r = await self._post(
            "v2",
            vin,
            "sdv/location/",
            body={
                "command": "SDV",
                "params": {
                    "location": loc | location,
                    "routePreference": route_preference,
                },
            },
        )

        return _correlation_id(r, "send destination")

    # EV

    async def set_charge_schedules(
        self, vin: str, command: str, schedules: list[JSON]
    ) -> str:
        """Sets the EV charge and climate schedules, returns the correlation ID.

        ``command`` is the schedule service of the vehicle, which determines
        the endpoint and the format of the schedules (see
        :data:`py_uconnect.command.SCHEDULE_ENDPOINTS`). The current schedules
        are part of the vehicle status (``evInfo``).
        """

        ep = SCHEDULE_ENDPOINTS_BY_COMMAND.get(command)
        if ep is None:
            raise ValueError(f"unknown schedule command: {command}")

        pin_auth = await self.pin_auth(vin)

        r = await self._post(
            ep.api_version,
            vin,
            ep.url,
            body={"command": command, "pinAuth": pin_auth, ep.field: schedules},
        )

        return _correlation_id(r, "set charge schedules")

    async def set_charging_level(
        self, vin: str, level: ChargingLevel, max_soc: int | None = None
    ) -> str:
        """Sets the charging power preference and optionally the maximum state
        of charge in percent (only for vehicles with the ``CSETTING2``
        service). Returns the correlation ID.
        """

        if max_soc is not None and not 0 < max_soc <= 100:
            raise ValueError(f"max_soc must be between 1 and 100, got {max_soc}")

        pin_auth = await self.pin_auth(vin)

        body: JSON = {"preference": ChargingLevel(level).value, "pinAuth": pin_auth}
        if max_soc is not None:
            body["maxSOC"] = str(max_soc)

        r = await self._request_json(
            "PUT", self._vehicle_path("v2", vin, "ev/charge/preference/"), body=body
        )

        return _correlation_id(r, "set charging level")

    # Trips and eco-coaching

    async def get_trips(self, vin: str, params: JSON | None = None) -> JSON:
        """Lists the recorded trips (trip report, ``TRIPREPORT`` service).

        The app passes a time range and paging as query parameters whose names
        are not known; ``params`` is sent as the query string.
        """

        return await self._get("v2", vin, "tripreport/trips/", params=params)

    async def get_last_trip(self, vin: str) -> JSON:
        """Gets the last recorded trip"""

        return await self._get("v2", vin, "tripreport/trips/last/")

    async def get_trip(self, vin: str, trip_id: str) -> JSON:
        """Gets the details of a recorded trip"""

        return await self._get("v2", vin, f"tripreport/trips/{trip_id}/")

    async def get_trip_summary(
        self,
        vin: str,
        period: Literal["daily", "weekly", "monthly"],
        params: JSON | None = None,
    ) -> JSON:
        """Gets the trip summary per day, week or month.

        As with :meth:`get_trips`, ``params`` is sent as the query string.
        """

        return await self._get(
            "v2", vin, f"tripreport/summary/{period}/", params=params
        )

    async def get_trip_report_settings(self, vin: str) -> JSON:
        """Gets the trip report settings (costs, currency)"""

        return await self._get("v2", vin, "tripreport/settings/")

    async def get_eco_coaching_profiles(self, vin: str) -> JSON:
        """Lists the eco-coaching profiles, used as ``profile`` in the other
        eco-coaching methods"""

        return await self._get("v2", vin, "ecocoaching/profiles/")

    async def get_eco_coaching_last_trip(
        self, vin: str, profile: str | None = None
    ) -> JSON:
        """Gets the eco-coaching assessment of the last trip"""

        return await self._post(
            "v2",
            vin,
            "ecocoaching/get-last-trip/",
            body=_drop_none({"profile": profile}),
        )

    async def get_eco_coaching_best_trip(
        self, vin: str, profile: str | None = None
    ) -> JSON:
        """Gets the eco-coaching assessment of the best trip"""

        return await self._post(
            "v2",
            vin,
            "ecocoaching/get-best-trip/",
            body=_drop_none({"profile": profile}),
        )

    async def get_eco_coaching_trips(
        self,
        vin: str,
        since: datetime | int | None = None,
        till: datetime | int | None = None,
        offset: int = 0,
        size: int = 100,
        profile: str | None = None,
    ) -> JSON:
        """Lists the eco-coaching trip assessments in a time range, by default
        the last 7 days like the app"""

        till_dt = till if till is not None else datetime.now(UTC)
        if since is None:
            since = (
                till_dt - ECO_COACHING_TRIPS_RANGE
                if isinstance(till_dt, datetime)
                else till_dt - int(ECO_COACHING_TRIPS_RANGE.total_seconds() * 1000)
            )

        return await self._post(
            "v2",
            vin,
            "ecocoaching/get-trips/",
            body=_drop_none(
                {
                    "since": _ms(since),
                    "till": _ms(till_dt),
                    "offset": offset,
                    "size": size,
                    "profile": profile,
                }
            ),
        )

    async def get_eco_coaching_monthly(
        self,
        vin: str,
        till: datetime | int | None = None,
        offset: int = 0,
        size: int = 100,
        profile: str | None = None,
    ) -> JSON:
        """Gets the eco-coaching assessments grouped by month"""

        return await self._post(
            "v2",
            vin,
            "ecocoaching/get-trips/monthly/",
            body=_drop_none(
                {
                    "since": 0,
                    "till": _ms(till if till is not None else datetime.now(UTC)),
                    "offset": offset,
                    "size": size,
                    "profile": profile,
                }
            ),
        )

    async def get_eco_coaching_daily(self, vin: str) -> JSON:
        """Gets the eco-coaching assessments grouped by day"""

        return await self._post("v2", vin, "ecocoaching/get-trips/daily/")

    async def get_eco_coaching_suggestions(self, vin: str) -> JSON:
        """Gets eco-driving suggestions"""

        return await self._get("v2", vin, "ecocoaching/suggestions/")

    async def get_eco_coaching_history(
        self,
        vin: str,
        group_by: Literal["trips", "day", "month"] = "day",
        since: datetime | int | None = None,
        till: datetime | int | None = None,
        offset: int | None = None,
        limit: int | None = None,
    ) -> JSON:
        """Gets eco-coaching data with the older (v1) API, for vehicles with
        the ``ECODRIVE``/``ECOCOACHINGR1`` services"""

        return await self._get(
            "v1",
            vin,
            "ecocoaching/",
            params=_drop_none(
                {
                    "groupby": group_by,
                    "since": _ms(since) if since is not None else None,
                    "till": _ms(till) if till is not None else None,
                    "offset": offset,
                    "limit": limit,
                }
            ),
        )

    # Drive alerts and theft alarm

    async def get_drive_alerts(self, vin: str) -> JSON:
        """Gets the drive alerts configuration: ``geofence``, ``curfew``,
        ``speed`` and ``valet`` alerts"""

        return await self._get("v3", vin, "parentalcontrols/config/")

    async def set_drive_alerts(self, vin: str, alerts: JSON) -> str:
        """Sets the drive alerts configuration (in the format returned by
        :meth:`get_drive_alerts`). Returns the correlation ID."""

        pin_auth = await self.pin_auth(vin)

        r = await self._post(
            "v4", vin, "parentalcontrols/config/", body=alerts | {"pinAuth": pin_auth}
        )

        return _correlation_id(r, "set drive alerts")

    async def get_theft_alarm_status(self, vin: str) -> JSON:
        """Gets whether theft alarm notifications are suppressed
        (``suppressionStatus``, ``suppressionDuration``)"""

        return await self._get("v1", vin, "theft/status/")

    async def set_theft_alarm_notifications(
        self,
        vin: str,
        enabled: bool,
        suppression: TheftAlarmSuppression | None = None,
    ) -> str:
        """Enables theft alarm notifications, or suppresses them for the given
        duration. Returns the correlation ID."""

        pin_auth = await self.pin_auth(vin)

        body: JSON = {"enabled": enabled, "pinAuth": pin_auth}
        if suppression is not None:
            body["suspensionDuration"] = TheftAlarmSuppression(suppression).value

        r = await self._post("v1", vin, "theft/alarm/", body=body)

        return _correlation_id(r, "set theft alarm notifications")
