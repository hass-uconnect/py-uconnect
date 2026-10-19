"""Low-level async client for the Uconnect cloud API.

Every method maps to a single endpoint and returns the decoded JSON response
as-is. See :class:`py_uconnect.Client` for a higher-level interface.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
from types import TracebackType
from typing import Any, Self

import aiohttp
from yarl import URL

from . import auth, sigv4
from ._http import api_headers, parse_json
from .brands import Brand, Endpoint
from .command import Command
from .exceptions import (
    APIError,
    CommandError,
    PinAuthenticationError,
    UconnectConnectionError,
)
from .models import ChargingLevel

_LOGGER = logging.getLogger(__name__)

JSON = dict[str, Any]

# Versions of the vehicle status endpoint, in order of preference. Some older
# vehicles only work with one of them.
STATUS_API_VERSIONS = ("v3", "v4")


def _is_expired_token_error(status: int, body: Any) -> bool:
    if status not in (401, 403):
        return False

    msg = str(body.get("message", "") if isinstance(body, dict) else body).lower()
    return "expired" in msg and ("token" in msg or "signature" in msg)


def _correlation_id(r: JSON, what: str) -> str:
    cid = r.get("correlationId")
    status = r.get("responseStatus")

    if not isinstance(cid, str) or not cid or status not in (None, "pending"):
        reason = r.get("debugMsg") or status or "no correlation ID in response"
        raise CommandError(f"{what} was not accepted: {reason}")

    return cid


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
        self.password = password
        self.pin = pin
        self.brand = brand

        self._session = session
        self._owns_session = session is None
        self._timeout = aiohttp.ClientTimeout(total=timeout)

        self._credentials: auth.Credentials | None = None
        self._login_lock = asyncio.Lock()
        self._status_api_version: dict[str, str] = {}

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
        endpoints that do not have a dedicated method yet.
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

    def _vehicle_path(self, version: str, vin: str, suffix: str = "") -> str:
        return f"/{version}/accounts/{{uid}}/vehicles/{vin}/{suffix}"

    # Vehicles

    async def list_vehicles(self) -> list[JSON]:
        """Lists the vehicles of the account with general information.

        Each item has keys like ``vin``, ``nickname``, ``make``,
        ``modelDescription``, ``tsoModelYear``, ``soldRegion``, ``fuelType``,
        ``sdp`` and ``services`` (the list of services and their state).
        """

        r = await self._request_json(
            "GET",
            "/v4/accounts/{uid}/vehicles",
            params={"stage": "ALL", "sdp": "ALL", "brand": self.brand.brand_code},
        )

        vehicles = r.get("vehicles")
        if not isinstance(vehicles, list):
            raise APIError("list_vehicles: no vehicles in response", body=r)

        return vehicles

    async def get_vehicle_info(self, vin: str) -> JSON:
        """Gets the detailed vehicle status: ``vehicleInfo`` (odometer, fuel,
        battery, tyres, service...) and ``evInfo`` (EV battery and charging).

        Tries the v3 endpoint first and falls back to v4 if the vehicle does
        not support it. The working version is remembered per vehicle.
        """

        versions = list(STATUS_API_VERSIONS)
        if (known := self._status_api_version.get(vin)) is not None:
            versions.remove(known)
            versions.insert(0, known)

        for i, version in enumerate(versions):
            try:
                r = await self._request_json(
                    "GET", self._vehicle_path(version, vin, "status/")
                )
            except APIError as err:
                if err.status not in (400, 404, 502) or i == len(versions) - 1:
                    raise

                _LOGGER.debug(
                    "%s: status %s failed with HTTP %s, trying the next version",
                    vin,
                    version,
                    err.status,
                )
                continue

            self._status_api_version[vin] = version
            return r

        raise AssertionError("unreachable")

    async def get_remote_status(self, vin: str) -> JSON:
        """Gets the state of doors, windows, trunk, engine etc."""

        return await self._request_json(
            "GET", self._vehicle_path("v1", vin, "remote/status")
        )

    async def get_vehicle_location(self, vin: str) -> JSON:
        """Gets the last known location of the vehicle"""

        return await self._request_json(
            "GET", self._vehicle_path("v1", vin, "location/lastknown")
        )

    async def get_vehicle_health_report(self, vin: str) -> JSON:
        """Gets the vehicle health report"""

        return await self._request_json("GET", self._vehicle_path("v1", vin, "vhr/"))

    async def get_maintenance_history(self, vin: str) -> JSON:
        """Gets the maintenance history"""

        return await self._request_json(
            "GET", self._vehicle_path("v1", vin, "maintenance/history/")
        )

    async def get_eco_coaching_last_trip(self, vin: str) -> JSON:
        """Gets eco-coaching data for the last trip"""

        return await self._request_json(
            "POST", self._vehicle_path("v2", vin, "ecocoaching/get-last-trip/")
        )

    async def get_eco_coaching_trips(self, vin: str) -> JSON:
        """Gets the eco-coaching trip list"""

        return await self._request_json(
            "POST", self._vehicle_path("v2", vin, "ecocoaching/get-trips/")
        )

    async def get_vehicle_image(
        self, vin: str, width: int = 600, height: int = 340
    ) -> JSON:
        """Gets a URL of a rendered image of the vehicle"""

        return await self._request_json(
            "POST",
            self._vehicle_path("v4", vin, "image/"),
            body={
                "imageURLs": [
                    {"id": vin, "width": width, "height": height, "resp": "png"}
                ]
            },
        )

    async def get_vehicle_notifications(self, vin: str, limit: int | None = 30) -> JSON:
        """Gets the notifications of the vehicle, including command results"""

        return await self._request_json(
            "GET",
            self._vehicle_path("v1", vin, "notifications"),
            params={"limit": limit} if limit is not None else None,
        )

    async def get_stolen_vehicle_status(self, vin: str) -> JSON:
        """Gets the stolen vehicle locator (SVLA) status"""

        return await self._request_json(
            "GET", self._vehicle_path("v1", vin, "svla/status/")
        )

    async def get_vehicle_subscription(self, vin: str) -> JSON:
        """Gets the connected services subscription status"""

        return await self._request_json(
            "GET", self._vehicle_path("v1", vin, "subscription/")
        )

    async def set_vehicle_nickname(self, vin: str, nickname: str) -> JSON:
        """Sets the nickname of the vehicle"""

        return await self._request_json(
            "POST",
            self._vehicle_path("v1", vin, "nickname/"),
            body={"nickname": nickname},
        )

    # Remote operations

    async def get_remote_operation_status(self, vin: str, correlation_id: str) -> JSON:
        """Gets the status of a remote operation by its correlation ID"""

        return await self._request_json(
            "GET", self._vehicle_path("v1", vin, f"remote/{correlation_id}/status/")
        )

    async def pin_auth(self) -> str:
        """Authenticates with the PIN and returns a ``pinAuth`` token.

        The token is required by remote commands and other operations that
        change the state of the vehicle.
        """

        if not self.pin:
            raise PinAuthenticationError("a PIN is required for this operation")

        try:
            r = await self._request_json(
                "POST",
                "/v1/accounts/{uid}/ignite/pin/authenticate",
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

        return token

    async def _send_command(self, vin: str, cmd: Command, pin_auth: str) -> str:
        r = await self._request_json(
            "POST",
            self._vehicle_path(cmd.api_version, vin, cmd.url),
            body={"command": cmd.name, "pinAuth": pin_auth},
        )

        return _correlation_id(r, f"command {cmd}")

    async def command(self, vin: str, cmd: Command) -> str:
        """Sends a remote command and returns its correlation ID.

        If the API rejects the command with HTTP 403 and the command has a
        fallback, the fallback is sent instead.
        """

        pin_auth = await self.pin_auth()

        try:
            return await self._send_command(vin, cmd, pin_auth)
        except APIError as err:
            if err.status != 403 or cmd.fallback is None:
                raise

            _LOGGER.info(
                "%s: command %s returned HTTP 403, retrying with %s",
                vin,
                cmd,
                cmd.fallback,
            )
            return await self._send_command(vin, cmd.fallback, pin_auth)

    # EV

    async def get_charge_schedules(self, vin: str) -> JSON:
        """Gets the EV charge schedules"""

        return await self._request_json(
            "GET", self._vehicle_path("v4", vin, "ev/schedule/")
        )

    async def set_charge_schedule(self, vin: str, schedule: JSON) -> str:
        """Sets the EV charge schedules, returns the correlation ID"""

        pin_auth = await self.pin_auth()

        r = await self._request_json(
            "POST",
            self._vehicle_path("v4", vin, "ev/schedule/"),
            body=schedule | {"pinAuth": pin_auth},
        )

        return _correlation_id(r, "set charge schedule")

    async def set_charging_level(
        self, vin: str, level: ChargingLevel, max_soc: int | None = None
    ) -> str:
        """Sets the charging power preference and optionally the maximum state
        of charge (in percent). Returns the correlation ID.
        """

        if max_soc is not None and not 0 < max_soc <= 100:
            raise ValueError(f"max_soc must be between 1 and 100, got {max_soc}")

        pin_auth = await self.pin_auth()

        body: JSON = {"preference": ChargingLevel(level).value, "pinAuth": pin_auth}
        if max_soc is not None:
            body["maxSOC"] = str(max_soc)

        r = await self._request_json(
            "PUT",
            self._vehicle_path("v2", vin, "ev/charge/preference/"),
            body=body,
        )

        return _correlation_id(r, "set charging level")
