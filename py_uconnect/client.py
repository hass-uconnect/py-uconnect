"""High-level async client: keeps parsed vehicle data and runs remote commands"""

from __future__ import annotations

import asyncio
import logging
from types import TracebackType
from typing import Any, Self

import aiohttp

from .api import API, JSON
from .brands import Brand
from .command import Command, resolve_command, schedule_endpoint
from .exceptions import APIError, CommandTimeoutError
from .models import (
    ChargingLevel,
    Vehicle,
    apply_list_item,
    apply_remote_status,
    apply_vehicle_info,
    get_str,
    parse_location,
)

_LOGGER = logging.getLogger(__name__)

OPERATION_SUCCEEDED = ("success", "succeeded", "completed", "complete")
OPERATION_FAILED = ("failure", "failed", "error", "rejected", "timeout")


def _operation_result(status: str | None) -> bool | None:
    if status is None:
        return None

    status = status.lower()
    if status in OPERATION_SUCCEEDED:
        return True
    if status in OPERATION_FAILED:
        return False

    return None


def _remote_operation_result(r: JSON) -> bool | None:
    return _operation_result(get_str(r, "status") or get_str(r, "responseStatus"))


def _notification_result(r: JSON, correlation_id: str) -> bool | None:
    items = r.get("notifications", {})
    items = items.get("items") if isinstance(items, dict) else None

    for item in items if isinstance(items, list) else []:
        if isinstance(item, dict) and item.get("correlationId") == correlation_id:
            result = _operation_result(get_str(item, "notification", "data", "status"))
            if result is not None:
                return result

    return None


class Client:
    """High-level async Uconnect client.

    :meth:`refresh` loads the vehicles of the account and their state into
    :attr:`vehicles`. Remote commands can be sent with :meth:`command` or
    :meth:`command_verify`, the latter waits for the result. For endpoints
    without a high-level wrapper use the low-level client in :attr:`api`.
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
        self.api = API(email, password, pin, brand, session=session, timeout=timeout)
        self.vehicles: dict[str, Vehicle] = {}
        self._info_unsupported: set[str] = set()

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

        await self.api.close()

    def set_pin(self, pin: str | None) -> None:
        """Sets the PIN used for remote commands"""

        self.api.pin = pin

    async def refresh(self) -> dict[str, Vehicle]:
        """Loads the vehicles of the account and their state into
        :attr:`vehicles`, removing those which are no longer in the account.
        """

        items = [x for x in await self.api.list_vehicles() if x.get("vin")]

        await asyncio.gather(*(self._refresh_vehicle(x) for x in items))

        vins = {x["vin"] for x in items}
        for vin in list(self.vehicles):
            if vin not in vins:
                del self.vehicles[vin]

        return self.vehicles

    async def _refresh_vehicle(self, item: JSON) -> None:
        vin: str = item["vin"]
        vehicle = self.vehicles.get(vin) or Vehicle(vin=vin)
        apply_list_item(vehicle, item)

        info, location, remote = await asyncio.gather(
            self.api.get_vehicle_info(
                vin, "v4" if "CPCOOP" in vehicle.enabled_services else "v3"
            ),
            self.api.get_vehicle_location(vin),
            self.api.get_remote_status(vin),
            return_exceptions=True,
        )

        # Endpoints that fail with an API error are skipped and the vehicle is
        # kept with the data that is available: not every vehicle supports
        # every endpoint. Other errors (auth, connection) are raised.
        for name, r in (("info", info), ("location", location), ("remote", remote)):
            if isinstance(r, APIError):
                level = logging.DEBUG
                if name == "info" and vin not in self._info_unsupported:
                    self._info_unsupported.add(vin)
                    level = logging.WARNING

                _LOGGER.log(level, "%s: unable to get %s: %s", vin, name, r)
            elif isinstance(r, BaseException):
                raise r

        if isinstance(info, dict):
            apply_vehicle_info(vehicle, info)
        if isinstance(location, dict):
            vehicle.raw_location = location
            vehicle.location = parse_location(location)
        if isinstance(remote, dict):
            apply_remote_status(vehicle, remote)

        self.vehicles[vin] = vehicle

    def get_vehicles(self) -> dict[str, Vehicle]:
        """Returns the vehicles loaded by the last :meth:`refresh`"""

        return self.vehicles

    async def command(
        self, vin: str, cmd: Command, params: dict[str, Any] | None = None
    ) -> str:
        """Sends a remote command, returns the correlation ID of the operation.

        If the vehicle was loaded by :meth:`refresh`, the variant of the
        command that fits its services is sent, like the official apps do
        (e.g. ``START_CHARGE`` instead of ``CNOW`` for vehicles with the
        ``CNOW2`` service). ``params`` are passed along, see
        :func:`py_uconnect.command.hvac_params`.
        """

        if (vehicle := self.vehicles.get(vin)) is not None:
            resolved = resolve_command(cmd, vehicle.enabled_services)
            if resolved != cmd:
                _LOGGER.debug("%s: sending %s instead of %s", vin, resolved, cmd)
                cmd = resolved

        return await self.api.command(vin, cmd, params)

    async def wait_for_operation(
        self,
        vin: str,
        correlation_id: str,
        timeout: float = 60,
        interval: float = 2,
    ) -> bool:
        """Waits for a remote operation to finish.

        Returns True if it succeeded and False if it failed. Raises
        :class:`CommandTimeoutError` if no result is reported within
        ``timeout`` seconds.

        The result is polled from the operation status endpoints (the apps
        use one for remote commands and another one for the other operations)
        and, as they are not available everywhere, from the vehicle
        notifications. An endpoint that returns HTTP 404 is not polled again.
        """

        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        status_endpoints = [
            self.api.get_remote_operation_last_status,
            self.api.get_remote_operation_status,
        ]
        last_error: Exception | None = None

        while True:
            await asyncio.sleep(interval)

            for endpoint in list(status_endpoints):
                try:
                    r = await endpoint(vin, correlation_id)
                    if (result := _remote_operation_result(r)) is not None:
                        return result
                except APIError as err:
                    last_error = err
                    if err.status == 404:
                        status_endpoints.remove(endpoint)

            try:
                r = await self.api.get_vehicle_notifications(vin)
                if (result := _notification_result(r, correlation_id)) is not None:
                    return result
            except APIError as err:
                last_error = err

            if loop.time() + interval >= deadline:
                raise CommandTimeoutError(
                    f"no result for operation {correlation_id} within {timeout}s"
                    + (f" (last error: {last_error})" if last_error else "")
                )

    async def command_verify(
        self,
        vin: str,
        cmd: Command,
        params: dict[str, Any] | None = None,
        timeout: float = 60,
        interval: float = 2,
    ) -> bool:
        """Sends a remote command and waits for its result, see
        :meth:`command` and :meth:`wait_for_operation`.
        """

        cid = await self.command(vin, cmd, params)
        return await self.wait_for_operation(vin, cid, timeout, interval)

    async def set_charging_level(
        self, vin: str, level: ChargingLevel, max_soc: int | None = None
    ) -> str:
        """Sets the charging power preference, returns the correlation ID.

        ``max_soc`` (in percent) is only supported by vehicles with the
        ``CSETTING2`` service.
        """

        return await self.api.set_charging_level(vin, level, max_soc)

    async def set_charging_level_verify(
        self,
        vin: str,
        level: ChargingLevel,
        max_soc: int | None = None,
        timeout: float = 60,
        interval: float = 2,
    ) -> bool:
        """Sets the charging power preference and waits for the result"""

        cid = await self.api.set_charging_level(vin, level, max_soc)
        return await self.wait_for_operation(vin, cid, timeout, interval)

    async def set_charge_schedules(
        self,
        vin: str,
        schedules: list[dict[str, Any]],
        command: str | None = None,
    ) -> str:
        """Sets the EV charge/climate schedules, returns the correlation ID.

        The schedules must be in the format of the vehicle's schedule service,
        the same as ``Vehicle.charge_schedules``. ``command`` is that service;
        it is determined from the vehicle's services if not given.
        """

        if command is None:
            vehicle = self.vehicles.get(vin)
            ep = schedule_endpoint(vehicle.enabled_services) if vehicle else None
            if ep is None:
                raise ValueError(
                    f"{vin}: no schedule service known, pass the command explicitly"
                )
            command = ep.command

        return await self.api.set_charge_schedules(vin, command, schedules)

    async def set_charge_schedules_verify(
        self,
        vin: str,
        schedules: list[dict[str, Any]],
        command: str | None = None,
        timeout: float = 60,
        interval: float = 2,
    ) -> bool:
        """Sets the EV charge/climate schedules and waits for the result"""

        cid = await self.set_charge_schedules(vin, schedules, command)
        return await self.wait_for_operation(vin, cid, timeout, interval)
