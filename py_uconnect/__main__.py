"""Command line interface, run ``python -m py_uconnect --help``"""

from __future__ import annotations

import argparse
import asyncio
import inspect
import json
import logging
import os
import sys
from typing import Any

from . import __version__
from .api import API
from .brands import BRANDS
from .client import Client
from .command import COMMANDS_BY_NAME
from .exceptions import UconnectError


def _required_params(fn: Any) -> list[str]:
    return [
        name
        for name, p in inspect.signature(fn).parameters.items()
        if p.default is inspect.Parameter.empty
    ]


# Read-only API methods that only need a VIN
GETTERS = sorted(
    name
    for name, fn in inspect.getmembers(API, inspect.iscoroutinefunction)
    if name.startswith("get_") and _required_params(fn) == ["self", "vin"]
)


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="uconnect",
        description="Query and control FCA/Stellantis vehicles via the Uconnect "
        "cloud. Credentials can also be passed as UCONNECT_EMAIL, "
        "UCONNECT_PASSWORD, UCONNECT_PIN and UCONNECT_BRAND environment variables.",
    )
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument(
        "-b",
        "--brand",
        default=os.environ.get("UCONNECT_BRAND"),
        choices=sorted(BRANDS),
        metavar="BRAND",
        help=f"one of: {', '.join(sorted(BRANDS))}",
    )
    p.add_argument("-u", "--email", default=os.environ.get("UCONNECT_EMAIL"))
    p.add_argument("-p", "--password", default=os.environ.get("UCONNECT_PASSWORD"))
    p.add_argument("--pin", default=os.environ.get("UCONNECT_PIN"))
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging")

    sub = p.add_subparsers(dest="action", required=True)

    s = sub.add_parser("vehicles", help="show the vehicles and their state")
    s.add_argument("--raw", action="store_true", help="include raw API responses")

    s = sub.add_parser("get", help="call a read-only endpoint for a vehicle")
    s.add_argument("endpoint", choices=GETTERS)
    s.add_argument("vin")

    s = sub.add_parser("command", help="send a remote command (needs the PIN)")
    s.add_argument("vin")
    s.add_argument("command", choices=sorted(COMMANDS_BY_NAME))
    s.add_argument("--no-wait", action="store_true", help="do not wait for the result")

    s = sub.add_parser("raw", help="send a request to an arbitrary API path")
    s.add_argument("method", type=str.upper)
    s.add_argument("path", help="e.g. /v1/accounts/{uid}/vehicles/VIN/vhr/")
    s.add_argument("--body", type=json.loads, help="JSON request body")
    s.add_argument(
        "--param", action="append", default=[], help="query parameter KEY=VALUE"
    )

    return p


def _print(v: Any) -> None:
    print(json.dumps(v, indent=2, ensure_ascii=False))


async def _run(args: argparse.Namespace) -> int:
    async with Client(
        args.email, args.password, args.pin, BRANDS[args.brand]
    ) as client:
        if args.action == "vehicles":
            vehicles = await client.refresh()
            _print([v.to_dict(raw=args.raw) for v in vehicles.values()])
        elif args.action == "get":
            _print(await getattr(client.api, args.endpoint)(args.vin))
        elif args.action == "command":
            cmd = COMMANDS_BY_NAME[args.command]
            if args.no_wait:
                print(await client.command(args.vin, cmd))
            else:
                ok = await client.command_verify(args.vin, cmd)
                print("success" if ok else "failed")
                return 0 if ok else 1
        elif args.action == "raw":
            params = dict(x.split("=", 1) for x in args.param)
            _print(
                await client.api.request(
                    args.method, args.path, params=params, body=args.body
                )
            )

    return 0


def main() -> None:
    """Entry point of the ``uconnect`` command"""

    args = _parser().parse_args()

    missing = [x for x in ("brand", "email", "password") if not getattr(args, x)]
    if missing:
        _parser().error(f"missing {', '.join(missing)}")

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING)

    try:
        sys.exit(asyncio.run(_run(args)))
    except UconnectError as err:
        print(f"error: {err}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
