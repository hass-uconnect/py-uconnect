"""Async Python client for the FCA/Stellantis Uconnect cloud API"""

from .api import API
from .brands import BRANDS, Brand
from .client import Client
from .command import COMMANDS, COMMANDS_BY_NAME, Command
from .exceptions import (
    APIError,
    AuthenticationError,
    CommandError,
    CommandTimeoutError,
    PinAuthenticationError,
    UconnectConnectionError,
    UconnectError,
)
from .models import ChargingLevel, Location, Vehicle

__version__ = "1.0.0"

__all__ = [
    "API",
    "BRANDS",
    "COMMANDS",
    "COMMANDS_BY_NAME",
    "APIError",
    "AuthenticationError",
    "Brand",
    "ChargingLevel",
    "Client",
    "Command",
    "CommandError",
    "CommandTimeoutError",
    "Location",
    "PinAuthenticationError",
    "UconnectConnectionError",
    "UconnectError",
    "Vehicle",
]
