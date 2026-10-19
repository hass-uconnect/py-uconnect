"""HTTP helpers shared by the authentication flow and the API client"""

from __future__ import annotations

import json
import uuid
from typing import Any

from .brands import Brand

# The API keys used by the library belong to the web portal, so requests look
# like they come from a desktop browser.
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36"
)


def api_headers(brand: Brand, api_key: str) -> dict[str, str]:
    """Headers expected by the Uconnect API gateways"""

    return {
        "User-Agent": USER_AGENT,
        "Content-Type": "application/json",
        "x-clientapp-name": "CWP",
        "x-clientapp-version": "1.0",
        "x-originator-type": "web",
        "clientrequestid": uuid.uuid4().hex.upper()[:16],
        "x-api-key": api_key,
        "locale": brand.locale,
    }


def parse_json(text: str) -> Any:
    """Decodes a JSON response body, returns None if it is not valid JSON"""

    try:
        return json.loads(text)
    except ValueError:
        return None
