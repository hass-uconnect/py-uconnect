"""Minimal AWS Signature Version 4 request signer.

The Uconnect API gateway authenticates requests with temporary AWS credentials
obtained from Cognito. Only the subset of SigV4 needed for that is implemented:
the ``host`` header and all ``x-amz-*`` headers are signed.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import parse_qsl, quote, urlsplit

ALGORITHM = "AWS4-HMAC-SHA256"


@dataclass(frozen=True)
class AWSCredentials:
    """Temporary AWS credentials used to sign API requests"""

    access_key_id: str
    secret_access_key: str = field(repr=False)
    session_token: str | None = field(default=None, repr=False)


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def _quote(s: str) -> str:
    return quote(s, safe="-_.~")


def _canonical_query(query: str) -> str:
    pairs = parse_qsl(query, keep_blank_values=True)
    return "&".join(f"{_quote(k)}={_quote(v)}" for k, v in sorted(pairs))


def sign(
    method: str,
    url: str,
    headers: Mapping[str, str],
    body: bytes,
    credentials: AWSCredentials,
    region: str,
    service: str,
    now: datetime | None = None,
) -> dict[str, str]:
    """Signs a request and returns the headers that must be added to it.

    ``url`` must be the exact (already percent-encoded) URL that is sent.
    ``headers`` are the headers that will be sent; the ``x-amz-*`` ones among them
    are signed along with ``host``. The returned dict contains ``X-Amz-Date``,
    ``Authorization`` and, if a session token is present, ``X-Amz-Security-Token``.
    """

    now = (now or datetime.now(UTC)).astimezone(UTC)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")

    parts = urlsplit(url)
    host = parts.hostname or ""
    if parts.port is not None and parts.port not in (80, 443):
        host = f"{host}:{parts.port}"

    added = {"X-Amz-Date": amz_date}
    if credentials.session_token is not None:
        added["X-Amz-Security-Token"] = credentials.session_token

    to_sign = {"host": host}
    for k, v in (*headers.items(), *added.items()):
        if k.lower().startswith("x-amz-"):
            to_sign[k.lower()] = " ".join(v.split())

    signed_headers = ";".join(sorted(to_sign))
    canonical_headers = "".join(f"{k}:{to_sign[k]}\n" for k in sorted(to_sign))

    canonical_request = "\n".join(
        [
            method.upper(),
            quote(parts.path or "/", safe="/~"),
            _canonical_query(parts.query),
            canonical_headers,
            signed_headers,
            hashlib.sha256(body).hexdigest(),
        ]
    )

    scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        [
            ALGORITHM,
            amz_date,
            scope,
            hashlib.sha256(canonical_request.encode()).hexdigest(),
        ]
    )

    key = _hmac(f"AWS4{credentials.secret_access_key}".encode(), date_stamp)
    key = _hmac(key, region)
    key = _hmac(key, service)
    key = _hmac(key, "aws4_request")
    signature = hmac.new(key, string_to_sign.encode(), hashlib.sha256).hexdigest()

    added["Authorization"] = (
        f"{ALGORITHM} Credential={credentials.access_key_id}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    return added
