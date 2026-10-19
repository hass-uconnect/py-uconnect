"""Login flow: Gigya account login -> Cognito identity -> temporary AWS credentials"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import aiohttp

from ._http import USER_AGENT, api_headers, parse_json
from .brands import Brand
from .exceptions import APIError, AuthenticationError, UconnectConnectionError
from .sigv4 import AWSCredentials

_LOGGER = logging.getLogger(__name__)

# Credentials are renewed this long before they expire
REFRESH_MARGIN = timedelta(minutes=5)

GIGYA_PARAMS = {
    "targetEnv": "jssdk",
    "loginMode": "standard",
    "sdk": "js_latest",
    "authMode": "cookie",
    "sdkBuild": "12234",
    "format": "json",
}

JWT_FIELDS = (
    "profile.firstName,profile.lastName,profile.email,country,locale,"
    "data.disclaimerCodeGSDP"
)


@dataclass(frozen=True)
class Credentials:
    """Result of a successful login"""

    # Gigya account UID, part of most API paths
    uid: str
    aws: AWSCredentials
    expires_at: datetime

    def expires_soon(
        self, margin: timedelta = REFRESH_MARGIN, now: datetime | None = None
    ) -> bool:
        """Whether the credentials expire within the given margin"""

        return (now or datetime.now(UTC)) >= self.expires_at - margin


async def _send(
    session: aiohttp.ClientSession,
    method: str,
    url: str,
    timeout: aiohttp.ClientTimeout,
    cookies: dict[str, str] | None = None,
    **kwargs: Any,
) -> tuple[int, Any]:
    try:
        async with session.request(
            method, url, timeout=timeout, cookies=cookies, **kwargs
        ) as resp:
            text = await resp.text()
            if cookies is not None:
                cookies.update({k: v.value for k, v in resp.cookies.items()})
            return resp.status, parse_json(text)
    except (aiohttp.ClientError, TimeoutError) as err:
        raise UconnectConnectionError(f"{method} {url}: {err!r}") from err


async def _gigya(
    session: aiohttp.ClientSession,
    brand: Brand,
    method: str,
    call: str,
    params: dict[str, Any],
    timeout: aiohttp.ClientTimeout,
    cookies: dict[str, str],
) -> dict[str, Any]:
    url = f"{brand.login_url}/{call}"
    status, r = await _send(
        session,
        method,
        url,
        timeout,
        cookies=cookies,
        params=params,
        headers={"User-Agent": USER_AGENT},
    )

    if status != 200 or not isinstance(r, dict):
        raise APIError(f"{call}: HTTP {status}", status=status, url=url)

    _LOGGER.debug("%s: statusCode %s", call, r.get("statusCode"))

    if r.get("statusCode") != 200 or r.get("errorCode", 0) != 0:
        raise AuthenticationError(
            f"{call} failed: {r.get('errorMessage')} ({r.get('errorCode')})"
            + (f": {r['errorDetails']}" if r.get("errorDetails") else "")
        )

    return r


async def _exchange_token(
    session: aiohttp.ClientSession,
    brand: Brand,
    id_token: str,
    timeout: aiohttp.ClientTimeout,
) -> tuple[str, str]:
    """Exchanges the Gigya JWT for a Cognito identity ID and OpenID token"""

    status, r = await _send(
        session,
        "POST",
        brand.token_url,
        timeout,
        headers=api_headers(brand, brand.api.key),
        json={"gigya_token": id_token},
    )

    if 400 <= status < 500:
        raise AuthenticationError(f"token exchange rejected: HTTP {status}: {r}")

    token = r.get("Token") if isinstance(r, dict) else None
    identity_id = r.get("IdentityId") if isinstance(r, dict) else None
    if status != 200 or not token or not identity_id:
        raise APIError(
            f"token exchange failed: HTTP {status}",
            status=status,
            url=brand.token_url,
        )

    return identity_id, token


async def _cognito_credentials(
    session: aiohttp.ClientSession,
    region: str,
    identity_id: str,
    token: str,
    timeout: aiohttp.ClientTimeout,
) -> tuple[AWSCredentials, datetime]:
    """Calls Cognito GetCredentialsForIdentity (an unsigned AWS JSON API call)"""

    url = f"https://cognito-identity.{region}.amazonaws.com/"
    status, r = await _send(
        session,
        "POST",
        url,
        timeout,
        headers={
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": "AWSCognitoIdentityService.GetCredentialsForIdentity",
        },
        json={
            "IdentityId": identity_id,
            "Logins": {"cognito-identity.amazonaws.com": token},
        },
    )

    if status != 200 or not isinstance(r, dict):
        error = r.get("__type", "") if isinstance(r, dict) else ""
        if "NotAuthorized" in error or "ResourceNotFound" in error:
            raise AuthenticationError(f"Cognito rejected the identity: {r}")

        raise APIError(
            f"GetCredentialsForIdentity: HTTP {status}: {r}", status=status, url=url
        )

    try:
        c = r["Credentials"]
        creds = AWSCredentials(
            access_key_id=c["AccessKeyId"],
            secret_access_key=c["SecretKey"],
            session_token=c["SessionToken"],
        )
        expires_at = datetime.fromtimestamp(float(c["Expiration"]), UTC)
    except (KeyError, TypeError, ValueError) as err:
        raise APIError(
            f"GetCredentialsForIdentity: unexpected response: {err!r}"
        ) from err

    return creds, expires_at


async def login(
    session: aiohttp.ClientSession,
    brand: Brand,
    email: str,
    password: str,
    timeout: aiohttp.ClientTimeout,
) -> Credentials:
    """Performs the full login flow and returns AWS credentials for the API"""

    # Gigya keeps state in cookies between the calls. They are tracked here
    # rather than in the session's cookie jar, which might be shared.
    cookies: dict[str, str] = {}

    await _gigya(
        session,
        brand,
        "GET",
        "accounts.webSdkBootstrap",
        {"apiKey": brand.login_api_key},
        timeout,
        cookies,
    )

    r = await _gigya(
        session,
        brand,
        "POST",
        "accounts.login",
        GIGYA_PARAMS
        | {
            "APIKey": brand.login_api_key,
            "loginID": email,
            "password": password,
            "sessionExpiration": 300,
            "include": "profile,data,emails,subscriptions,preferences",
        },
        timeout,
        cookies,
    )

    try:
        uid: str = r["UID"]
        login_token: str = r["sessionInfo"]["login_token"]
    except (KeyError, TypeError) as err:
        raise AuthenticationError(
            f"accounts.login: unexpected response: {err!r}"
        ) from err

    r = await _gigya(
        session,
        brand,
        "POST",
        "accounts.getJWT",
        GIGYA_PARAMS
        | {
            "APIKey": brand.login_api_key,
            "login_token": login_token,
            "fields": JWT_FIELDS,
        },
        timeout,
        cookies,
    )

    id_token = r.get("id_token")
    if not isinstance(id_token, str):
        raise AuthenticationError("accounts.getJWT: no id_token in response")

    identity_id, token = await _exchange_token(session, brand, id_token, timeout)
    aws, expires_at = await _cognito_credentials(
        session, brand.region, identity_id, token, timeout
    )

    _LOGGER.debug("Logged in as %s, credentials expire at %s", uid, expires_at)

    return Credentials(uid=uid, aws=aws, expires_at=expires_at)
