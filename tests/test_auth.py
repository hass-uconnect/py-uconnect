from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import aiohttp
import pytest

from py_uconnect import API, APIError, AuthenticationError, UconnectConnectionError
from py_uconnect.auth import Credentials
from py_uconnect.sigv4 import AWSCredentials

from .conftest import (
    AWS_ACCESS_KEY,
    AWS_SESSION_TOKEN,
    BRAND,
    UID,
    cognito_url,
    gigya_url,
    mock_login,
    vehicle_url,
)
from .mock_http import MockSession


async def test_login(http: MockSession, api: API) -> None:
    mock_login(http)

    await api.login()

    assert api.uid == UID
    creds = api._credentials
    assert creds is not None
    assert creds.aws == AWSCredentials(AWS_ACCESS_KEY, "SECRET", AWS_SESSION_TOKEN)
    assert not creds.expires_soon()

    (bootstrap,) = http.calls_to("GET", gigya_url(BRAND, "accounts.webSdkBootstrap"))
    assert bootstrap.query == {"apiKey": BRAND.login_api_key}

    (login,) = http.calls_to("POST", gigya_url(BRAND, "accounts.login"))
    assert login.query["loginID"] == "user@example.com"
    assert login.query["password"] == "secret"
    assert login.query["APIKey"] == BRAND.login_api_key
    # Cookies set by the bootstrap call are sent along
    assert login.cookies == {"gmid": "GMID"}

    (jwt,) = http.calls_to("POST", gigya_url(BRAND, "accounts.getJWT"))
    assert jwt.query["login_token"] == "LOGIN-TOKEN"
    assert jwt.cookies == {"gmid": "GMID"}

    (token,) = http.calls_to("POST", BRAND.token_url)
    assert token.json == {"gigya_token": "GIGYA-JWT"}
    assert token.headers["x-api-key"] == BRAND.api.key

    (cognito,) = http.calls_to("POST", cognito_url(BRAND))
    assert cognito.json == {
        "IdentityId": f"{BRAND.region}:identity",
        "Logins": {"cognito-identity.amazonaws.com": "OPENID-TOKEN"},
    }
    assert cognito.headers["X-Amz-Target"] == (
        "AWSCognitoIdentityService.GetCredentialsForIdentity"
    )


async def test_login_invalid_credentials(http: MockSession, api: API) -> None:
    http.get(
        gigya_url(BRAND, "accounts.webSdkBootstrap"),
        payload={"statusCode": 200, "errorCode": 0},
    )
    http.post(
        gigya_url(BRAND, "accounts.login"),
        payload={
            "statusCode": 403,
            "errorCode": 403042,
            "errorMessage": "Invalid LoginID",
        },
    )

    with pytest.raises(AuthenticationError, match="Invalid LoginID"):
        await api.login()


async def test_login_gigya_http_error_is_not_auth_error(
    http: MockSession, api: API
) -> None:
    http.get(gigya_url(BRAND, "accounts.webSdkBootstrap"), status=503)

    with pytest.raises(APIError) as err:
        await api.login()

    assert not isinstance(err.value, AuthenticationError)
    assert err.value.status == 503


async def test_login_token_exchange_rejected(http: MockSession, api: API) -> None:
    mock_login(http, skip=("token",))
    http.post(BRAND.token_url, status=401, payload={"message": "Unauthorized"})

    with pytest.raises(AuthenticationError, match="token exchange"):
        await api.login()


async def test_login_token_exchange_server_error(http: MockSession, api: API) -> None:
    mock_login(http, skip=("token",))
    http.post(BRAND.token_url, status=500, body="oops")

    with pytest.raises(APIError) as err:
        await api.login()

    assert not isinstance(err.value, AuthenticationError)


async def test_login_cognito_not_authorized(http: MockSession, api: API) -> None:
    mock_login(http, skip=("cognito",))
    http.post(
        cognito_url(BRAND),
        status=400,
        payload={"__type": "NotAuthorizedException", "message": "Invalid token"},
    )

    with pytest.raises(AuthenticationError, match="Cognito"):
        await api.login()


async def test_login_cognito_malformed_response(http: MockSession, api: API) -> None:
    mock_login(http, skip=("cognito",))
    http.post(cognito_url(BRAND), payload={"Credentials": {"AccessKeyId": "x"}})

    with pytest.raises(APIError, match="unexpected response"):
        await api.login()


@pytest.mark.parametrize(
    "exception", [aiohttp.ClientConnectionError("boom"), TimeoutError()]
)
async def test_login_connection_error(
    http: MockSession, api: API, exception: Exception
) -> None:
    http.get(gigya_url(BRAND, "accounts.webSdkBootstrap"), exception=exception)

    with pytest.raises(UconnectConnectionError):
        await api.login()


def test_credentials_expiry() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    creds = Credentials(
        uid=UID,
        aws=AWSCredentials("a", "b"),
        expires_at=now + timedelta(minutes=10),
    )

    assert not creds.expires_soon(now=now)
    assert creds.expires_soon(now=now + timedelta(minutes=6))
    assert creds.expires_soon(now=now + timedelta(minutes=11))


async def test_concurrent_requests_log_in_once(http: MockSession, api: API) -> None:
    mock_login(http)
    http.get(vehicle_url("v1", "remote/status"), payload={}, repeat=True)

    await asyncio.gather(
        *(api.get_remote_status("ZFAEFAC39MX000001") for _ in range(5))
    )

    assert len(http.calls_to("POST", gigya_url(BRAND, "accounts.login"))) == 1


async def test_expiring_credentials_are_renewed(http: MockSession, api: API) -> None:
    mock_login(http, repeat=True)
    http.get(vehicle_url("v1", "remote/status"), payload={}, repeat=True)

    await api.get_remote_status("ZFAEFAC39MX000001")
    await api.get_remote_status("ZFAEFAC39MX000001")
    assert len(http.calls_to("POST", gigya_url(BRAND, "accounts.login"))) == 1

    assert api._credentials is not None
    api._credentials = Credentials(
        uid=UID,
        aws=api._credentials.aws,
        expires_at=datetime.now(UTC) + timedelta(minutes=1),
    )

    await api.get_remote_status("ZFAEFAC39MX000001")
    assert len(http.calls_to("POST", gigya_url(BRAND, "accounts.login"))) == 2


async def test_expired_token_response_triggers_new_login(
    http: MockSession, api: API
) -> None:
    mock_login(http, repeat=True)
    http.get(
        vehicle_url("v1", "remote/status"),
        status=403,
        payload={"message": "The security token included in the request is expired"},
    )
    http.get(vehicle_url("v1", "remote/status"), payload={"ok": True})

    assert await api.get_remote_status("ZFAEFAC39MX000001") == {"ok": True}
    assert len(http.calls_to("POST", gigya_url(BRAND, "accounts.login"))) == 2


async def test_owned_session_is_closed() -> None:
    api = API("a", "b", None, BRAND)
    session = api._http()

    await api.close()

    assert session.closed


async def test_passed_session_is_not_closed(http: MockSession) -> None:
    async with API("a", "b", None, BRAND, session=http):  # type: ignore[arg-type]
        pass

    assert not http.closed
