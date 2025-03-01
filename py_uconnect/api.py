import requests
import uuid
import json
import boto3
import base64
import logging
import http.client as http_client

from dataclasses import dataclass, field
from dataclasses_json import dataclass_json

from datetime import datetime, timedelta
from requests_auth_aws_sigv4 import AWSSigV4

from .command import Command
from .brands import Brand

_LOGGER = logging.getLogger("py_uconnect")


@dataclass_json
@dataclass
class ChargingLevel:
    name: str


CHARGING_LEVEL_ONE = ChargingLevel("LEVEL_ONE")
CHARGING_LEVEL_TWO = ChargingLevel("LEVEL_TWO")
CHARGING_LEVEL_THREE = ChargingLevel("LEVEL_THREE")
CHARGING_LEVEL_FOUR = ChargingLevel("LEVEL_FOUR")
CHARGING_LEVEL_FIVE = ChargingLevel("LEVEL_FIVE")

CHARGING_LEVELS = [
    CHARGING_LEVEL_ONE,
    CHARGING_LEVEL_TWO,
    CHARGING_LEVEL_THREE,
    CHARGING_LEVEL_FOUR,
    CHARGING_LEVEL_FIVE,
]

CHARGING_LEVELS_BY_NAME = {x.name: x for x in CHARGING_LEVELS}


class API:
    def __init__(
        self,
        email: str,
        password: str,
        pin: str,
        brand: Brand,
        disable_tls_verification: bool = False,
        dev_mode: bool = False,
        trace: bool = False,
    ):
        self.email = email
        self.password = password
        self.pin = pin
        self.brand = brand
        self.dev_mode = dev_mode

        self.uid: str = None
        self.aws_auth: AWSSigV4 = None

        self.sess = requests.Session()
        self.cognito_client = None

        self.expire_time: datetime = None

        if disable_tls_verification:
            self.sess.verify = False
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        if trace:
            http_client.HTTPConnection.debuglevel = 1
            logging.basicConfig()
            logging.getLogger().setLevel(logging.TRACE)
            requests_log = logging.getLogger("requests.packages.urllib3")
            requests_log.setLevel(logging.DEBUG)
            requests_log.propagate = True

    def _with_default_params(self, params: dict):
        return params | {
            "targetEnv": "jssdk",
            "loginMode": "standard",
            "sdk": "js_latest",
            "authMode": "cookie",
            "sdkBuild": "12234",
            "format": "json",
            "APIKey": self.brand.login_api_key,
        }

    def _default_aws_headers(self, key: str):
        return {
            "x-clientapp-name": "CWP",
            "x-clientapp-version": "1.0",
            "clientrequestid": uuid.uuid4().hex.upper()[0:16],
            "x-api-key": key,
            "locale": self.brand.locale,
            "x-originator-type": "web",
        }

    def set_debug(self, debug: bool):
        _LOGGER.setLevel(logging.DEBUG if debug else logging.WARNING)

    def set_tls_verification(self, verify: bool):
        self.sess.verify = verify

    def set_pin(self, pin: str):
        self.pin = pin

    def login(self):
        """Logs into the Uconnect and caches the auth tokens"""

        if self.cognito_client is None:
            self.cognito_client = boto3.client("cognito-identity", self.brand.region)

        r = self.sess.request(
            method="GET",
            url=self.brand.login_url + "/accounts.webSdkBootstrap",
            params={"apiKey": self.brand.login_api_key},
        )

        r.raise_for_status()
        _LOGGER.debug(f"Login: accounts.webSdkBootstrap: {r.text}")
        r = r.json()

        if r["statusCode"] != 200:
            raise Exception(f"bootstrap failed: {r}")

        r = self.sess.request(
            method="POST",
            url=self.brand.login_url + "/accounts.login",
            params=self._with_default_params(
                {
                    "loginID": self.email,
                    "password": self.password,
                    "sessionExpiration": 300,
                    "include": "profile,data,emails,subscriptions,preferences",
                }
            ),
        )

        r.raise_for_status()
        _LOGGER.debug(f"Login: accounts.login: {r.text}")
        r = r.json()

        if r["statusCode"] != 200:
            raise Exception(f"account login failed: {r}")

        self.uid = r["UID"]
        login_token = r["sessionInfo"]["login_token"]

        r = self.sess.request(
            method="POST",
            url=self.brand.login_url + "/accounts.getJWT",
            params=self._with_default_params(
                {
                    "login_token": login_token,
                    "fields": "profile.firstName,profile.lastName,profile.email,country,locale,data.disclaimerCodeGSDP",
                }
            ),
        )

        r.raise_for_status()
        _LOGGER.debug(f"Login: accounts.getJWT: {r.text}")
        r = r.json()

        if r["statusCode"] != 200:
            raise Exception(f"unable to obtain JWT: {r}")

        r = self.sess.request(
            method="POST",
            url=self.brand.token_url,
            headers=self._default_aws_headers(self.brand.api.key)
            | {"content-type": "application/json"},
            json={"gigya_token": r["id_token"]},
        )

        r.raise_for_status()
        _LOGGER.debug(f"Login: obtain token: {r.text}")
        r = r.json()

        token = r.get("Token", None)
        identity_id = r.get("IdentityId", None)
        if token is None or identity_id is None:
            raise Exception(f"unable to obtain identity & token: {r}")

        r = self.cognito_client.get_credentials_for_identity(
            IdentityId=identity_id,
            Logins={"cognito-identity.amazonaws.com": token},
        )

        creds = r.get("Credentials", None)
        if not creds:
            raise Exception(f"unable to obtain AWS credentials: {r}")

        self.aws_auth = AWSSigV4(
            "execute-api",
            region=self.brand.region,
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretKey"],
            aws_session_token=creds["SessionToken"],
        )

        self.expire_time = creds["Expiration"]

    def _refresh_token_if_needed(self):
        """Checks if token is available and fresh, refreshes it otherwise"""

        if self.dev_mode:
            return

        if (
            self.expire_time is None
            or datetime.now().astimezone() > self.expire_time - timedelta(minutes=5)
        ):
            try:
                self.login()
            except Exception as e:
                raise Exception(f"unable to login: {e}")

    def list_vehicles(self) -> list[dict]:
        """Loads a list of vehicles with general info"""

        if self.dev_mode:
            with open("test_list.json") as f:
                return json.load(f)["vehicles"]

        self._refresh_token_if_needed()

        r = self.sess.request(
            method="GET",
            url=self.brand.api.url + f"/v4/accounts/{self.uid}/vehicles",
            headers=self._default_aws_headers(self.brand.api.key)
            | {"content-type": "application/json"},
            params={"stage": "ALL"},
            auth=self.aws_auth,
        )

        r.raise_for_status()
        _LOGGER.debug(f"list_vehicles: {r.text}")
        r = r.json()

        if not "vehicles" in r:
            raise Exception(f"incorrect response: {r}")

        return r["vehicles"]

    def get_vehicle(self, vin: str) -> dict:
        """Gets a more detailed info abount a vehicle with a given VIN"""

        if self.dev_mode:
            with open(f"test_vehicle_{vin}.json") as f:
                return json.load(f)

        self._refresh_token_if_needed()

        r = self.sess.request(
            method="GET",
            url=self.brand.api.url + f"/v2/accounts/{self.uid}/vehicles/{vin}/status",
            headers=self._default_aws_headers(self.brand.api.key)
            | {"content-type": "application/json"},
            auth=self.aws_auth,
        )

        r.raise_for_status()
        _LOGGER.debug(f"get_vehicle ({vin}): {r.text}")
        r = r.json()

        return r

    def get_vehicle_status(self, vin: str) -> dict:
        """Loads another part of status of a vehicle with a given VIN"""

        if self.dev_mode:
            with open(f"test_vehicle_status_{vin}.json") as f:
                return json.load(f)

        self._refresh_token_if_needed()

        r = self.sess.request(
            method="GET",
            url=self.brand.api.url
            + f"/v1/accounts/{self.uid}/vehicles/{vin}/remote/status",
            headers=self._default_aws_headers(self.brand.api.key)
            | {"content-type": "application/json"},
            auth=self.aws_auth,
        )

        r.raise_for_status()
        _LOGGER.debug(f"get_vehicle_status ({vin}): {r.text}")
        r = r.json()

        return r

    def get_vehicle_location(self, vin: str) -> dict:
        """Gets last known location of a vehicle with a given VIN"""

        if self.dev_mode:
            with open(f"test_vehicle_location_{vin}.json") as f:
                return json.load(f)

        self._refresh_token_if_needed()

        r = self.sess.request(
            method="GET",
            url=self.brand.api.url
            + f"/v1/accounts/{self.uid}/vehicles/{vin}/location/lastknown",
            headers=self._default_aws_headers(self.brand.api.key)
            | {"content-type": "application/json"},
            auth=self.aws_auth,
        )

        r.raise_for_status()
        _LOGGER.debug(f"get_vehicle_location ({vin}): {r.text}")
        r = r.json()

        return r

    def get_vehicle_notifications(self, vin: str, limit: int | None = 30) -> dict:
        """Loads notifications for a vehicle with a given VIN"""

        self._refresh_token_if_needed()

        url = (
            self.brand.api.url + f"/v1/accounts/{self.uid}/vehicles/{vin}/notifications"
        )

        if limit is not None:
            url += f"?limit={limit}"

        r = self.sess.request(
            method="GET",
            url=url,
            headers=self._default_aws_headers(self.brand.api.key)
            | {"content-type": "application/json"},
            auth=self.aws_auth,
        )

        r.raise_for_status()
        _LOGGER.debug(f"get_vehicle_notifications ({vin}): {r.text}")
        r = r.json()

        return r

    def _pin_auth(self) -> str:
        data = {
            "pin": base64.b64encode(self.pin.encode()).decode(encoding="utf-8"),
        }

        self._refresh_token_if_needed()

        r = self.sess.request(
            method="POST",
            url=self.brand.auth.url
            + f"/v1/accounts/{self.uid}/ignite/pin/authenticate",
            headers=self._default_aws_headers(self.brand.auth.token)
            | {"content-type": "application/json"},
            auth=self.aws_auth,
            json=data,
        )

        r.raise_for_status()
        _LOGGER.debug(f"pin auth: {r.text}")
        r = r.json()

        if not "token" in r:
            raise Exception(f"authentication failed: no token found: {r}")

        return r["token"]

    def command(self, vin: str, cmd: Command):
        """Sends given command to the vehicle with a given VIN"""

        if self.dev_mode:
            return

        pin_auth = self._pin_auth()

        data = {
            "command": cmd.name,
            "pinAuth": pin_auth,
        }

        r = self.sess.request(
            method="POST",
            url=self.brand.api.url
            + f"/v1/accounts/{self.uid}/vehicles/{vin}/{cmd.url}",
            headers=self._default_aws_headers(self.brand.api.key)
            | {"content-type": "application/json"},
            auth=self.aws_auth,
            json=data,
        )

        r.raise_for_status()
        _LOGGER.debug(f"command execute ({vin} {cmd}): {r.text}")
        r = r.json()

        if not "responseStatus" in r or r["responseStatus"] != "pending":
            error = r.get("debugMsg", "unknown error")
            raise Exception(f"command queuing failed: {error} ({r})")

        return r["correlationId"]

    def set_charging_level(self, vin: str, level: ChargingLevel):
        """Sets the charging level on the vehicle with a given VIN"""

        if self.dev_mode:
            return

        pin_auth = self._pin_auth()

        data = {
            "preference": level.name,
            "pinAuth": pin_auth,
        }

        r = self.sess.request(
            method="PUT",
            url=self.brand.api.url
            + f"/v2/accounts/{self.uid}/vehicles/{vin}/ev/charge/preference/",
            headers=self._default_aws_headers(self.brand.api.key)
            | {"content-type": "application/json"},
            auth=self.aws_auth,
            json=data,
        )

        r.raise_for_status()
        _LOGGER.debug(f"set charging level ({vin} {level.name}): {r.text}")
        r = r.json()

        if not "correlationId" in r:
            error = r.get("debugMsg", "unknown error")
            raise Exception(f"set charging level failed: {error} ({r})")

        return r["correlationId"]
