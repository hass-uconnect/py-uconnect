import requests
import uuid
import json
import boto3
import base64
import datetime

from dataclasses import dataclass
from requests_auth_aws_sigv4 import AWSSigV4

from .command import Command

AWS_REGION = "eu-west-1"
LOGIN_API_KEY = "3_mOx_J2dRgjXYCdyhchv3b5lhi54eBcdCTX4BI8MORqmZCoQWhA0mV2PTlptLGUQI"
API_KEY = "2wGyL6PHec9o1UeLPYpoYa1SkEWqeBur9bLsi24i"
LOGIN_URL = "https://loginmyuconnect.fiat.com"
TOKEN_URL = "https://authz.sdpr-01.fcagcv.com/v2/cognito/identity/token"
API_URL = "https://channels.sdpr-01.fcagcv.com"
AUTH_API_KEY = "JWRYW7IYhW9v0RqDghQSx4UcRYRILNmc8zAuh5ys"
AUTH_URL = "https://mfa.fcl-01.fcagcv.com"
LOCALE = "de_de"


@dataclass
class Brand:
    name: str
    AWS_REGION: str = "eu-west-1"
    LOGIN_API_KEY = "3_mOx_J2dRgjXYCdyhchv3b5lhi54eBcdCTX4BI8MORqmZCoQWhA0mV2PTlptLGUQI"
    API_KEY = "2wGyL6PHec9o1UeLPYpoYa1SkEWqeBur9bLsi24i"
    LOGIN_URL = "https://loginmyuconnect.fiat.com"
    TOKEN_URL = "https://authz.sdpr-01.fcagcv.com/v2/cognito/identity/token"
    API_URL = "https://channels.sdpr-01.fcagcv.com"
    AUTH_API_KEY = "JWRYW7IYhW9v0RqDghQSx4UcRYRILNmc8zAuh5ys"
    AUTH_URL = "https://mfa.fcl-01.fcagcv.com"


class API:
    def __init__(self, email: str, password: str, pin: str, dev_mode: bool = False):
        self.email = email
        self.password = password
        self.pin = pin
        self.dev_mode = dev_mode

        self.uid: str = None
        self.aws_auth: AWSSigV4 = None

        self.sess = requests.Session()
        self.cognito_client = boto3.client(
            'cognito-identity', AWS_REGION) if not dev_mode else None

        self.expire_time: datetime.datetime = None

    def _with_default_params(self, params: dict):
        return params | {
            "targetEnv": "jssdk",
            "loginMode": "standard",
            "sdk": "js_latest",
            "authMode": "cookie",
            "sdkBuild": "12234",
            "format": "json",
            "APIKey": LOGIN_API_KEY,
        }

    def _default_aws_headers(self, key: str):
        return {
            "x-clientapp-name": "CWP",
            "x-clientapp-version": "1.0",
            "clientrequestid": uuid.uuid4().hex.upper()[0:16],
            "x-api-key": key,
            "locale": "de_de",
            "x-originator-type": "web",
        }

    def login(self):
        """Logs into the Fiat Cloud and caches the auth tokens"""

        r = self.sess.request(
            method="GET",
            url=LOGIN_URL + "/accounts.webSdkBootstrap",
            params={"apiKey": LOGIN_API_KEY}
        ).json()

        if r['statusCode'] != 200:
            raise Exception("bootstrap failed")

        r = self.sess.request(
            method="POST",
            url=LOGIN_URL + "/accounts.login",
            params=self._with_default_params({
                "loginID": self.email,
                "password": self.password,
                "sessionExpiration": 300,
                "include": "profile,data,emails,subscriptions,preferences"
            })
        ).json()

        if r['statusCode'] != 200:
            raise Exception("login failed")

        self.uid = r['UID']
        login_token = r['sessionInfo']['login_token']

        r = self.sess.request(
            method="POST",
            url=LOGIN_URL + "/accounts.getJWT",
            params=self._with_default_params({
                "login_token": login_token,
                "fields": "profile.firstName,profile.lastName,profile.email,country,locale,data.disclaimerCodeGSDP"
            })
        ).json()

        if r['statusCode'] != 200:
            raise Exception("unable to obtain JWT")

        r = self.sess.request(
            method="POST",
            url=TOKEN_URL,
            headers=self._default_aws_headers(API_KEY),
            json={"gigya_token": r['id_token']}
        ).json()

        r = self.cognito_client.get_credentials_for_identity(
            IdentityId=r['IdentityId'],
            Logins={"cognito-identity.amazonaws.com": r['Token']},
        )

        creds = r['Credentials']

        self.aws_auth = AWSSigV4(
            'execute-api',
            region=AWS_REGION,
            aws_access_key_id=creds['AccessKeyId'],
            aws_secret_access_key=creds['SecretKey'],
            aws_session_token=creds['SessionToken'],
        )

        self.expire_time = creds['Expiration']

    def _refresh_token_if_needed(self):
        """Checks if token is available and fresh, refreshes it otherwise"""

        if self.dev_mode:
            return

        if self.expire_time is None or datetime.datetime.now().astimezone() > self.expire_time - datetime.timedelta(minutes=5):
            self.login()

    def list_vehicles(self) -> list[dict]:
        """Loads a list of vehicles with general info"""

        if self.dev_mode:
            with open("test_list.json") as f:
                return json.load(f)['vehicles']

        self._refresh_token_if_needed()

        return self.sess.request(
            method="GET",
            url=API_URL + f"/v4/accounts/{self.uid}/vehicles",
            headers=self._default_aws_headers(
                API_KEY) | {"content-type": "application/json"},
            params={"stage": "ALL"},
            auth=self.aws_auth,
        ).json()['vehicles']

    def get_vehicle(self, vin: str) -> dict:
        """Gets a more detailed info abount a vehicle with a given VIN"""

        if self.dev_mode:
            with open(f"test_vehicle_{vin}.json") as f:
                return json.load(f)

        self._refresh_token_if_needed()

        return self.sess.request(
            method="GET",
            url=API_URL + f"/v2/accounts/{self.uid}/vehicles/{vin}/status",
            headers=self._default_aws_headers(
                API_KEY) | {"content-type": "application/json"},
            auth=self.aws_auth,
        ).json()

    def get_vehicle_status(self, vin: str) -> dict:
        """Loads another part of status of a vehicle with a given VIN"""

        if self.dev_mode:
            with open(f"test_vehicle_status_{vin}.json") as f:
                return json.load(f)

        self._refresh_token_if_needed()

        return self.sess.request(
            method="GET",
            url=API_URL +
            f"/v1/accounts/{self.uid}/vehicles/{vin}/remote/status",
            headers=self._default_aws_headers(
                API_KEY) | {"content-type": "application/json"},
            auth=self.aws_auth,
        ).json()

    def get_vehicle_location(self, vin: str) -> dict:
        """Gets last known location of a vehicle with a given VIN"""

        if self.dev_mode:
            with open(f"test_vehicle_location_{vin}.json") as f:
                return json.load(f)

        self._refresh_token_if_needed()

        return self.sess.request(
            method="GET",
            url=API_URL +
            f"/v1/accounts/{self.uid}/vehicles/{vin}/location/lastknown",
            headers=self._default_aws_headers(
                API_KEY) | {"content-type": "application/json"},
            auth=self.aws_auth,
        ).json()

    def command(self,
                vin: str, cmd: Command):
        """Sends given command to the vehicle with a given VIN"""

        data = {
            'pin': base64.b64encode(self.pin.encode()).decode(encoding="utf-8"),
        }

        self._refresh_token_if_needed()

        r = self.sess.request(
            method="POST",
            url=AUTH_URL +
            f"/v1/accounts/{self.uid}/ignite/pin/authenticate",
            headers=self._default_aws_headers(AUTH_API_KEY) | {
                "content-type": "application/json"},
            auth=self.aws_auth,
            json=data,
        ).json()

        if not 'token' in r:
            raise Exception("authentication failed")

        data = {
            "command": cmd.name,
            "pinAuth": r['token'],
        }

        r = self.sess.request(
            method="POST",
            url=API_URL +
            f"/v1/accounts/{self.uid}/vehicles/{vin}/{cmd.url}",
            headers=self._default_aws_headers(
                API_KEY) | {"content-type": "application/json"},
            auth=self.aws_auth,
            json=data,
        ).json()

        if not 'responseStatus' in r or r['responseStatus'] != 'pending':
            error = r.get('debugMsg', 'unknown error')
            raise Exception(f"command queuing failed: {error}")
