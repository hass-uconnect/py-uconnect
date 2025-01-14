from contextlib import suppress
import requests
import uuid
import json
import boto3
import logging
import http.client as http_client
import base64
from command import Command
from dataclasses import dataclass
import datetime


from requests_auth_aws_sigv4 import AWSSigV4

# from dataclasses import dataclass
# from dataclasses_json import dataclass_json

AWS_REGION = "eu-west-1"
LOGIN_API_KEY = "3_mOx_J2dRgjXYCdyhchv3b5lhi54eBcdCTX4BI8MORqmZCoQWhA0mV2PTlptLGUQI"
API_KEY = "2wGyL6PHec9o1UeLPYpoYa1SkEWqeBur9bLsi24i"
LOGIN_URL = "https://loginmyuconnect.fiat.com"
TOKEN_URL = "https://authz.sdpr-01.fcagcv.com/v2/cognito/identity/token"
API_URL = "https://channels.sdpr-01.fcagcv.com"
AUTH_API_KEY = "JWRYW7IYhW9v0RqDghQSx4UcRYRILNmc8zAuh5ys"
AUTH_URL = "https://mfa.fcl-01.fcagcv.com"
LOCALE = "de_de"


# http_client.HTTPConnection.debuglevel = 1
# logging.basicConfig()
# logging.getLogger().setLevel(logging.DEBUG)
# requests_log = logging.getLogger("requests.packages.urllib3")
# requests_log.setLevel(logging.DEBUG)
# requests_log.propagate = True

@dataclass
class Brand:
    name: str


@dataclass
class Wheel:
    type: str
    pressure: int = None
    status: str = None

    def __repr__(self):
        return f"type: {self.type}, pressure: {self.pressure}, status: {self.status}"


@dataclass
class Vehicle:
    vin: str
    brand: Brand = "fiat"
    odometer: float = None
    days_to_service: int = None
    distance_to_service: float = None
    distance_to_empty: int = None
    battery_voltage: float = None
    wheels: list[Wheel] = None
    state_of_charge: int = None
    plug_in_status: bool = None
    charging_status: str = None
    ignition_on: bool = None
    charging_level: str = None
    time_to_fully_charge_l3: int = None
    time_to_fully_charge_l2: int = None
    charge_power_preference: str = None

    def __repr__(self):
        return f"vin: {self.vin}\ndays_to_service: {self.days_to_service}\ndistance_to_service: {self.distance_to_service}\ndistance_to_empty: {self.distance_to_empty}\nbattery_voltage: {self.battery_voltage}"


class Client:
    def __init__(self, email: str, password: str, pin: str, mode: str = "real"):
        self.email = email
        self.password = password
        self.pin = pin
        self.mode = mode

        self.uid: str = None
        self.aws_auth = None

        self.sess = requests.Session()
        self.cognito_client = boto3.client('cognito-identity', AWS_REGION)

        self.expire_time: datetime.datetime = None

    def with_default_params(self, params: dict):
        return params | {
            "targetEnv": "jssdk",
            "loginMode": "standard",
            "sdk": "js_latest",
            "authMode": "cookie",
            "sdkBuild": "12234",
            "format": "json",
            "APIKey": LOGIN_API_KEY,
        }

    def default_aws_headers(self, key: str):
        return {
            "x-clientapp-name": "CWP",
            "x-clientapp-version": "1.0",
            "clientrequestid": uuid.uuid4().hex.upper()[0:16],
            "x-api-key": key,
            "locale": LOCALE,
            "x-originator-type": "web",
        }

    def login(self):
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
            params=self.with_default_params({
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
            params=self.with_default_params({
                "login_token": login_token,
                "fields": "profile.firstName,profile.lastName,profile.email,country,locale,data.disclaimerCodeGSDP"
            })
        ).json()

        if r['statusCode'] != 200:
            raise Exception("unable to obtain JWT")

        r = self.sess.request(
            method="POST",
            url=TOKEN_URL,
            headers=self.default_aws_headers(API_KEY),
            json={"gigya_token": r['id_token']}
        ).json()

        r = self.cognito_client.get_credentials_for_identity(
            IdentityId=r['IdentityId'],
            Logins={"cognito-identity.amazonaws.com": r['Token']},
        )

        print(r)

        creds = r['Credentials']

        self.aws_auth = AWSSigV4(
            'execute-api',
            region=AWS_REGION,
            aws_access_key_id=creds['AccessKeyId'],
            aws_secret_access_key=creds['SecretKey'],
            aws_session_token=creds['SessionToken'],
        )
        self.expire_time = datetime.datetime.now()

    def need_to_login(self):
        return self.expire_time is None or datetime.datetime.now() > self.expire_time - datetime.time.minute(5)

    def fake_fetch(self):
        with open("test_data.json", mode="r") as data_file:
            return json.load(data_file)

    def fetch(self):
        if self.mode == "fake":
            return self.fake_fetch()

        if self.need_to_login():
            self.login()

        vehicles = self.sess.request(
            method="GET",
            url=API_URL + f"/v4/accounts/{self.uid}/vehicles",
            headers=self.default_aws_headers(
                API_KEY) | {"content-type": "application/json"},
            params={"stage": "ALL"},
            auth=self.aws_auth,
        ).json()['vehicles']

        r = {}
        for vin in [x['vin'] for x in vehicles]:
            v = self.sess.request(
                method="GET",
                url=API_URL + f"/v2/accounts/{self.uid}/vehicles/{vin}/status",
                headers=self.default_aws_headers(
                    API_KEY) | {"content-type": "application/json"},
                auth=self.aws_auth,
            ).json()
            r[vin] = v

        return r

    def get_vehicles(self) -> list[Vehicle]:
        data = self.fetch()
        return [Client.create_vehicle(k, v) for k, v in data.items()]

    def create_vehicle(vin: str, params: dict) -> Vehicle:
        ret = Vehicle(vin)
        with suppress(KeyError, TypeError):
            ret.battery_voltage = float(
                params["vehicleInfo"]["batteryInfo"]["batteryVoltage"]["value"])
            ret.charging_status = params["evInfo"]["battery"]["chargingStatus"]
            ret.days_to_service = int(params["vehicleInfo"]["daysToService"])
            ret.distance_to_empty = int(
                params["evInfo"]["battery"]["distanceToEmpty"]["value"])
            ret.distance_to_service = float(
                params["vehicleInfo"]["distanceToService"]["distanceToService"]["value"])
            ret.plug_in_status = bool(
                params["evInfo"]["battery"]["plugInStatus"])
            ret.state_of_charge = int(
                params["evInfo"]["battery"]["stateOfCharge"])
            ret.ignition_on = True if params["evInfo"]["ignitionStatus"] == "ON" else False
            ret.charging_level = params["evInfo"]["battery"]["chargingLevel"]
            ret.time_to_fully_charge_l3 = params["evInfo"]["battery"]["timeToFullyChargeL3"]
            ret.time_to_fully_charge_l2 = params["evInfo"]["battery"]["timeToFullyChargeL2"]
            ret.charge_power_preference = params["evInfo"]["chargePowerPreference"]

            ret.wheels = []
            wheels = params["vehicleInfo"]["tyrePressure"]
            for w in wheels:
                x = Wheel(w["type"], None if w["pressure"]["value"] ==
                          "null" else int(w["pressure"]["value"]), w["status"])
                ret.wheels.append(x)

            ret.odometer = float(
                params["vehicleInfo"]["odometer"]["odometer"]["value"])
        return ret

    def execute(self,
                vin: str, cmd: Command):
        data = {
            'pin': base64.b64encode(self.pin.encode()).decode(encoding="utf-8"),
        }

        r = self.sess.request(
            method="POST",
            url=AUTH_URL +
            f"/v1/accounts/{self.uid}/ignite/pin/authenticate",
            headers=self.default_aws_headers(AUTH_API_KEY) | {
                "content-type": "application/json"},
            auth=self.aws_auth,
            json=data,
        ).json()

        if not 'token' in r:
            raise Exception("authentication failed")

        data = {
            "command": cmd.message,
            "pinAuth": r['token'],
        }

        r = self.sess.request(
            method="POST",
            url=API_URL +
            f"/v1/accounts/{self.uid}/vehicles/{vin}/{cmd.url}",
            headers=self.default_aws_headers(
                API_KEY) | {"content-type": "application/json"},
            auth=self.aws_auth,
            json=data,
        ).json()

        if not 'responseStatus' in r or r['responseStatus'] != 'pending':
            raise Exception("command execution failed")

        # print(json.dumps(r, indent=2))
