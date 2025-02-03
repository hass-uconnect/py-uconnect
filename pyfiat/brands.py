from dataclasses import dataclass

API_URL_EU = "https://channels.sdpr-01.fcagcv.com"
API_URL_US = "https://channels.sdpr-02.fcagcv.com"

TOKEN_URL_EU = "https://authz.sdpr-01.fcagcv.com/v2/cognito/identity/token"
TOKEN_URL_US = "https://authz.sdpr-02.fcagcv.com/v2/cognito/identity/token"
TOKEN_URL_US_PREP = "https://authz.sdpr-02.prep.fcagcv.com/v2/cognito/identity/token"

LOCALE_EU = "de_de"
LOCALE_US = "en_us"

REGION_US = "us-east-1"
REGION_EU = "eu-west-1"


@dataclass
class API:
    url: str
    key: str


API_EU = API(
    url="https://channels.sdpr-01.fcagcv.com",
    key="2wGyL6PHec9o1UeLPYpoYa1SkEWqeBur9bLsi24i",
)

API_US = API(
    url="https://channels.sdpr-02.fcagcv.com",
    key="OgNqp2eAv84oZvMrXPIzP8mR8a6d9bVm1aaH9LqU",
)


@dataclass
class Auth:
    url: str
    token: str


AUTH_EU = Auth(
    url="https://mfa.fcl-01.fcagcv.com",
    token="JWRYW7IYhW9v0RqDghQSx4UcRYRILNmc8zAuh5ys",
)

AUTH_US = Auth(
    url="https://mfa.fcl-02.fcagcv.com",
    token="fNQO6NjR1N6W0E5A6sTzR3YY4JGbuPv48Nj9aZci",
)

AUTH_US_PREP = Auth(
    url="https://mfa.fcl-02.prep.fcagcv.com",
    token="lHBEtsqT1Y5oKvzhvA9KW6rkirU3ZtGf44jTIiQV"
)


@dataclass
class Brand:
    name: str
    region: str
    login_api_key: str
    login_url: str
    token_url: list[str]
    api: API
    auth: list[Auth]
    locale: str


FIAT_EU = Brand(
    name="FIAT_EU",
    region=REGION_EU,
    login_api_key="3_mOx_J2dRgjXYCdyhchv3b5lhi54eBcdCTX4BI8MORqmZCoQWhA0mV2PTlptLGUQI",
    login_url="https://loginmyuconnect.fiat.com",
    token_url=[TOKEN_URL_EU, TOKEN_URL_US],
    api=API_EU,
    auth=[AUTH_EU, AUTH_US],
    locale=LOCALE_EU,
)

FIAT_US = Brand(
    name="FIAT_US",
    region=REGION_US,
    login_api_key="3_WfFvlZJwcSdOD0LFQCngUV3W390R4Yshpuq3RsZvnV4VG0c9Q6R0RtDwcXc8dTrI",
    login_url="https://login-us.fiat.com",
    token_url=[TOKEN_URL_US, TOKEN_URL_EU],
    api=API_US,
    auth=[AUTH_EU, AUTH_US],
    locale=LOCALE_US,
)

FIAT_ASIA = Brand(
    name="FIAT_ASIA",
    region=REGION_EU,
    login_api_key="4_YAQNaPqdPEUbbzhvhunKAA",
    login_url="https://login-iap.fiat.com",
    token_url=[TOKEN_URL_EU, TOKEN_URL_US],
    api=API_EU,
    auth=[AUTH_EU, AUTH_US],
    locale=LOCALE_EU,
)

FIAT_CANADA = Brand(
    name="FIAT_CANADA",
    region=REGION_US,
    login_api_key="3_Ii2kSgQm4ljy19LIZeLwa76OlmWbpSa8w3aSP5VJdx19tub3oWxsFR-HEusDnUEh",
    login_url="https://login-stage-us.fiat.com",
    token_url={TOKEN_URL_US_PREP, TOKEN_URL_US, TOKEN_URL_EU},
    api=API_US,
    auth=[AUTH_US_PREP, AUTH_US, AUTH_EU],
    locale=LOCALE_US,
)

ALFA_ROMEO_US_CANADA = Brand(
    name="ALFA_ROMEO_US_CANADA",
    region=REGION_US,
    login_api_key="3_FSxGyaktviayTDRcgp9r9o2KjuFSrHT13wWNN9zPrvAGUCoXPDqoIPOwlBUhck4A",
    login_url="https://login-us.alfaromeo.com",
    token_url=[TOKEN_URL_US, TOKEN_URL_EU],
    api=API_US,
    auth=[AUTH_US, AUTH_EU],
    locale=LOCALE_US,
)

ALFA_ROMEO_ASIA = Brand(
    name="ALFA_ROMEO_ASIA",
    region=REGION_EU,
    login_api_key="4_PSQeADnQ4p5XOaDgT0B5pA",
    login_url="https://login-iap.alfaromeo.com",
    token_url=[TOKEN_URL_EU, TOKEN_URL_US],
    api=API_EU,
    auth=[AUTH_EU, AUTH_US],
    locale=LOCALE_EU,
)

ALFA_ROMEO_EU = Brand(
    name="ALFA_ROMEO_EU",
    region=REGION_EU,
    login_api_key="3_h8sj2VQI-KYXiunPq9a1QuAA4yWkY0r5AD1u8A8B1RPn_Cvl54xcoc2-InH5onJ1",
    login_url="https://login.alfaromeo.com",
    token_url=[TOKEN_URL_EU, TOKEN_URL_US],
    api=API_EU,
    auth=[AUTH_EU, AUTH_US],
    locale=LOCALE_EU,
)

CHRYSLER_CANADA = Brand(
    name="CHRYSLER_CANADA",
    region=REGION_US,
    login_api_key="3_gdhu-ur4jc2hEryDMnF4YPELkjzSi-invZTjop4isZu4ReHodVcuL44u93cOUqMC",
    login_url="https://login-stage-us.chrysler.com",
    token_url=[TOKEN_URL_US, TOKEN_URL_EU],
    api=API_US,
    auth=[AUTH_US, AUTH_EU],
    locale=LOCALE_US,
)

CHRYSLER_US = Brand(
    name="CHRYSLER_US",
    region=REGION_US,
    login_api_key="3_cv4AzHkJh48-cqwaf_Ahcg1HnsmQqz1lm0sOdVdHW5FjT3m6SyywywOBaskBQqwn",
    login_url="https://login-us.chrysler.com",
    token_url=[TOKEN_URL_US, TOKEN_URL_EU],
    api=API_US,
    auth=[AUTH_US, AUTH_EU],
    locale=LOCALE_US,
)

MASERATI_EU = Brand(
    name="MASERATI_EU",
    region=REGION_EU,
    login_api_key="3_rNbVuhn2gIt3BnLjlGsJcMo26Lft3avDne_FLRT34Dy_9OxHtCVOnplwY436lGZa",
    login_url="https://login.maserati.com",
    token_url=[TOKEN_URL_EU, TOKEN_URL_US],
    api=API_EU,
    auth=[AUTH_EU, AUTH_US],
    locale=LOCALE_EU,
)

MASERATI_ASIA = Brand(
    name="MASERATI_ASIA",
    region=REGION_EU,
    login_api_key="4_uwF-in6KF-aMbEkPAb-fOg",
    login_url="https://accounts.au1.gigya.com",
    token_url=[TOKEN_URL_EU, TOKEN_URL_US],
    api=API_EU,
    auth=[AUTH_EU, AUTH_US],
    locale=LOCALE_EU,
)

MASERATI_US_CANADA = Brand(
    name="MASERATI_US_CANADA",
    region=REGION_US,
    login_api_key="3_nShL4-O7IL0OGqroO8AzwiRU0-ZHcBZ4TLBrh5MORusMo5XYxhCLXPYfjI4OOLOy",
    login_url="https://login-us.maserati.com",
    token_url=[TOKEN_URL_US, TOKEN_URL_EU],
    api=API_US,
    auth=[AUTH_US, AUTH_EU],
    locale=LOCALE_US,
)

JEEP_EU = Brand(
    name="JEEP_EU",
    region=REGION_EU,
    login_api_key="3_ZvJpoiZQ4jT5ACwouBG5D1seGEntHGhlL0JYlZNtj95yERzqpH4fFyIewVMmmK7j",
    login_url="https://login.jeep.com",
    token_url=[TOKEN_URL_EU, TOKEN_URL_US],
    api=API_EU,
    auth=[AUTH_EU, AUTH_US],
    locale=LOCALE_EU,
)

JEEP_US = Brand(
    name="JEEP_US",
    region=REGION_US,
    login_api_key="3_5qxvrevRPG7--nEXe6huWdVvF5kV7bmmJcyLdaTJ8A45XUYpaR398QNeHkd7EB1X",
    login_url="https://login-us.jeep.com",
    token_url=[TOKEN_URL_US, TOKEN_URL_EU],
    api=API_US,
    auth=[AUTH_US, AUTH_EU],
    locale=LOCALE_US,
)

JEEP_ASIA = Brand(
    name="JEEP_ASIA",
    region=REGION_EU,
    login_api_key="4_zqGYHC7rM8RCHHl4YFDebA",
    login_url="https://login-iap.jeep.com",
    token_url=[TOKEN_URL_EU, TOKEN_URL_US],
    api=API_EU,
    auth=[AUTH_EU, AUTH_US],
    locale=LOCALE_EU,
)

DODGE_US = Brand(
    name="DODGE_US",
    region=REGION_US,
    login_api_key="4_dSRvo6ZIpp8_St7BF9VHGA",
    login_url="https://login-us.dodge.com",
    token_url=[TOKEN_URL_US, TOKEN_URL_EU],
    api=API_US,
    auth=[AUTH_US, AUTH_EU],
    locale=LOCALE_US,
)

RAM_US = Brand(
    name="RAM_US",
    region=REGION_US,
    login_api_key="3_7YjzjoSb7dYtCP5-D6FhPsCciggJFvM14hNPvXN9OsIiV1ujDqa4fNltDJYnHawO",
    login_url="https://login-us.ramtrucks.com",
    token_url=[TOKEN_URL_US, TOKEN_URL_EU],
    api=API_US,
    auth=[AUTH_US, AUTH_EU],
    locale=LOCALE_US,
)

BRANDS = {
    FIAT_EU.name: FIAT_EU,
    FIAT_US.name: FIAT_US,
    FIAT_CANADA.name: FIAT_CANADA,
    FIAT_ASIA.name: FIAT_ASIA,

    JEEP_EU.name: JEEP_EU,
    JEEP_US.name: JEEP_US,
    JEEP_ASIA.name: JEEP_ASIA,

    DODGE_US.name: DODGE_US,

    RAM_US.name: RAM_US,

    CHRYSLER_CANADA.name: CHRYSLER_CANADA,
    CHRYSLER_US.name: CHRYSLER_US,

    ALFA_ROMEO_US_CANADA.name: ALFA_ROMEO_US_CANADA,
    ALFA_ROMEO_EU.name: ALFA_ROMEO_EU,
    ALFA_ROMEO_ASIA.name: ALFA_ROMEO_ASIA,

    MASERATI_ASIA.name: MASERATI_ASIA,
    MASERATI_EU.name: MASERATI_EU,
    MASERATI_US_CANADA.name: MASERATI_US_CANADA,
}
