from dataclasses import dataclass


@dataclass
class Brand:
    name: str
    region: str
    login_api_key: str
    api_key: str
    login_url: str
    token_url: str
    api_url: str
    auth_api_key: str
    auth_url: str
    locale: str


FIAT_EU = Brand(
    name="FIAT_EU",
    region="eu-west-1",
    login_api_key="3_mOx_J2dRgjXYCdyhchv3b5lhi54eBcdCTX4BI8MORqmZCoQWhA0mV2PTlptLGUQI",
    api_key="2wGyL6PHec9o1UeLPYpoYa1SkEWqeBur9bLsi24i",
    login_url="https://loginmyuconnect.fiat.com",
    token_url="https://authz.sdpr-01.fcagcv.com/v2/cognito/identity/token",
    api_url="https://channels.sdpr-01.fcagcv.com",
    auth_api_key="JWRYW7IYhW9v0RqDghQSx4UcRYRILNmc8zAuh5ys",
    auth_url="https://mfa.fcl-01.fcagcv.com",
    locale="de_de",
)

FIAT_US = Brand(
    name="FIAT_US",
    region="us-east-1",
    login_api_key="3_etlYkCXNEhz4_KJVYDqnK1CqxQjvJStJMawBohJU2ch3kp30b0QCJtLCzxJ93N-M",
    api_key="OgNqp2eAv84oZvMrXPIzP8mR8a6d9bVm1aaH9LqU",
    login_url="https://login-us.fiat.com",
    token_url="https://authz.sdpr-02.fcagcv.com/v2/cognito/identity/token",
    api_url="https://channels.sdpr-02.fcagcv.com",
    auth_api_key="JWRYW7IYhW9v0RqDghQSx4UcRYRILNmc8zAuh5ys",
    auth_url="https://mfa.fcl-01.fcagcv.com",
    locale="en_us",
)

FIAT_ASIA = Brand(
    name="FIAT_ASIA",
    region="eu-west-1",
    login_api_key="4_YAQNaPqdPEUbbzhvhunKAA",
    api_key="qLYupk65UU1tw2Ih1cJhs4izijgRDbir2UFHA3Je",
    login_url="https://login-iap.fiat.com",
    token_url="https://authz.sdpr-01.fcagcv.com/v2/cognito/identity/token",
    api_url="https://channels.sdpr-01.fcagcv.com",
    auth_api_key="JWRYW7IYhW9v0RqDghQSx4UcRYRILNmc8zAuh5ys",
    auth_url="https://mfa.fcl-01.fcagcv.com",
    locale="en_us",
)

FIAT_CANADA = Brand(
    name="FIAT_CANADA",
    region="us-east-1",
    login_api_key="3_Ii2kSgQm4ljy19LIZeLwa76OlmWbpSa8w3aSP5VJdx19tub3oWxsFR-HEusDnUEh",
    api_key="2rVctWlJz47M1GsL7o9ph2RPCqAzf57r7nYtdK1B",
    login_url="https://login-stage-us.fiat.com",
    token_url="https://authz.sdpr-02.prep.fcagcv.com/v2/cognito/identity/token",
    api_url="https://channels.sdpr-02.prep.fcagcv.com",
    auth_api_key="lHBEtsqT1Y5oKvzhvA9KW6rkirU3ZtGf44jTIiQV",
    auth_url="https://mfa.fcl-02.prep.fcagcv.com",
    locale="en_us",
)

ALFA_ROMEO_US_CANADA = Brand(
    name="ALFA_ROMEO_US_CANADA",
    region="us-east-1",
    login_api_key="3_FSxGyaktviayTDRcgp9r9o2KjuFSrHT13wWNN9zPrvAGUCoXPDqoIPOwlBUhck4A",
    api_key="OgNqp2eAv84oZvMrXPIzP8mR8a6d9bVm1aaH9LqU",
    login_url="https://login-us.alfaromeo.com",
    token_url="https://authz.sdpr-02.fcagcv.com/v2/cognito/identity/token",
    api_url="https://channels.sdpr-02.fcagcv.com",
    auth_api_key="fNQO6NjR1N6W0E5A6sTzR3YY4JGbuPv48Nj9aZci",
    auth_url="https://mfa.fcl-02.fcagcv.com",
    locale="en_us",
)

ALFA_ROMEO_ASIA = Brand(
    name="ALFA_ROMEO_ASIA",
    region="us-east-1",
    login_api_key="4_PSQeADnQ4p5XOaDgT0B5pA",
    api_key="OgNqp2eAv84oZvMrXPIzP8mR8a6d9bVm1aaH9LqU",
    login_url="https://login-iap.alfaromeo.com",
    token_url="https://authz.sdpr-02.fcagcv.com/v2/cognito/identity/token",
    api_url="https://channels.sdpr-02.fcagcv.com",
    auth_api_key="fNQO6NjR1N6W0E5A6sTzR3YY4JGbuPv48Nj9aZci",
    auth_url="https://mfa.fcl-02.fcagcv.com",
    locale="en_us",
)

ALFA_ROMEO_EU = Brand(
    name="ALFA_ROMEO_EU",
    region="us-east-1",
    login_api_key="3_h8sj2VQI-KYXiunPq9a1QuAA4yWkY0r5AD1u8A8B1RPn_Cvl54xcoc2-InH5onJ1",
    api_key="OgNqp2eAv84oZvMrXPIzP8mR8a6d9bVm1aaH9LqU",
    login_url="https://login.alfaromeo.com",
    token_url="https://authz.sdpr-02.fcagcv.com/v2/cognito/identity/token",
    api_url="https://channels.sdpr-02.fcagcv.com",
    auth_api_key="fNQO6NjR1N6W0E5A6sTzR3YY4JGbuPv48Nj9aZci",
    auth_url="https://mfa.fcl-02.fcagcv.com",
    locale="de_de",
)

CHRYSLER_CANADA = Brand(
    name="CHRYSLER_CANADA",
    region="us-east-1",
    login_api_key="3_gdhu-ur4jc2hEryDMnF4YPELkjzSi-invZTjop4isZu4ReHodVcuL44u93cOUqMC",
    api_key="OgNqp2eAv84oZvMrXPIzP8mR8a6d9bVm1aaH9LqU",
    login_url="https://login-stage-us.chrysler.com",
    token_url="https://authz.sdpr-02.fcagcv.com/v2/cognito/identity/token",
    api_url="https://channels.sdpr-02.fcagcv.com",
    auth_api_key="fNQO6NjR1N6W0E5A6sTzR3YY4JGbuPv48Nj9aZci",
    auth_url="https://mfa.fcl-02.fcagcv.com",
    locale="en_us",
)

CHRYSLER_US = Brand(
    name="CHRYSLER_US",
    region="us-east-1",
    login_api_key="3_cv4AzHkJh48-cqwaf_Ahcg1HnsmQqz1lm0sOdVdHW5FjT3m6SyywywOBaskBQqwn",
    api_key="OgNqp2eAv84oZvMrXPIzP8mR8a6d9bVm1aaH9LqU",
    login_url="https://login-us.chrysler.com",
    token_url="https://authz.sdpr-02.fcagcv.com/v2/cognito/identity/token",
    api_url="https://channels.sdpr-02.fcagcv.com",
    auth_api_key="fNQO6NjR1N6W0E5A6sTzR3YY4JGbuPv48Nj9aZci",
    auth_url="https://mfa.fcl-02.fcagcv.com",
    locale="en_us",
)

MASERATI_EU = Brand(
    name="MASERATI_EU",
    region="eu-west-1",
    login_api_key="3_rNbVuhn2gIt3BnLjlGsJcMo26Lft3avDne_FLRT34Dy_9OxHtCVOnplwY436lGZa",
    api_key="qLYupk65UU1tw2Ih1cJhs4izijgRDbir2UFHA3Je",
    login_url="https://login.maserati.com",
    token_url="https://authz.sdpr-01.fcagcv.com/v2/cognito/identity/token",
    api_url="https://channels.sdpr-01.fcagcv.com",
    auth_api_key="JWRYW7IYhW9v0RqDghQSx4UcRYRILNmc8zAuh5ys",
    auth_url="https://mfa.fcl-01.fcagcv.com",
    locale="de_de",
)

MASERATI_ASIA = Brand(
    name="MASERATI_ASIA",
    region="eu-west-1",
    login_api_key="4_uwF-in6KF-aMbEkPAb-fOg",
    api_key="qLYupk65UU1tw2Ih1cJhs4izijgRDbir2UFHA3Je",
    login_url="https://accounts.au1.gigya.com",
    token_url="https://authz.sdpr-01.fcagcv.com/v2/cognito/identity/token",
    api_url="https://channels.sdpr-01.fcagcv.com",
    auth_api_key="JWRYW7IYhW9v0RqDghQSx4UcRYRILNmc8zAuh5ys",
    auth_url="https://mfa.fcl-01.fcagcv.com",
    locale="en_us",
)

MASERATI_US_CANADA = Brand(
    name="MASERATI_US_CANADA",
    region="us-east-1",
    login_api_key="3_nShL4-O7IL0OGqroO8AzwiRU0-ZHcBZ4TLBrh5MORusMo5XYxhCLXPYfjI4OOLOy",
    api_key="OgNqp2eAv84oZvMrXPIzP8mR8a6d9bVm1aaH9LqU",
    login_url="https://login-us.maserati.com",
    token_url="https://authz.sdpr-02.fcagcv.com/v2/cognito/identity/token",
    api_url="https://channels.sdpr-02.fcagcv.com",
    auth_api_key="fNQO6NjR1N6W0E5A6sTzR3YY4JGbuPv48Nj9aZci",
    auth_url="https://mfa.fcl-02.fcagcv.com",
    locale="en_us",
)

JEEP_EU = Brand(
    name="JEEP_EU",
    region="eu-west-1",
    login_api_key="3_ZvJpoiZQ4jT5ACwouBG5D1seGEntHGhlL0JYlZNtj95yERzqpH4fFyIewVMmmK7j",
    api_key="2wGyL6PHec9o1UeLPYpoYa1SkEWqeBur9bLsi24i",
    login_url="https://login.jeep.com",
    token_url="https://authz.sdpr-01.fcagcv.com/v2/cognito/identity/token",
    api_url="https://channels.sdpr-01.fcagcv.com",
    auth_api_key="JWRYW7IYhW9v0RqDghQSx4UcRYRILNmc8zAuh5ys",
    auth_url="https://mfa.fcl-01.fcagcv.com",
    locale="de_de",
)

JEEP_US = Brand(
    name="JEEP_US",
    region="us-east-1",
    login_api_key="3_5qxvrevRPG7--nEXe6huWdVvF5kV7bmmJcyLdaTJ8A45XUYpaR398QNeHkd7EB1X",
    api_key="OgNqp2eAv84oZvMrXPIzP8mR8a6d9bVm1aaH9LqU",
    login_url="https://login-us.jeep.com",
    token_url="https://authz.sdpr-02.fcagcv.com/v2/cognito/identity/token",
    api_url="https://channels.sdpr-02.fcagcv.com",
    auth_api_key="fNQO6NjR1N6W0E5A6sTzR3YY4JGbuPv48Nj9aZci",
    auth_url="https://mfa.fcl-02.fcagcv.com",
    locale="en_us",
)

JEEP_ASIA = Brand(
    name="JEEP_ASIA",
    region="eu-west-1",
    login_api_key="4_zqGYHC7rM8RCHHl4YFDebA",
    api_key="2wGyL6PHec9o1UeLPYpoYa1SkEWqeBur9bLsi24i",
    login_url="https://login-iap.jeep.com",
    token_url="https://authz.sdpr-01.fcagcv.com/v2/cognito/identity/token",
    api_url="https://channels.sdpr-01.fcagcv.com",
    auth_api_key="JWRYW7IYhW9v0RqDghQSx4UcRYRILNmc8zAuh5ys",
    auth_url="https://mfa.fcl-01.fcagcv.com",
    locale="de_de",
)

DODGE_US = Brand(
    name="DODGE_US",
    region="us-east-1",
    login_api_key="3_etlYkCXNEhz4_KJVYDqnK1CqxQjvJStJMawBohJU2ch3kp30b0QCJtLCzxJ93N-M",
    api_key="OgNqp2eAv84oZvMrXPIzP8mR8a6d9bVm1aaH9LqU",
    login_url="https://accounts.us1.gigya.com",
    token_url="https://authz.sdpr-02.fcagcv.com/v2/cognito/identity/token",
    api_url="https://channels.sdpr-02.fcagcv.com",
    auth_api_key="JWRYW7IYhW9v0RqDghQSx4UcRYRILNmc8zAuh5ys",
    auth_url="https://mfa.fcl-01.fcagcv.com",
    locale="en_us",
)

RAM_US = Brand(
    name="RAM_US",
    region="us-east-1",
    login_api_key="3_7YjzjoSb7dYtCP5-D6FhPsCciggJFvM14hNPvXN9OsIiV1ujDqa4fNltDJYnHawO",
    api_key="OgNqp2eAv84oZvMrXPIzP8mR8a6d9bVm1aaH9LqU",
    login_url="https://accounts.us1.gigya.com",
    token_url="https://authz.sdpr-02.fcagcv.com/v2/cognito/identity/token",
    api_url="https://channels.sdpr-02.fcagcv.com",
    auth_api_key="JWRYW7IYhW9v0RqDghQSx4UcRYRILNmc8zAuh5ys",
    auth_url="https://mfa.fcl-01.fcagcv.com",
    locale="en_us",
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
