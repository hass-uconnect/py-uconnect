from dataclasses import dataclass


@dataclass
class Brand:
    name: str
    region: str = "eu-west-1"
    login_api_key: str = "3_mOx_J2dRgjXYCdyhchv3b5lhi54eBcdCTX4BI8MORqmZCoQWhA0mV2PTlptLGUQI"
    api_key: str = "2wGyL6PHec9o1UeLPYpoYa1SkEWqeBur9bLsi24i"
    login_url: str = "https://loginmyuconnect.fiat.com"
    token_url: str = "https://authz.sdpr-01.fcagcv.com/v2/cognito/identity/token"
    api_url: str = "https://channels.sdpr-01.fcagcv.com"
    auth_api_key: str = "JWRYW7IYhW9v0RqDghQSx4UcRYRILNmc8zAuh5ys"
    auth_url: str = "https://mfa.fcl-01.fcagcv.com"


FIAT_EU = Brand("fiat_eu")

FIAT_US = Brand(
    name="fiat_us",
    region="us-east-1",
    login_api_key="3_etlYkCXNEhz4_KJVYDqnK1CqxQjvJStJMawBohJU2ch3kp30b0QCJtLCzxJ93N-M",
    api_key="OgNqp2eAv84oZvMrXPIzP8mR8a6d9bVm1aaH9LqU",
    login_url="https://login-us.fiat.com",
    token_url="https://authz.sdpr-02.fcagcv.com/v2/cognito/identity/token",
    api_url="https://channels.sdpr-02.fcagcv.com",
    auth_api_key="JWRYW7IYhW9v0RqDghQSx4UcRYRILNmc8zAuh5ys",
    auth_url="https://mfa.fcl-01.fcagcv.com"
)

JEEP_EU = Brand(
    name="jeep_eu",
    login_api_key="3_ZvJpoiZQ4jT5ACwouBG5D1seGEntHGhlL0JYlZNtj95yERzqpH4fFyIewVMmmK7j",
    login_url="https://login.jeep.com"
)

JEEP_US = Brand(
    name="jeep_us",
    region="us-east-1",
    login_api_key="3_5qxvrevRPG7--nEXe6huWdVvF5kV7bmmJcyLdaTJ8A45XUYpaR398QNeHkd7EB1X",
    api_key="OgNqp2eAv84oZvMrXPIzP8mR8a6d9bVm1aaH9LqU",
    login_url="https://login-us.jeep.com",
    token_url="https://authz.sdpr-02.fcagcv.com/v2/cognito/identity/token",
    api_url="https://channels.sdpr-02.fcagcv.com",
    auth_api_key="fNQO6NjR1N6W0E5A6sTzR3YY4JGbuPv48Nj9aZci",
    auth_url="https://mfa.fcl-02.fcagcv.com"
)

DODGE_US = Brand(
    name="dodge_us",
    region="us-east-1",
    login_api_key="3_etlYkCXNEhz4_KJVYDqnK1CqxQjvJStJMawBohJU2ch3kp30b0QCJtLCzxJ93N-M",
    api_key="OgNqp2eAv84oZvMrXPIzP8mR8a6d9bVm1aaH9LqU",
    login_url="https://login-us.dodge.com",
    token_url="https://authz.sdpr-02.fcagcv.com/v2/cognito/identity/token",
    api_url="https://channels.sdpr-02.fcagcv.com",
    auth_api_key="JWRYW7IYhW9v0RqDghQSx4UcRYRILNmc8zAuh5ys",
    auth_url="https://mfa.fcl-01.fcagcv.com"
)

RAM_US = Brand(
    name="ram_us",
    region="us-east-1",
    login_api_key="3_7YjzjoSb7dYtCP5-D6FhPsCciggJFvM14hNPvXN9OsIiV1ujDqa4fNltDJYnHawO",
    api_key="OgNqp2eAv84oZvMrXPIzP8mR8a6d9bVm1aaH9LqU",
    login_url="https://login-us.ramtrucks.com",
    token_url="https://authz.sdpr-02.fcagcv.com/v2/cognito/identity/token",
    api_url="https://channels.sdpr-02.fcagcv.com",
    auth_api_key="JWRYW7IYhW9v0RqDghQSx4UcRYRILNmc8zAuh5ys",
    auth_url="https://mfa.fcl-01.fcagcv.com"
)
