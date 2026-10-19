from datetime import UTC, datetime

import pytest

from py_uconnect.sigv4 import AWSCredentials, sign

# Vectors from the AWS Signature Version 4 test suite
NOW = datetime(2015, 8, 30, 12, 36, tzinfo=UTC)
CREDS = AWSCredentials("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")
SCOPE = "AKIDEXAMPLE/20150830/us-east-1/service/aws4_request"


@pytest.mark.parametrize(
    ("method", "url", "signature"),
    [
        (
            "GET",
            "https://example.amazonaws.com/",
            "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
        ),
        (
            "GET",
            "https://example.amazonaws.com/?Param2=value2&Param1=value1",
            "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500",
        ),
        (
            "POST",
            "https://example.amazonaws.com/",
            "5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b",
        ),
    ],
)
def test_aws_test_suite(method: str, url: str, signature: str) -> None:
    headers = sign(method, url, {}, b"", CREDS, "us-east-1", "service", NOW)

    assert headers == {
        "X-Amz-Date": "20150830T123600Z",
        "Authorization": f"AWS4-HMAC-SHA256 Credential={SCOPE}, "
        f"SignedHeaders=host;x-amz-date, Signature={signature}",
    }


def test_session_token_is_added_and_signed() -> None:
    creds = AWSCredentials(CREDS.access_key_id, CREDS.secret_access_key, "TOKEN123")
    headers = sign(
        "POST",
        "https://channels.sdpr-01.fcagcv.com/v1/accounts/abc/vehicles/VIN/remote/",
        # Headers other than x-amz-* are not signed
        {"Content-Type": "application/json", "x-api-key": "KEY"},
        b'{"command":"RDL","pinAuth":"x"}',
        creds,
        "us-east-1",
        "service",
        NOW,
    )

    # Cross-checked with botocore's SigV4Auth restricted to the same headers
    assert headers == {
        "X-Amz-Date": "20150830T123600Z",
        "X-Amz-Security-Token": "TOKEN123",
        "Authorization": f"AWS4-HMAC-SHA256 Credential={SCOPE}, "
        "SignedHeaders=host;x-amz-date;x-amz-security-token, "
        "Signature=93b6d15d66879e0b4ad52efc7a8d81ff54fa1e5dd353b1d47ba47f0b729aef2a",
    }


def test_signature_depends_on_body_and_query() -> None:
    url = "https://example.amazonaws.com/path"
    base = sign("POST", url, {}, b"a", CREDS, "us-east-1", "service", NOW)

    assert base != sign("POST", url, {}, b"b", CREDS, "us-east-1", "service", NOW)
    assert base != sign(
        "POST", url + "?x=1", {}, b"a", CREDS, "us-east-1", "service", NOW
    )


def test_query_is_canonicalized() -> None:
    a = sign(
        "GET",
        "https://example.amazonaws.com/?b=2&a=1",
        {},
        b"",
        CREDS,
        "us-east-1",
        "service",
        NOW,
    )
    b = sign(
        "GET",
        "https://example.amazonaws.com/?a=1&b=2",
        {},
        b"",
        CREDS,
        "us-east-1",
        "service",
        NOW,
    )

    assert a == b


def test_non_default_port_is_part_of_host() -> None:
    a = sign("GET", "https://example.com:8443/", {}, b"", CREDS, "r", "s", NOW)
    b = sign("GET", "https://example.com/", {}, b"", CREDS, "r", "s", NOW)

    assert a != b
