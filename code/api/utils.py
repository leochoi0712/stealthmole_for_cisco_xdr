import jwt
import json
import requests
from requests.exceptions import ConnectionError, InvalidURL, SSLError
from jwt import InvalidSignatureError, DecodeError, InvalidAudienceError

from flask import request, jsonify, current_app, g

from api.errors import RelayError, AuthorizationError


NO_AUTH_HEADER = "Authorization header is missing"
WRONG_AUTH_TYPE = "Wrong authorization type"
WRONG_PAYLOAD_STRUCTURE = "Wrong JWT payload structure"
WRONG_JWT_STRUCTURE = "Wrong JWT structure"
WRONG_AUDIENCE = "Wrong configuration-token-audience"
KID_NOT_FOUND = "kid from JWT header not found in API response"
WRONG_KEY = (
    "Failed to decode JWT with provided key. "
    "Make sure domain in custom_jwks_host "
    "corresponds to your SecureX instance region."
)
JWKS_HOST_MISSING = (
    "jwks_host is missing in JWT payload. Make sure "
    "custom_jwks_host field is present in module_type"
)
WRONG_JWKS_HOST = (
    "Wrong jwks_host in JWT payload. Make sure domain follows "
    "the visibility.<region>.cisco.com structure"
)


def get_json(schema):
    data = request.get_json(force=True, silent=True, cache=False)

    error = schema.validate(data)

    if error:
        raise RelayError(
            code="invalid payload received",
            message=f"Invalid JSON payload received. {json.dumps(error)}.",
        )

    return data


def get_public_key(jwks_host, token):
    """
    Get public key by requesting it from specified jwks host.
    """

    expected_errors = {
        ConnectionError: WRONG_JWKS_HOST,
        InvalidURL: WRONG_JWKS_HOST,
        KeyError: WRONG_JWKS_HOST,
        SSLError: WRONG_JWKS_HOST,
        json.JSONDecodeError: WRONG_JWKS_HOST,
    }
    try:
        response = requests.get(f"https://{jwks_host}/.well-known/jwks")
        jwks = response.json()

        public_keys = {}
        for jwk in jwks["keys"]:
            kid = jwk["kid"]
            public_keys[kid] = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
        kid = jwt.get_unverified_header(token)["kid"]
        return public_keys.get(kid)
    except tuple(expected_errors) as error:
        message = expected_errors[error.__class__]
        raise AuthorizationError(message)


def get_auth_token():
    """
    Parse and validate incoming request Authorization header.
    """
    expected_errors = {KeyError: NO_AUTH_HEADER, AssertionError: WRONG_AUTH_TYPE}
    try:
        scheme, token = request.headers["Authorization"].split()
        assert scheme.lower() == "bearer"
        return token
    except tuple(expected_errors) as error:
        raise AuthorizationError(expected_errors[error.__class__])


def get_credentials():
    """
    Get Authorization token and validate its signature
    against the public key from /.well-known/jwks endpoint.
    """

    expected_errors = {
        KeyError: WRONG_PAYLOAD_STRUCTURE,
        AssertionError: JWKS_HOST_MISSING,
        InvalidSignatureError: WRONG_KEY,
        DecodeError: WRONG_JWT_STRUCTURE,
        InvalidAudienceError: WRONG_AUDIENCE,
        TypeError: KID_NOT_FOUND,
    }
    token = get_auth_token()
    try:
        jwks_host = jwt.decode(token, options={"verify_signature": False}).get(
            "jwks_host"
        )
        assert jwks_host
        key = get_public_key(jwks_host, token)
        aud = request.url_root
        payload = jwt.decode(
            token, key=key, algorithms=["RS256"], audience=[aud.rstrip("/")]
        )

        assert "acccess_key" in payload
        assert "secret_key" in payload

        return payload
    except tuple(expected_errors) as error:
        message = expected_errors[error.__class__]
        raise AuthorizationError(message)


def jsonify_data(data):
    return jsonify({"data": data})


def format_docs(docs):
    return {"count": len(docs), "docs": docs}


def jsonify_result():
    result = {"data": {}}

    if g.get("verdicts"):
        result["data"]["verdicts"] = format_docs(g.verdicts)

    if g.get("errors"):
        result["errors"] = g.errors

        if not result.get("data"):
            result.pop("data", None)

    return jsonify(result)
