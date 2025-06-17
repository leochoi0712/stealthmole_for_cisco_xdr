import base64
from datetime import datetime, timezone
import json

from flask import request, jsonify

from api.errors import RelayError, AuthorizationError


NO_AUTH_HEADER = "Authorization header is missing"
WRONG_AUTH_TYPE = "Wrong authorization type"


def get_json(schema):
    data = request.get_json(force=True, silent=True, cache=False)
    error = schema.validate(data)
    if error:
        raise RelayError(
            code="invalid payload received",
            message=f"Invalid JSON payload received. {json.dumps(error)}.",
        )

    return data


def get_auth_token():
    """
    Parse and validate incoming request Authorization header.
    """
    expected_errors = {KeyError: NO_AUTH_HEADER, AssertionError: WRONG_AUTH_TYPE}
    try:
        scheme, token = request.headers["Authorization"].split()
        scheme = scheme.lower()
        assert scheme == "basic"
        return token
    except tuple(expected_errors) as error:
        raise AuthorizationError(expected_errors[error.__class__])


def get_credentials():
    """
    Get Authorization token
    """
    token = get_auth_token()
    try:
        decoded_str = base64.b64decode(token).decode("utf-8")
        decoded_list = decoded_str.split(":")
        credentials = {"access_key": decoded_list[0], "secret_key": decoded_list[1]}
        return credentials
    except Exception as error:
        raise AuthorizationError(error)


def jsonify_data(data):
    return jsonify({"data": data})


def format_docs(docs):
    return {"count": len(docs), "docs": docs}


def unix_to_iso8601(timestamp: int) -> str:
    return (
        datetime.fromtimestamp(timestamp, tz=timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )
