from flask import Blueprint, current_app

from api.utils import get_credentials, jsonify_data
from api.client import StealthMoleClient


health_api = Blueprint("health", __name__)


@health_api.route("/health", methods=["POST"])
def health():
    credentials = get_credentials()
    client = StealthMoleClient(credentials)

    _ = client.make_observe(current_app.config["HEALTH_CHECKER_DOMAIN"])

    return jsonify_data({"status": "ok"})
