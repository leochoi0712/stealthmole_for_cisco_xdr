import traceback

from flask import Flask, jsonify

from api.enrich import enrich_api
from api.health import health_api
from api.watchdog import watchdog_api
from api.version import version_api
from api.errors import RelayError


app = Flask(__name__)

app.url_map.strict_slashes = False
app.config.from_object("config.Config")

app.register_blueprint(health_api)
app.register_blueprint(enrich_api)
app.register_blueprint(version_api)
app.register_blueprint(watchdog_api)


@app.errorhandler(Exception)
def handle_error(exception):
    code = getattr(exception, "code", 500)
    message = getattr(exception, "description", "Something went wrong.")
    reason = ".".join(
        [
            exception.__class__.__module__,
            exception.__class__.__name__,
        ]
    )

    if code != 404:
        app.logger.error(traceback.format_exc())

    response = jsonify(code=code, message=message, reason=reason)
    return response, code


@app.errorhandler(RelayError)
def handle_relay_error(error):
    app.logger.error(traceback.format_exc())
    return {"errors": [error.json]}


if __name__ == "__main__":
    app.run()
