import jwt
import uuid
import datetime
import json
import requests

from flask import current_app

from api.errors import StealthMoleError, AuthorizationError, ObserveError


class StealthMoleClient:
    def __init__(self, credentials):
        self.access_key = credentials["access_key"]
        self.secret_key = credentials["secret_key"]

    def __create_payload(self):
        """
        Creates a JSON web token payload.
        Used in create_header()
        """

        payload = {
            "access_key": self.access_key,
            "nonce": str(uuid.uuid4()),
            "iat": int(datetime.datetime.now(datetime.timezone.utc).timestamp()),
        }
        return payload

    def __create_header(self):
        """
        Creates a JSON web token header
        """

        jwt_token = jwt.encode(self.__create_payload(), self.secret_key)
        authorization_token = "Bearer {}".format(jwt_token)
        header = {"Authorization": authorization_token}
        return header

    def make_observe(self, observable):
        server_url = current_app.config["API_URL"]
        query_params = {"query": f"{observable["type"]}:{observable["value"]}"}
        try:
            res = requests.get(
                server_url, params=query_params, headers=self.__create_header()
            )
            json_res = json.loads(res.content)

            if res == 401:
                raise AuthorizationError(json_res["detail"])
            elif res != 200:
                raise ObserveError(json_res["detail"])
            return json_res["data"]

        except Exception as e:
            raise StealthMoleError(str(e))
