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

    def make_authentication(self):
        res = requests.get(
            current_app.config["API_AUTH_URL"], headers=self.__create_header()
        )
        json_res = json.loads(res.content)
        if res.status_code == 401:
            raise AuthorizationError(json_res["detail"])

    def make_observe(self, module_type, observable):
        server_url = current_app.config["API_SEARCH_URL"].replace(
            "module_type", module_type
        )
        query_params = {
            "query": f"{observable['type']}:{observable['value']}",
            "order": "asc",
        }
        try:
            res = requests.get(
                server_url, params=query_params, headers=self.__create_header()
            )
            json_res = json.loads(res.content)

            if res.status_code != 200:
                raise ObserveError(
                    f"{module_type.upper()} Module: {json_res["detail"]}"
                )
            return json_res

        except Exception as e:
            raise StealthMoleError(str(e))
