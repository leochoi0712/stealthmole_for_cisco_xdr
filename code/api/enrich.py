from flask import Blueprint, current_app
from functools import partial

from api.mappings import Indicator, Relationship, Sighting
from api.schemas import ObservableSchema
from api.utils import get_json, get_credentials, jsonify_data
from api.client import StealthMoleClient
from api.bundle import Bundle


enrich_api = Blueprint("enrich", __name__)


get_observables = partial(get_json, schema=ObservableSchema(many=True))


def filter_observables(observables):
    filtered_list = []
    for obj in observables:
        obj["type"] = obj["type"].lower()
        if obj["type"] in current_app.config["STEALTHMOLE_OBSERVABLE_TYPES"]:
            if obj in filtered_list:
                continue
            filtered_list.append(obj)
    return filtered_list


@enrich_api.route("/observe/observables", methods=["POST"])
def observe_observables():
    credentials = get_credentials()
    observables = get_observables()

    bundle = Bundle()
    client = StealthMoleClient(credentials)

    for obj in observables:
        for module_code, module in current_app.config[
            "STEALTHMOLE_MODULE_TYPES"
        ].items():
            if obj["type"] in module["observable_type"]:
                result = client.make_observe(module_type=module_code, observable=obj)
                if result["totalCount"] == 0:
                    continue
                indicator = Indicator.map(module=module, observable=obj, data=result)
                sighting = Sighting.map(module=module, observable=obj, data=result)
                relationship = Relationship.map(indicator=indicator, sighting=sighting)

                bundle.add(indicator)
                bundle.add(sighting)
                bundle.add(relationship)

    data = bundle.json()
    return jsonify_data(data)


@enrich_api.route("/refer/observables", methods=["POST"])
def refer_observables():
    return {
        "data": [
            {
                "id": "ref-stealthmole-search",
                "title": "Search for this observable",
                "description": "Search this observable in StealthMole",
                "categories": ["StealthMole", "Search"],
                "url": "https://platform.stealthmole.com/",
            }
        ]
    }
