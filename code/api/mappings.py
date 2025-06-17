from abc import ABC, abstractmethod
from uuid import uuid4, uuid5
from typing import Dict, Any

from flask import current_app

from api.utils import unix_to_iso8601


JSON = Dict[str, Any]


class Mapping(ABC):

    @classmethod
    @abstractmethod
    def map(cls, *args, **kwargs) -> JSON:
        pass


CTIM_DEFAULTS = {
    "schema_version": "1.1.3",
}


def transient_id(entity, base_value=None):
    # uuid = (
    #     uuid5(current_app.config["NAMESPACE_BASE"], base_value)
    #     if base_value
    #     else uuid4()
    # )
    uuid = uuid4()
    return f'transient:{entity["type"]}-{uuid}'


class Indicator(Mapping):
    DEFAULTS = {
        "type": "indicator",
        "producer": "StealthMole",
        "tlp": "red",
        "valid_time": {},
        "tags": ["darkweb", "leaked"],
        **CTIM_DEFAULTS,
    }

    @classmethod
    def map(cls, module, observable, data: JSON) -> JSON:
        indicator: JSON = cls.DEFAULTS.copy()

        indicator["confidence"] = module["confidence"]
        indicator["source"] = f"StealthMole {module["name"]}"
        indicator["title"] = (
            f"{data['totalCount']:,} Credentials leaked from {module["source"]}"
        )
        indicator["id"] = transient_id(indicator, observable["value"])

        return indicator


class Sighting(Mapping):
    DEFAULTS = {
        "count": 1,
        "type": "sighting",
        **CTIM_DEFAULTS,
    }

    @classmethod
    def map(cls, module, observable, data: JSON) -> JSON:
        sighting: JSON = cls.DEFAULTS.copy()

        sighting["confidence"] = module["confidence"]
        sighting["severity"] = module["confidence"]
        sighting["source"] = f"StealthMole {module["name"]}"

        if "CL" in module["name"]:
            leakeddate = "leaked_date"
        else:
            leakeddate = "leakeddate"

        if data["data"][0][leakeddate]:
            try:
                start_time = unix_to_iso8601(data["data"][0][leakeddate])
            except:
                start_time = "2016-01-01T00:00:00Z"
        else:
            start_time = unix_to_iso8601(data["data"][0]["regdate"])

        sighting["observed_time"] = {"start_time": start_time}
        sighting["observables"] = [observable]
        sighting["id"] = transient_id(sighting)

        return sighting


class Relationship(Mapping):
    DEFAULTS = {
        "type": "relationship",
        "relationship_type": "sighting-of",
        **CTIM_DEFAULTS,
    }

    @classmethod
    def map(cls, indicator: JSON, sighting: JSON) -> JSON:
        relationship: JSON = cls.DEFAULTS.copy()

        relationship["source_ref"] = sighting["id"]
        relationship["target_ref"] = indicator["id"]
        relationship["id"] = transient_id(relationship)

        return relationship
