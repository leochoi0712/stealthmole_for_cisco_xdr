import json


class Config:
    settings = json.load(open("container_settings.json", "r"))
    VERSION = settings["VERSION"]

    STEALTHMOLE_OBSERVABLE_TYPES = {"email": "Email", "domain": "Domain", "ip": "IP"}
    HEALTH_CHECKER_DOMAIN = "stealthmole.com"

    MODULE_TYPE = "cds"
    API_URL = f"https://api.stealthmole.com/v2/{MODULE_TYPE}/search"
