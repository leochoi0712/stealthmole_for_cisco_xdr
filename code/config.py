import json
from uuid import NAMESPACE_X500


class Config:
    settings = json.load(open("module_settings.json", "r"))
    VERSION = settings["VERSION"]

    NAMESPACE_BASE = NAMESPACE_X500

    STEALTHMOLE_MODULE_TYPES = {
        "cds": {
            "name": "Compromised Dataset (CDS)",
            "source": "Infosteatler Malwares",
            "confidence": "High",
            "observable_type": {"email", "domain", "ip", "url"},
        },
        "ub": {
            "name": "ULP Binder (UB)",
            "source": "URL:LOGIN:PASS Log",
            "confidence": "High",
            "observable_type": {"url", "domain", "email"},
        },
        "cl": {
            "name": "Credential Lookout (CL)",
            "source": "Breached Servers",
            "confidence": "Medium",
            "observable_type": {"email", "domain"},
        },
        "cb": {
            "name": "Combo Binder (CB)",
            "source": "Combo Lists",
            "confidence": "Low",
            "observable_type": {"email", "domain"},
        },
    }
    API_SEARCH_URL = f"https://api.stealthmole.com/v2/module_type/search"
    API_AUTH_URL = f"https://api.stealthmole.com/v2/user/quotas"
