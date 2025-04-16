class RelayError(Exception):
    def __init__(self, code, message, type_="fatal"):
        self.code = code or "Unknown"
        self.message = message or "Something went wrong."
        self.type_ = type_
        super().__init__(message)

    @property
    def json(self):
        return {"type": self.type_, "code": self.code, "message": self.message}


class AuthorizationError(RelayError):
    def __init__(self, message):
        super().__init__(
            code="authorization error", message=f"Authorization failed: {message}"
        )


class WatchdogError(RelayError):
    def __init__(self):
        super().__init__(code="health check failed", message="Invalid Health Check")


class StealthMoleError(RelayError):
    def __init__(self, message):
        super().__init__(code="stealthmole error", message=message)


class ObserveError(RelayError):
    def __init__(self, message):
        super().__init__(code="observe error", message=message)
