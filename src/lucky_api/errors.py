class LuckyError(Exception):
    """Base exception for the Lucky API package."""


class LuckyConfigError(LuckyError):
    """Raised when the client configuration cannot be loaded or validated."""


class LuckyAuthenticationError(LuckyError):
    """Raised when Lucky authentication fails."""


class LuckyAPIError(LuckyError):
    """Raised when communication with the Lucky API fails."""


class LuckyResponseError(LuckyAPIError):
    """Raised when Lucky returns an invalid response shape."""
