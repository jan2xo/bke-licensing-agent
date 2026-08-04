class ApiError(Exception):
    """Base error with a safe, user-facing message."""


class NetworkUnavailableError(ApiError): pass
class ConnectionTimeoutError(NetworkUnavailableError): pass
class RequestTimeoutError(NetworkUnavailableError): pass
class TlsFailureError(NetworkUnavailableError): pass
class InvalidServerResponseError(ApiError): pass
class AuthenticationRequiredError(ApiError): pass
class AuthenticationExpiredError(ApiError): pass
class AuthorizationDeniedError(ApiError): pass
class ResourceNotFoundError(ApiError): pass
class ConflictError(ApiError): pass
class RateLimitExceededError(ApiError): pass
class ServerUnavailableError(ApiError): pass
class UnsupportedClientVersionError(ApiError): pass
class UnknownApiError(ApiError): pass
