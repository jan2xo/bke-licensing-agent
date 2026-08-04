from ..api.errors import ApiError


class AuthenticationError(ApiError): pass
class InvalidCredentialsError(AuthenticationError): pass
class ExpiredSessionError(AuthenticationError): pass
class RevokedSessionError(AuthenticationError): pass
class RefreshFailedError(AuthenticationError): pass
class SecureStorageUnavailableError(AuthenticationError): pass
class CorruptedSecureStorageError(AuthenticationError): pass
class ConcurrentSessionError(AuthenticationError): pass
class MissingSessionError(AuthenticationError): pass
