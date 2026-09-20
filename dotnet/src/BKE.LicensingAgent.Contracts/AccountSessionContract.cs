using System.Text.Json.Serialization;

namespace BKE.LicensingAgent.Contracts;

public sealed record AccountSessionStartRequest(
    [property: JsonPropertyName("correlation_id")] string CorrelationId);

public sealed record AccountSessionStartResponse(
    [property: JsonPropertyName("capability_id")] string CapabilityId,
    [property: JsonPropertyName("contract_version")] int ContractVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("verification_uri"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? VerificationUri,
    [property: JsonPropertyName("user_code"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? UserCode,
    [property: JsonPropertyName("expires_at"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? ExpiresAt,
    [property: JsonPropertyName("error"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AccountSessionError? Error);

public sealed record AccountSessionStatusRequest(
    [property: JsonPropertyName("correlation_id")] string CorrelationId);

public sealed record AccountSessionStatusResponse(
    [property: JsonPropertyName("capability_id")] string CapabilityId,
    [property: JsonPropertyName("contract_version")] int ContractVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("account"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AccountSessionAccount? Account,
    [property: JsonPropertyName("error"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AccountSessionError? Error);

public sealed record AccountSessionLogoutRequest(
    [property: JsonPropertyName("correlation_id")] string CorrelationId);

public sealed record AccountSessionLogoutResponse(
    [property: JsonPropertyName("capability_id")] string CapabilityId,
    [property: JsonPropertyName("contract_version")] int ContractVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("error"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AccountSessionError? Error);

public sealed record AccountSessionAccount(
    [property: JsonPropertyName("user_id")] string UserId,
    [property: JsonPropertyName("email")] string Email,
    [property: JsonPropertyName("account_id")] string AccountId,
    [property: JsonPropertyName("account_type")] string AccountType,
    [property: JsonPropertyName("display_name")] string DisplayName);

public sealed record AccountSessionError(
    [property: JsonPropertyName("code")] string Code,
    [property: JsonPropertyName("message")] string Message,
    [property: JsonPropertyName("retryable")] bool Retryable);

internal sealed record RemoteDeviceAuthorizationStartResponse(
    [property: JsonPropertyName("device_code")] string DeviceCode,
    [property: JsonPropertyName("user_code")] string UserCode,
    [property: JsonPropertyName("verification_uri")] string VerificationUri,
    [property: JsonPropertyName("expires_in")] int ExpiresIn,
    [property: JsonPropertyName("interval")] int Interval);

internal sealed record RemoteDeviceAuthorizationPollResponse(
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("access_token")] string? AccessToken,
    [property: JsonPropertyName("refresh_token")] string? RefreshToken,
    [property: JsonPropertyName("expires_in")] int? ExpiresIn,
    [property: JsonPropertyName("session_id")] string? SessionId,
    [property: JsonPropertyName("user_id")] string? UserId,
    [property: JsonPropertyName("email")] string? Email,
    [property: JsonPropertyName("account_id")] string? AccountId,
    [property: JsonPropertyName("account_type")] string? AccountType,
    [property: JsonPropertyName("account_display_name")] string? AccountDisplayName);
