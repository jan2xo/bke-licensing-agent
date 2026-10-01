using System.Text.Json.Serialization;

namespace BKE.LicensingAgent.Contracts;

public sealed record AccountRecentAuthStartRequest(
    [property: JsonPropertyName("correlation_id")] string CorrelationId,
    [property: JsonPropertyName("current_password")] string CurrentPassword);

public sealed record AccountRecentAuthCompleteRequest(
    [property: JsonPropertyName("correlation_id")] string CorrelationId,
    [property: JsonPropertyName("challenge_token")] string ChallengeToken,
    [property: JsonPropertyName("code")] string Code);

public sealed record AccountRecentAuthResponse(
    [property: JsonPropertyName("capability_id")] string CapabilityId,
    [property: JsonPropertyName("contract_version")] int ContractVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("correlation_id")] string CorrelationId,
    [property: JsonPropertyName("recent_authenticated_until"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? RecentAuthenticatedUntil,
    [property: JsonPropertyName("challenge_token"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? ChallengeToken,
    [property: JsonPropertyName("expires_at"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? ExpiresAt,
    [property: JsonPropertyName("email_sent"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] bool? EmailSent,
    [property: JsonPropertyName("mfa_reference"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? MfaReference,
    [property: JsonPropertyName("error"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AccountRecentAuthError? Error);

public sealed record AccountRecentAuthError(
    [property: JsonPropertyName("code")] string Code,
    [property: JsonPropertyName("message")] string Message,
    [property: JsonPropertyName("retryable")] bool Retryable);
