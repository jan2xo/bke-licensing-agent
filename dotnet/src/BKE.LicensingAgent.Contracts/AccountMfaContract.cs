using System.Text.Json.Serialization;

namespace BKE.LicensingAgent.Contracts;

public sealed record AccountMfaStatusRequest(
    [property: JsonPropertyName("correlation_id")] string CorrelationId);

public sealed record AccountMfaStatusResponse(
    [property: JsonPropertyName("capability_id")] string CapabilityId,
    [property: JsonPropertyName("contract_version")] int ContractVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("enabled")] bool Enabled,
    [property: JsonPropertyName("enrollment_pending")] bool EnrollmentPending,
    [property: JsonPropertyName("recovery_codes_remaining")] int RecoveryCodesRemaining,
    [property: JsonPropertyName("error"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AccountMfaError? Error);

public sealed record AccountMfaEnrollStartRequest(
    [property: JsonPropertyName("correlation_id")] string CorrelationId,
    [property: JsonPropertyName("current_password")] string CurrentPassword);

public sealed record AccountMfaChallengeResponse(
    [property: JsonPropertyName("capability_id")] string CapabilityId,
    [property: JsonPropertyName("contract_version")] int ContractVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("challenge_token"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? ChallengeToken,
    [property: JsonPropertyName("expires_at"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? ExpiresAt,
    [property: JsonPropertyName("email_sent")] bool EmailSent,
    [property: JsonPropertyName("mfa_reference"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? MfaReference,
    [property: JsonPropertyName("error"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AccountMfaError? Error);

public sealed record AccountMfaEnrollCompleteRequest(
    [property: JsonPropertyName("correlation_id")] string CorrelationId,
    [property: JsonPropertyName("current_password")] string CurrentPassword,
    [property: JsonPropertyName("challenge_token")] string ChallengeToken,
    [property: JsonPropertyName("code")] string Code);

public sealed record AccountMfaProofChallengeRequest(
    [property: JsonPropertyName("correlation_id")] string CorrelationId,
    [property: JsonPropertyName("current_password")] string CurrentPassword);

public sealed record AccountMfaMutationRequest(
    [property: JsonPropertyName("correlation_id")] string CorrelationId,
    [property: JsonPropertyName("current_password")] string CurrentPassword,
    [property: JsonPropertyName("challenge_token")] string ChallengeToken,
    [property: JsonPropertyName("code")] string Code);

public sealed record AccountMfaMutationResponse(
    [property: JsonPropertyName("capability_id")] string CapabilityId,
    [property: JsonPropertyName("contract_version")] int ContractVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("reauthentication_required")] bool ReauthenticationRequired,
    [property: JsonPropertyName("enrollment_required"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] bool? EnrollmentRequired,
    [property: JsonPropertyName("recovery_codes"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] IReadOnlyList<string>? RecoveryCodes,
    [property: JsonPropertyName("error"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AccountMfaError? Error);

public sealed record AccountMfaError(
    [property: JsonPropertyName("code")] string Code,
    [property: JsonPropertyName("message")] string Message,
    [property: JsonPropertyName("retryable")] bool Retryable);
