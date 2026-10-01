using System.Text.Json.Serialization;

namespace BKE.LicensingAgent.Contracts;

public sealed record StoreTrialStartRequest(
    [property: JsonPropertyName("correlation_id")] string CorrelationId,
    [property: JsonPropertyName("edition_id")] string EditionId);

public sealed record StoreTrialStartResponse(
    [property: JsonPropertyName("capability_id")] string CapabilityId,
    [property: JsonPropertyName("contract_version")] int ContractVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("correlation_id")] string CorrelationId,
    [property: JsonPropertyName("trial_ends_at"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? TrialEndsAt,
    [property: JsonPropertyName("grace_ends_at"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? GraceEndsAt,
    [property: JsonPropertyName("error"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] StoreTrialStartError? Error);

public sealed record StoreTrialStartError(
    [property: JsonPropertyName("code")] string Code,
    [property: JsonPropertyName("message")] string Message,
    [property: JsonPropertyName("retryable")] bool Retryable);
