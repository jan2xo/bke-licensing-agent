using System.Text.Json.Serialization;

namespace BKE.LicensingAgent.Contracts;

public sealed record StoreGiftClaimRevealRequest(
    [property: JsonPropertyName("correlation_id")] string CorrelationId);

public sealed record StoreGiftClaimRevealResponse(
    [property: JsonPropertyName("capability_id")] string CapabilityId,
    [property: JsonPropertyName("contract_version")] int ContractVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("correlation_id")] string CorrelationId,
    [property: JsonPropertyName("order_id"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? OrderId,
    [property: JsonPropertyName("claim_code_id"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? ClaimCodeId,
    [property: JsonPropertyName("claim_code"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? ClaimCode,
    [property: JsonPropertyName("error"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] StoreGiftClaimRevealError? Error);

public sealed record StoreGiftClaimRevealError(
    [property: JsonPropertyName("code")] string Code,
    [property: JsonPropertyName("message")] string Message,
    [property: JsonPropertyName("retryable")] bool Retryable);
