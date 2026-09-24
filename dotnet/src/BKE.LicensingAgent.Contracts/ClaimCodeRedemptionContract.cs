using System.Text.Json.Serialization;

namespace BKE.LicensingAgent.Contracts;

public sealed record ClaimCodeRedeemRequest(
    [property: JsonPropertyName("correlation_id")] string CorrelationId,
    [property: JsonPropertyName("code")] string Code);

public sealed record ClaimCodeRedeemResponse(
    [property: JsonPropertyName("capability_id")] string CapabilityId,
    [property: JsonPropertyName("contract_version")] int ContractVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("account_id"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? AccountId,
    [property: JsonPropertyName("entitlement_id"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? EntitlementId,
    [property: JsonPropertyName("error"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] ClaimCodeRedeemError? Error);

public sealed record ClaimCodeRedeemError(
    [property: JsonPropertyName("code")] string Code,
    [property: JsonPropertyName("message")] string Message,
    [property: JsonPropertyName("retryable")] bool Retryable);
