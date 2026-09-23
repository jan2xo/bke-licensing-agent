using System.Text.Json.Serialization;

namespace BKE.LicensingAgent.Contracts;

public sealed record SoftwareUpdateRequest(
    [property: JsonPropertyName("correlation_id")] string CorrelationId,
    [property: JsonPropertyName("product_id")] string ProductId);

public sealed record SoftwareUpdateResponse(
    [property: JsonPropertyName("capability_id")] string CapabilityId,
    [property: JsonPropertyName("contract_version")] int ContractVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("state")] string State,
    [property: JsonPropertyName("error"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] SoftwareUpdateError? Error);

public sealed record SoftwareUpdateError(
    [property: JsonPropertyName("code")] string Code,
    [property: JsonPropertyName("message")] string Message,
    [property: JsonPropertyName("retryable")] bool Retryable);
