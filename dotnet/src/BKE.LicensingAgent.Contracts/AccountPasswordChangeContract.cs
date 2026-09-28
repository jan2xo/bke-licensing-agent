using System.Text.Json.Serialization;

namespace BKE.LicensingAgent.Contracts;

public sealed record AccountPasswordChangeRequest(
    [property: JsonPropertyName("correlation_id")] string CorrelationId,
    [property: JsonPropertyName("current_password")] string CurrentPassword,
    [property: JsonPropertyName("new_password")] string NewPassword);

public sealed record AccountPasswordChangeResponse(
    [property: JsonPropertyName("capability_id")] string CapabilityId,
    [property: JsonPropertyName("contract_version")] int ContractVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("reauthentication_required")] bool ReauthenticationRequired,
    [property: JsonPropertyName("error"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AccountPasswordChangeError? Error);

public sealed record AccountPasswordChangeError(
    [property: JsonPropertyName("code")] string Code,
    [property: JsonPropertyName("message")] string Message,
    [property: JsonPropertyName("retryable")] bool Retryable);
