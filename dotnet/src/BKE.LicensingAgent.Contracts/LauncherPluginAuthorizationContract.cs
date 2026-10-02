using System.Text.Json.Serialization;

namespace BKE.LicensingAgent.Contracts;

public sealed record LauncherPluginAuthorizeRequest(
    [property: JsonPropertyName("correlation_id")] string CorrelationId,
    [property: JsonPropertyName("product_id")] string ProductId,
    [property: JsonPropertyName("version")] string Version);

public sealed record LauncherPluginAuthorizeResponse(
    [property: JsonPropertyName("capability_id")] string CapabilityId,
    [property: JsonPropertyName("contract_version")] int ContractVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("authorized")] bool Authorized,
    [property: JsonPropertyName("reason")] string Reason,
    [property: JsonPropertyName("error"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] LauncherPluginAuthorizeError? Error);

public sealed record LauncherPluginAuthorizeError(
    [property: JsonPropertyName("code")] string Code,
    [property: JsonPropertyName("message")] string Message,
    [property: JsonPropertyName("retryable")] bool Retryable);
