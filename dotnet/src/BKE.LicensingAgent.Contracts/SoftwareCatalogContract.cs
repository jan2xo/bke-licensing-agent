using System.Text.Json.Serialization;

namespace BKE.LicensingAgent.Contracts;

public sealed record SoftwareCatalogRequest(
    [property: JsonPropertyName("correlation_id")] string CorrelationId);

public sealed record SoftwareCatalogResponse(
    [property: JsonPropertyName("capability_id")] string CapabilityId,
    [property: JsonPropertyName("contract_version")] int ContractVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("items")] IReadOnlyList<SoftwareCatalogItem> Items,
    [property: JsonPropertyName("error"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] SoftwareCatalogError? Error);

public sealed record SoftwareCatalogItem(
    [property: JsonPropertyName("product_id")] string ProductId,
    [property: JsonPropertyName("display_name")] string DisplayName,
    [property: JsonPropertyName("summary")] string Summary,
    [property: JsonPropertyName("execution_type"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? ExecutionType,
    [property: JsonPropertyName("entitled")] bool Entitled,
    [property: JsonPropertyName("installable")] bool Installable,
    [property: JsonPropertyName("state")] string State,
    [property: JsonPropertyName("latest_version"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? LatestVersion,
    [property: JsonPropertyName("installed_version"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? InstalledVersion);

public sealed record SoftwareCatalogError(
    [property: JsonPropertyName("code")] string Code,
    [property: JsonPropertyName("message")] string Message,
    [property: JsonPropertyName("retryable")] bool Retryable);
