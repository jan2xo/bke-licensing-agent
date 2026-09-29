using System.Text.Json.Serialization;

namespace BKE.LicensingAgent.Contracts;

public sealed record AccountPrivacyListRequest(
    [property: JsonPropertyName("correlation_id")] string CorrelationId,
    [property: JsonPropertyName("limit")] int Limit);

public sealed record AccountPrivacyItem(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("scope")] string Scope,
    [property: JsonPropertyName("request_type")] string RequestType,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("summary")] string Summary,
    [property: JsonPropertyName("response_summary"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? ResponseSummary,
    [property: JsonPropertyName("reviewed_at"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? ReviewedAt,
    [property: JsonPropertyName("closed_at"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? ClosedAt,
    [property: JsonPropertyName("created_at")] string CreatedAt);

public sealed record AccountPrivacyListResponse(
    [property: JsonPropertyName("capability_id")] string CapabilityId,
    [property: JsonPropertyName("contract_version")] int ContractVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("request_types")] IReadOnlyList<string> RequestTypes,
    [property: JsonPropertyName("items")] IReadOnlyList<AccountPrivacyItem> Items,
    [property: JsonPropertyName("error"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AccountPrivacyError? Error);

public sealed record AccountPrivacyCreateRequest(
    [property: JsonPropertyName("correlation_id")] string CorrelationId,
    [property: JsonPropertyName("request_type")] string RequestType,
    [property: JsonPropertyName("summary")] string Summary);

public sealed record AccountPrivacyCreateResponse(
    [property: JsonPropertyName("capability_id")] string CapabilityId,
    [property: JsonPropertyName("contract_version")] int ContractVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("request_id"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? RequestId,
    [property: JsonPropertyName("request_type"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? RequestType,
    [property: JsonPropertyName("request_status"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? RequestStatus,
    [property: JsonPropertyName("error"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AccountPrivacyError? Error);

public sealed record AccountPrivacyError(
    [property: JsonPropertyName("code")] string Code,
    [property: JsonPropertyName("message")] string Message,
    [property: JsonPropertyName("retryable")] bool Retryable);
