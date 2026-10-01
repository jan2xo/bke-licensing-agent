using System.Text.Json.Serialization;

namespace BKE.LicensingAgent.Contracts;

public sealed record AccountPendingOrderContinueRequest(
    [property: JsonPropertyName("correlation_id")] string CorrelationId,
    [property: JsonPropertyName("order_continue_handle")] string OrderContinueHandle);

public sealed record AccountPendingOrderCancelRequest(
    [property: JsonPropertyName("correlation_id")] string CorrelationId,
    [property: JsonPropertyName("order_cancel_handle")] string OrderCancelHandle);

public sealed record AccountPendingOrderContinueResponse(
    [property: JsonPropertyName("capability_id")] string CapabilityId,
    [property: JsonPropertyName("contract_version")] int ContractVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("checkout_url"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? CheckoutUrl,
    [property: JsonPropertyName("error"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AccountPendingOrderError? Error);

public sealed record AccountPendingOrderCancelResponse(
    [property: JsonPropertyName("capability_id")] string CapabilityId,
    [property: JsonPropertyName("contract_version")] int ContractVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("error"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AccountPendingOrderError? Error);

public sealed record AccountPendingOrderError(
    [property: JsonPropertyName("code")] string Code,
    [property: JsonPropertyName("message")] string Message,
    [property: JsonPropertyName("retryable")] bool Retryable);
