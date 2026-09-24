using System.Text.Json.Serialization;

namespace BKE.LicensingAgent.Contracts;

public sealed record StoreCheckoutStatusRequest(
    [property: JsonPropertyName("correlation_id")] string CorrelationId);

public sealed record StoreCheckoutStatusResponse(
    [property: JsonPropertyName("capability_id")] string CapabilityId,
    [property: JsonPropertyName("contract_version")] int ContractVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("correlation_id")] string CorrelationId,
    [property: JsonPropertyName("order_id"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? OrderId,
    [property: JsonPropertyName("order_number"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? OrderNumber,
    [property: JsonPropertyName("order_status"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? OrderStatus,
    [property: JsonPropertyName("fulfillment_mode"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? FulfillmentMode,
    [property: JsonPropertyName("payment_status"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? PaymentStatus,
    [property: JsonPropertyName("checkout_url"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? CheckoutUrl,
    [property: JsonPropertyName("paid_at"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? PaidAt,
    [property: JsonPropertyName("error"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] StoreCheckoutStatusError? Error);

public sealed record StoreCheckoutStatusError(
    [property: JsonPropertyName("code")] string Code,
    [property: JsonPropertyName("message")] string Message,
    [property: JsonPropertyName("retryable")] bool Retryable);
