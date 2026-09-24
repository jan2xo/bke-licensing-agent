using System.Text.Json.Serialization;

namespace BKE.LicensingAgent.Contracts;

public sealed record StoreCheckoutStartRequest(
    [property: JsonPropertyName("correlation_id")] string CorrelationId,
    [property: JsonPropertyName("purchase_plan_id")] string PurchasePlanId,
    [property: JsonPropertyName("purchase_mode")] string PurchaseMode,
    [property: JsonPropertyName("legal_version_ids")] IReadOnlyList<string> LegalVersionIds);

public sealed record StoreCheckoutStartResponse(
    [property: JsonPropertyName("capability_id")] string CapabilityId,
    [property: JsonPropertyName("contract_version")] int ContractVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("correlation_id")] string CorrelationId,
    [property: JsonPropertyName("order_id"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? OrderId,
    [property: JsonPropertyName("checkout_url"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? CheckoutUrl,
    [property: JsonPropertyName("complimentary"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] bool? Complimentary,
    [property: JsonPropertyName("error"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] StoreCheckoutStartError? Error);

public sealed record StoreCheckoutStartError(
    [property: JsonPropertyName("code")] string Code,
    [property: JsonPropertyName("message")] string Message,
    [property: JsonPropertyName("retryable")] bool Retryable);
