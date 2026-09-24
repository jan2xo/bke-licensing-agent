using System.Text.Json.Serialization;

namespace BKE.LicensingAgent.Contracts;

public sealed record StoreCatalogRequest(
    [property: JsonPropertyName("correlation_id")] string CorrelationId);

public sealed record StoreCatalogResponse(
    [property: JsonPropertyName("capability_id")] string CapabilityId,
    [property: JsonPropertyName("contract_version")] int ContractVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("gift_checkout_enabled")] bool GiftCheckoutEnabled,
    [property: JsonPropertyName("products")] IReadOnlyList<StoreCatalogProduct> Products,
    [property: JsonPropertyName("error"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] StoreCatalogError? Error);

public sealed record StoreCatalogProduct(
    [property: JsonPropertyName("product_id")] string ProductId,
    [property: JsonPropertyName("slug")] string Slug,
    [property: JsonPropertyName("display_name")] string DisplayName,
    [property: JsonPropertyName("summary")] string Summary,
    [property: JsonPropertyName("description")] string Description,
    [property: JsonPropertyName("product_type")] string ProductType,
    [property: JsonPropertyName("execution_type"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? ExecutionType,
    [property: JsonPropertyName("editions")] IReadOnlyList<StoreCatalogEdition> Editions);

public sealed record StoreCatalogEdition(
    [property: JsonPropertyName("edition_id")] string EditionId,
    [property: JsonPropertyName("slug")] string Slug,
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("description"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Description,
    [property: JsonPropertyName("features")] IReadOnlyList<string> Features,
    [property: JsonPropertyName("max_users")] int MaxUsers,
    [property: JsonPropertyName("max_devices_per_user")] int MaxDevicesPerUser,
    [property: JsonPropertyName("update_policy")] string UpdatePolicy,
    [property: JsonPropertyName("plans")] IReadOnlyList<StoreCatalogPlan> Plans);

public sealed record StoreCatalogPlan(
    [property: JsonPropertyName("purchase_plan_id")] string PurchasePlanId,
    [property: JsonPropertyName("type")] string Type,
    [property: JsonPropertyName("currency")] string Currency,
    [property: JsonPropertyName("amount_minor")] long AmountMinor,
    [property: JsonPropertyName("billing_type")] string BillingType,
    [property: JsonPropertyName("interval_unit"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? IntervalUnit,
    [property: JsonPropertyName("interval_count"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] int? IntervalCount,
    [property: JsonPropertyName("renewal_behavior")] string RenewalBehavior,
    [property: JsonPropertyName("savings_minor")] long SavingsMinor,
    [property: JsonPropertyName("effective_monthly_minor"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] long? EffectiveMonthlyMinor);

public sealed record StoreCatalogError(
    [property: JsonPropertyName("code")] string Code,
    [property: JsonPropertyName("message")] string Message,
    [property: JsonPropertyName("retryable")] bool Retryable);
