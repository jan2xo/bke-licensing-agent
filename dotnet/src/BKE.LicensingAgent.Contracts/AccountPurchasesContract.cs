using System.Text.Json.Serialization;

namespace BKE.LicensingAgent.Contracts;

public sealed record AccountPurchasesRequest(
    [property: JsonPropertyName("correlation_id")] string CorrelationId);

public sealed record AccountPurchasesAccount(
    [property: JsonPropertyName("type")] string Type,
    [property: JsonPropertyName("display_name")] string DisplayName,
    [property: JsonPropertyName("lifecycle_state")] string LifecycleState,
    [property: JsonPropertyName("role")] string Role);

public sealed record AccountPurchasesPermissions(
    [property: JsonPropertyName("view_orders")] bool ViewOrders,
    [property: JsonPropertyName("view_subscriptions")] bool ViewSubscriptions,
    [property: JsonPropertyName("view_all_licenses")] bool ViewAllLicenses);

public sealed record AccountPurchasesLicense(
    [property: JsonPropertyName("product_name")] string ProductName,
    [property: JsonPropertyName("edition_name"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? EditionName,
    [property: JsonPropertyName("plan_type"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? PlanType,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("key_last_four")] string KeyLastFour,
    [property: JsonPropertyName("expires_at"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? ExpiresAt,
    [property: JsonPropertyName("max_devices")] int MaxDevices,
    [property: JsonPropertyName("active_devices")] int ActiveDevices);

public sealed record AccountPurchasesSubscription(
    [property: JsonPropertyName("product_name")] string ProductName,
    [property: JsonPropertyName("edition_name"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? EditionName,
    [property: JsonPropertyName("plan_type"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? PlanType,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("seats")] int Seats,
    [property: JsonPropertyName("current_period_end")] string CurrentPeriodEnd);

public sealed record AccountPurchasesOrderItem(
    [property: JsonPropertyName("product_name")] string ProductName,
    [property: JsonPropertyName("edition_name"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? EditionName,
    [property: JsonPropertyName("plan_name"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? PlanName);

public sealed record AccountPurchasesOrder(
    [property: JsonPropertyName("number")] string Number,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("total_minor")] int TotalMinor,
    [property: JsonPropertyName("currency")] string Currency,
    [property: JsonPropertyName("created_at")] string CreatedAt,
    [property: JsonPropertyName("invoice_available")] bool InvoiceAvailable,
    [property: JsonPropertyName("items")] IReadOnlyList<AccountPurchasesOrderItem> Items);

public sealed record AccountPurchasesResponse(
    [property: JsonPropertyName("capability_id")] string CapabilityId,
    [property: JsonPropertyName("contract_version")] int ContractVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("account"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AccountPurchasesAccount? Account,
    [property: JsonPropertyName("permissions"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AccountPurchasesPermissions? Permissions,
    [property: JsonPropertyName("licenses")] IReadOnlyList<AccountPurchasesLicense> Licenses,
    [property: JsonPropertyName("subscriptions")] IReadOnlyList<AccountPurchasesSubscription> Subscriptions,
    [property: JsonPropertyName("orders")] IReadOnlyList<AccountPurchasesOrder> Orders,
    [property: JsonPropertyName("error"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AccountPurchasesError? Error);

public sealed record AccountPurchasesError(
    [property: JsonPropertyName("code")] string Code,
    [property: JsonPropertyName("message")] string Message,
    [property: JsonPropertyName("retryable")] bool Retryable);
