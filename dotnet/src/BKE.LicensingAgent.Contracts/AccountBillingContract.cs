using System.Text.Json.Serialization;

namespace BKE.LicensingAgent.Contracts;

public sealed record AccountBillingRequest(
    [property: JsonPropertyName("correlation_id")] string CorrelationId);

public sealed record AccountBillingAccount(
    [property: JsonPropertyName("type")] string Type,
    [property: JsonPropertyName("display_name")] string DisplayName,
    [property: JsonPropertyName("lifecycle_state")] string LifecycleState,
    [property: JsonPropertyName("role")] string Role);

public sealed record AccountBillingPermissions(
    [property: JsonPropertyName("view_invoices")] bool ViewInvoices,
    [property: JsonPropertyName("view_payments")] bool ViewPayments);

public sealed record AccountBillingInvoiceLine(
    [property: JsonPropertyName("description")] string Description,
    [property: JsonPropertyName("quantity")] int Quantity,
    [property: JsonPropertyName("unit_amount_minor")] int UnitAmountMinor,
    [property: JsonPropertyName("total_minor")] int TotalMinor);

public sealed record AccountBillingInvoice(
    [property: JsonPropertyName("number")] string Number,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("order_number")] string OrderNumber,
    [property: JsonPropertyName("currency")] string Currency,
    [property: JsonPropertyName("subtotal_minor")] int SubtotalMinor,
    [property: JsonPropertyName("tax_minor")] int TaxMinor,
    [property: JsonPropertyName("total_minor")] int TotalMinor,
    [property: JsonPropertyName("issued_at"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? IssuedAt,
    [property: JsonPropertyName("created_at")] string CreatedAt,
    [property: JsonPropertyName("lines")] IReadOnlyList<AccountBillingInvoiceLine> Lines);

public sealed record AccountBillingPayment(
    [property: JsonPropertyName("order_number")] string OrderNumber,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("amount_minor")] int AmountMinor,
    [property: JsonPropertyName("currency")] string Currency,
    [property: JsonPropertyName("paid_at"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? PaidAt,
    [property: JsonPropertyName("created_at")] string CreatedAt);

public sealed record AccountBillingResponse(
    [property: JsonPropertyName("capability_id")] string CapabilityId,
    [property: JsonPropertyName("contract_version")] int ContractVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("account"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AccountBillingAccount? Account,
    [property: JsonPropertyName("permissions"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AccountBillingPermissions? Permissions,
    [property: JsonPropertyName("invoices")] IReadOnlyList<AccountBillingInvoice> Invoices,
    [property: JsonPropertyName("payments")] IReadOnlyList<AccountBillingPayment> Payments,
    [property: JsonPropertyName("error"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AccountBillingError? Error);

public sealed record AccountBillingError(
    [property: JsonPropertyName("code")] string Code,
    [property: JsonPropertyName("message")] string Message,
    [property: JsonPropertyName("retryable")] bool Retryable);
