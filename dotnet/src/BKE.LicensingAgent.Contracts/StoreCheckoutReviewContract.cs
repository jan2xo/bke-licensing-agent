using System.Text.Json.Serialization;

namespace BKE.LicensingAgent.Contracts;

public sealed record StoreCheckoutReviewRequest(
    [property: JsonPropertyName("correlation_id")] string CorrelationId,
    [property: JsonPropertyName("purchase_plan_id")] string PurchasePlanId);

public sealed record StoreCheckoutReviewResponse(
    [property: JsonPropertyName("capability_id")] string CapabilityId,
    [property: JsonPropertyName("contract_version")] int ContractVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("purchase_modes")] IReadOnlyList<string> PurchaseModes,
    [property: JsonPropertyName("product"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] StoreCheckoutReviewProduct? Product,
    [property: JsonPropertyName("edition"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] StoreCheckoutReviewEdition? Edition,
    [property: JsonPropertyName("plan"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] StoreCatalogPlan? Plan,
    [property: JsonPropertyName("legal_documents")] IReadOnlyList<StoreCheckoutReviewLegalDocument> LegalDocuments,
    [property: JsonPropertyName("pending_legal")] IReadOnlyList<StoreCheckoutReviewPendingLegalDocument> PendingLegal,
    [property: JsonPropertyName("error"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] StoreCheckoutReviewError? Error);

public sealed record StoreCheckoutReviewProduct(
    [property: JsonPropertyName("product_id")] string ProductId,
    [property: JsonPropertyName("slug")] string Slug,
    [property: JsonPropertyName("display_name")] string DisplayName,
    [property: JsonPropertyName("summary")] string Summary);

public sealed record StoreCheckoutReviewEdition(
    [property: JsonPropertyName("edition_id")] string EditionId,
    [property: JsonPropertyName("slug")] string Slug,
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("max_users")] int MaxUsers,
    [property: JsonPropertyName("max_devices_per_user")] int MaxDevicesPerUser,
    [property: JsonPropertyName("update_policy")] string UpdatePolicy);

public sealed record StoreCheckoutReviewLegalDocument(
    [property: JsonPropertyName("document_type")] string DocumentType,
    [property: JsonPropertyName("title")] string Title,
    [property: JsonPropertyName("slug")] string Slug,
    [property: JsonPropertyName("document_version_id")] string DocumentVersionId,
    [property: JsonPropertyName("version")] string Version,
    [property: JsonPropertyName("sla_version"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? SlaVersion,
    [property: JsonPropertyName("requires_reacceptance")] bool RequiresReacceptance);

public sealed record StoreCheckoutReviewPendingLegalDocument(
    [property: JsonPropertyName("document_type")] string DocumentType,
    [property: JsonPropertyName("title")] string Title,
    [property: JsonPropertyName("slug")] string Slug,
    [property: JsonPropertyName("document_version_id")] string DocumentVersionId,
    [property: JsonPropertyName("version")] string Version);

public sealed record StoreCheckoutReviewError(
    [property: JsonPropertyName("code")] string Code,
    [property: JsonPropertyName("message")] string Message,
    [property: JsonPropertyName("retryable")] bool Retryable);
