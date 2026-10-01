using System.Text.Json.Serialization;

namespace BKE.LicensingAgent.Contracts;

public sealed record StoreGiftClaimsRequest(
    [property: JsonPropertyName("correlation_id")] string CorrelationId);

public sealed record StoreGiftClaimItem(
    [property: JsonPropertyName("gift_claim_handle")] string GiftClaimHandle,
    [property: JsonPropertyName("order_number")] string OrderNumber,
    [property: JsonPropertyName("product_name")] string ProductName,
    [property: JsonPropertyName("edition_name")] string? EditionName,
    [property: JsonPropertyName("plan_name")] string? PlanName,
    [property: JsonPropertyName("last_four")] string LastFour,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("created_at")] string CreatedAt,
    [property: JsonPropertyName("expires_at")] string? ExpiresAt);

public sealed record StoreGiftClaimsResponse(
    [property: JsonPropertyName("capability_id")] string CapabilityId,
    [property: JsonPropertyName("contract_version")] int ContractVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("correlation_id")] string CorrelationId,
    [property: JsonPropertyName("account_lifecycle_state"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? AccountLifecycleState,
    [property: JsonPropertyName("claims")] IReadOnlyList<StoreGiftClaimItem> Claims,
    [property: JsonPropertyName("error"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] StoreGiftClaimsError? Error);

public sealed record StoreGiftClaimPersistentRevealRequest(
    [property: JsonPropertyName("correlation_id")] string CorrelationId,
    [property: JsonPropertyName("gift_claim_handle")] string GiftClaimHandle);

public sealed record StoreGiftClaimPersistentRevealResponse(
    [property: JsonPropertyName("capability_id")] string CapabilityId,
    [property: JsonPropertyName("contract_version")] int ContractVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("correlation_id")] string CorrelationId,
    [property: JsonPropertyName("gift_claim_handle"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? GiftClaimHandle,
    [property: JsonPropertyName("claim_code"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? ClaimCode,
    [property: JsonPropertyName("error"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] StoreGiftClaimsError? Error);

public sealed record StoreGiftClaimsError(
    [property: JsonPropertyName("code")] string Code,
    [property: JsonPropertyName("message")] string Message,
    [property: JsonPropertyName("retryable")] bool Retryable);
