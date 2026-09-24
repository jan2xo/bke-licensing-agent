using System.Text.Json.Serialization;

namespace BKE.LicensingAgent.Contracts;

public static class LocalAgentContract
{
    public const string ContractId = "bke.licensing-agent.local-api";
    public const int ContractVersion = 1;
    public const string BindHost = "127.0.0.1";
    public const int DefaultPort = 43873;
    public const long MaxJsonBodyBytes = 32_768;
    public const int MaxChunkLineBytes = 8_192;
    public const int StorageSchemaVersion = 10;

    public const string LicenseCenterBrowserPath = "/license-center";
    public const string AuthorizePath = "/v1/authorize";
    public const string ActivatePath = "/v1/activate";
    public const string OpenLicenseCenterPath = "/v1/license-center/open";
    public const string RequestNotificationPath = "/v1/notifications/request";
    public const string NotificationFeedPath = "/v1/notifications/feed";
    public const string NotificationMarkReadPath = "/v1/notifications/mark-read";
    public const string NotificationDismissPath = "/v1/notifications/dismiss";
    public const string NotificationUnreadCountPath = "/v1/notifications/unread-count";
    public const string CheckUpdatesPath = "/v1/updates/check";
    public const string OpenUpdateCenterPath = "/v1/update-center/open";
    public const string AccountSessionDeviceContextPath = "/v1/account-session/device-context";
    public const string AccountSessionCompletePath = "/v1/account-session/complete";
    public const string AccountSessionStartPath = "/v1/account-session/start";
    public const string AccountSessionStatusPath = "/v1/account-session/status";
    public const string AccountSessionLogoutPath = "/v1/account-session/logout";
    public const string SoftwareCatalogPath = "/v1/software/catalog";
    public const string SoftwareInstallPath = "/v1/software/install";
    public const string SoftwareUpdatePath = "/v1/software/update";
    public const string SoftwareRepairPath = "/v1/software/repair";
    public const string SoftwareOpenPath = "/v1/software/open";
    public const string SoftwareRemovePath = "/v1/software/remove";
    public const string ClaimCodeRedeemPath = "/v1/claims/redeem";
    public const string StoreCatalogPath = "/v1/store/catalog";
    public const string StoreCheckoutReviewPath = "/v1/store/checkout-review";
    public const string StoreCheckoutStartPath = "/v1/store/checkout-start";

    public const string UpdateCapabilityId = "bke.updates.check";
    public const int UpdateContractVersion = 1;
    public const string TypedNotificationCapabilityId = "bke.notifications.typed";
    public const int TypedNotificationContractVersion = 1;
    public const string NotificationInboxCapabilityId = "bke.notifications";
    public const int NotificationInboxContractVersion = 1;
    public const string AccountSessionCapabilityId = "bke.account-session";
    public const int AccountSessionContractVersion = 1;
    public const string SoftwareCatalogCapabilityId = "bke.software-catalog";
    public const int SoftwareCatalogContractVersion = 1;
    public const string SoftwareInstallCapabilityId = "bke.software-install";
    public const int SoftwareInstallContractVersion = 1;
    public const string SoftwareUpdateCapabilityId = "bke.software-update";
    public const int SoftwareUpdateContractVersion = 1;
    public const string SoftwareRepairCapabilityId = "bke.software-repair";
    public const int SoftwareRepairContractVersion = 1;
    public const string SoftwareOpenCapabilityId = "bke.software-open";
    public const int SoftwareOpenContractVersion = 1;
    public const string SoftwareRemoveCapabilityId = "bke.software-remove";
    public const int SoftwareRemoveContractVersion = 1;
    public const string ClaimCodeRedemptionCapabilityId = "bke.claim-code-redemption";
    public const int ClaimCodeRedemptionContractVersion = 1;
    public const string StoreCatalogCapabilityId = "bke.store-catalog";
    public const int StoreCatalogContractVersion = 1;
    public const string StoreCheckoutReviewCapabilityId = "bke.store-checkout-review";
    public const int StoreCheckoutReviewContractVersion = 1;
    public const string StoreCheckoutStartCapabilityId = "bke.store-checkout-start";
    public const int StoreCheckoutStartContractVersion = 1;
}

public sealed record AuthorizeRequest(
    [property: JsonPropertyName("product_id")] string ProductId,
    [property: JsonPropertyName("version")] string Version,
    [property: JsonPropertyName("installation_id")] string InstallationId);

public sealed record AuthorizationResponse(
    [property: JsonPropertyName("authorized")] bool Authorized,
    [property: JsonPropertyName("reason")] string Reason,
    [property: JsonPropertyName("license_center_url"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? LicenseCenterUrl = null);

public sealed record ActivateRequest(
    [property: JsonPropertyName("product_id")] string ProductId,
    [property: JsonPropertyName("version")] string Version,
    [property: JsonPropertyName("installation_id")] string InstallationId,
    [property: JsonPropertyName("license_key")] string LicenseKey);

public sealed record OpenLicenseCenterRequest(
    [property: JsonPropertyName("product_id")] string ProductId,
    [property: JsonPropertyName("version")] string Version,
    [property: JsonPropertyName("installation_id")] string InstallationId,
    [property: JsonPropertyName("correlation_id")] string CorrelationId);

public sealed record OpenLicenseCenterResponse(
    [property: JsonPropertyName("outcome")] string Outcome,
    [property: JsonPropertyName("reason")] string Reason,
    [property: JsonPropertyName("authorization_changed")] bool AuthorizationChanged,
    [property: JsonPropertyName("correlation_id")] string CorrelationId);

public sealed record TypedNotificationRequest(
    [property: JsonPropertyName("product_id")] string ProductId,
    [property: JsonPropertyName("version")] string Version,
    [property: JsonPropertyName("installation_id")] string InstallationId,
    [property: JsonPropertyName("code")] string Code);

public sealed record TypedNotificationResponse(
    [property: JsonPropertyName("capability_id")] string CapabilityId,
    [property: JsonPropertyName("contract_version")] int ContractVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("notification_id")] string? NotificationId,
    [property: JsonPropertyName("code")] string? Code,
    [property: JsonPropertyName("reason")] string Reason);

public sealed record NotificationFeedRequest(
    [property: JsonPropertyName("product_id")] string ProductId,
    [property: JsonPropertyName("version")] string Version,
    [property: JsonPropertyName("installation_id")] string InstallationId,
    [property: JsonPropertyName("limit")] int Limit,
    [property: JsonPropertyName("include_dismissed")] bool IncludeDismissed);

public sealed record NotificationContextRequest(
    [property: JsonPropertyName("product_id")] string ProductId,
    [property: JsonPropertyName("version")] string Version,
    [property: JsonPropertyName("installation_id")] string InstallationId);

public sealed record NotificationMutationRequest(
    [property: JsonPropertyName("product_id")] string ProductId,
    [property: JsonPropertyName("version")] string Version,
    [property: JsonPropertyName("installation_id")] string InstallationId,
    [property: JsonPropertyName("notification_id")] string NotificationId);

public sealed record NotificationCapabilityError(
    [property: JsonPropertyName("code")] string Code,
    [property: JsonPropertyName("message")] string Message,
    [property: JsonPropertyName("retryable")] bool Retryable);

public sealed record NotificationItem(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("source")] string Source,
    [property: JsonPropertyName("title")] string Title,
    [property: JsonPropertyName("body")] string Body,
    [property: JsonPropertyName("category")] string Category,
    [property: JsonPropertyName("severity")] string Severity,
    [property: JsonPropertyName("created_at")] string CreatedAt,
    [property: JsonPropertyName("expires_at")] string? ExpiresAt,
    [property: JsonPropertyName("state")] string State,
    [property: JsonPropertyName("delivery_mode")] string DeliveryMode,
    [property: JsonPropertyName("actions")] IReadOnlyList<object> Actions);

public sealed record NotificationFeedResponse(
    [property: JsonPropertyName("capability_id")] string CapabilityId,
    [property: JsonPropertyName("contract_version")] int ContractVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("items")] IReadOnlyList<NotificationItem> Items,
    [property: JsonPropertyName("error")] NotificationCapabilityError? Error);

public sealed record NotificationMutationResponse(
    [property: JsonPropertyName("capability_id")] string CapabilityId,
    [property: JsonPropertyName("contract_version")] int ContractVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("error")] NotificationCapabilityError? Error);

public sealed record NotificationUnreadCountResponse(
    [property: JsonPropertyName("capability_id")] string CapabilityId,
    [property: JsonPropertyName("contract_version")] int ContractVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("count")] int Count,
    [property: JsonPropertyName("error")] NotificationCapabilityError? Error);

public sealed record UpdateCheckRequest(
    [property: JsonPropertyName("product_id")] string ProductId,
    [property: JsonPropertyName("current_version")] string CurrentVersion,
    [property: JsonPropertyName("requested_version"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? RequestedVersion = null);

public sealed record UpdateCapabilityError(
    [property: JsonPropertyName("code")] string Code,
    [property: JsonPropertyName("message")] string Message,
    [property: JsonPropertyName("retryable")] bool Retryable);

public sealed record UpdateCheckResponse(
    [property: JsonPropertyName("capability_id")] string CapabilityId,
    [property: JsonPropertyName("contract_version")] int ContractVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("available_version")] string? AvailableVersion,
    [property: JsonPropertyName("error")] UpdateCapabilityError? Error);

public sealed record OpenUpdateCenterRequest(
    [property: JsonPropertyName("product_id")] string ProductId,
    [property: JsonPropertyName("version")] string Version,
    [property: JsonPropertyName("correlation_id")] string CorrelationId);

public sealed record OpenUpdateCenterResponse(
    [property: JsonPropertyName("outcome")] string Outcome,
    [property: JsonPropertyName("reason")] string Reason,
    [property: JsonPropertyName("correlation_id")] string CorrelationId);
