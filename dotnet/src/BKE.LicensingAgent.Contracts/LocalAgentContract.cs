using System.Text.Json.Serialization;

namespace BKE.LicensingAgent.Contracts;

public static class LocalAgentContract
{
    public const string ContractId = "bke.licensing-agent.local-api";
    public const int ContractVersion = 1;
    public const string BindHost = "127.0.0.1";
    public const int DefaultPort = 43873;
    public const long MaxJsonBodyBytes = 32_768;

    public const string LicenseCenterBrowserPath = "/license-center";
    public const string AuthorizePath = "/v1/authorize";
    public const string ActivatePath = "/v1/activate";
    public const string OpenLicenseCenterPath = "/v1/license-center/open";
    public const string CheckUpdatesPath = "/v1/updates/check";
    public const string OpenUpdateCenterPath = "/v1/update-center/open";

    public const string UpdateCapabilityId = "bke.updates.check";
    public const int UpdateContractVersion = 1;
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
