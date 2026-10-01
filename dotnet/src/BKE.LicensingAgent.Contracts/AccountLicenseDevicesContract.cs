using System.Text.Json.Serialization;

namespace BKE.LicensingAgent.Contracts;

public sealed record AccountLicenseDevicesRequest(
    [property: JsonPropertyName("correlation_id")] string CorrelationId,
    [property: JsonPropertyName("license_management_handle")] string LicenseManagementHandle);

public sealed record AccountLicenseDeviceDeactivateRequest(
    [property: JsonPropertyName("correlation_id")] string CorrelationId,
    [property: JsonPropertyName("license_management_handle")] string LicenseManagementHandle,
    [property: JsonPropertyName("device_management_handle")] string DeviceManagementHandle);

public sealed record AccountLicenseDeviceInfo(
    [property: JsonPropertyName("product_name")] string ProductName,
    [property: JsonPropertyName("edition_name"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? EditionName,
    [property: JsonPropertyName("key_last_four")] string KeyLastFour,
    [property: JsonPropertyName("max_devices")] int MaxDevices,
    [property: JsonPropertyName("active_devices")] int ActiveDevices);

public sealed record AccountAuthorizedDevice(
    [property: JsonPropertyName("label"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Label,
    [property: JsonPropertyName("operating_system"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? OperatingSystem,
    [property: JsonPropertyName("architecture"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Architecture,
    [property: JsonPropertyName("last_seen_at")] string LastSeenAt,
    [property: JsonPropertyName("activated_at")] string ActivatedAt,
    [property: JsonPropertyName("active")] bool Active,
    [property: JsonPropertyName("management_handle"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? ManagementHandle);

public sealed record AccountLicenseDevicesResponse(
    [property: JsonPropertyName("capability_id")] string CapabilityId,
    [property: JsonPropertyName("contract_version")] int ContractVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("license"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AccountLicenseDeviceInfo? License,
    [property: JsonPropertyName("devices")] IReadOnlyList<AccountAuthorizedDevice> Devices,
    [property: JsonPropertyName("error"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AccountLicenseDevicesError? Error);

public sealed record AccountLicenseDeviceDeactivateResponse(
    [property: JsonPropertyName("capability_id")] string CapabilityId,
    [property: JsonPropertyName("contract_version")] int ContractVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("error"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AccountLicenseDevicesError? Error);

public sealed record AccountLicenseDevicesError(
    [property: JsonPropertyName("code")] string Code,
    [property: JsonPropertyName("message")] string Message,
    [property: JsonPropertyName("retryable")] bool Retryable);
