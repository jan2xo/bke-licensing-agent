using System.Text.Json.Serialization;

namespace BKE.LicensingAgent.Contracts;

public sealed record AccountLicenseSeatsRequest(
    [property: JsonPropertyName("correlation_id")] string CorrelationId,
    [property: JsonPropertyName("license_management_handle")] string LicenseManagementHandle);

public sealed record AccountLicenseSeatsManageRequest(
    [property: JsonPropertyName("correlation_id")] string CorrelationId,
    [property: JsonPropertyName("action")] string Action,
    [property: JsonPropertyName("license_management_handle")] string LicenseManagementHandle,
    [property: JsonPropertyName("target_management_handle")] string TargetManagementHandle);

public sealed record AccountLicenseSeatInfo(
    [property: JsonPropertyName("product_name")] string ProductName,
    [property: JsonPropertyName("edition_name"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? EditionName,
    [property: JsonPropertyName("key_last_four")] string KeyLastFour,
    [property: JsonPropertyName("max_seats")] int MaxSeats,
    [property: JsonPropertyName("assigned_seats")] int AssignedSeats,
    [property: JsonPropertyName("available_seats")] int AvailableSeats);

public sealed record AccountLicenseSeatTarget(
    [property: JsonPropertyName("email")] string Email,
    [property: JsonPropertyName("name"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Name,
    [property: JsonPropertyName("assigned")] bool Assigned,
    [property: JsonPropertyName("eligible")] bool Eligible,
    [property: JsonPropertyName("management_handle")] string ManagementHandle);

public sealed record AccountLicenseSeatsResponse(
    [property: JsonPropertyName("capability_id")] string CapabilityId,
    [property: JsonPropertyName("contract_version")] int ContractVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("license"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AccountLicenseSeatInfo? License,
    [property: JsonPropertyName("targets")] IReadOnlyList<AccountLicenseSeatTarget> Targets,
    [property: JsonPropertyName("error"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AccountLicenseSeatsError? Error);

public sealed record AccountLicenseSeatsManageResponse(
    [property: JsonPropertyName("capability_id")] string CapabilityId,
    [property: JsonPropertyName("contract_version")] int ContractVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("error"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AccountLicenseSeatsError? Error);

public sealed record AccountLicenseSeatsError(
    [property: JsonPropertyName("code")] string Code,
    [property: JsonPropertyName("message")] string Message,
    [property: JsonPropertyName("retryable")] bool Retryable);
