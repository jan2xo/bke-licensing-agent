using System.Text.Json.Serialization;

namespace BKE.LicensingAgent.Contracts;

public sealed record AccountOrganizationOverviewRequest(
    [property: JsonPropertyName("correlation_id")] string CorrelationId);

public sealed record AccountOrganizationCreateRequest(
    [property: JsonPropertyName("correlation_id")] string CorrelationId,
    [property: JsonPropertyName("display_name")] string DisplayName,
    [property: JsonPropertyName("legal_name")] string LegalName,
    [property: JsonPropertyName("billing_email")] string BillingEmail,
    [property: JsonPropertyName("registration_number"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? RegistrationNumber,
    [property: JsonPropertyName("tax_id"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? TaxId);

public sealed record AccountOrganizationProfileUpdateRequest(
    [property: JsonPropertyName("correlation_id")] string CorrelationId,
    [property: JsonPropertyName("update_organization_profile")] bool UpdateOrganizationProfile,
    [property: JsonPropertyName("display_name"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? DisplayName,
    [property: JsonPropertyName("legal_name"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? LegalName,
    [property: JsonPropertyName("registration_number")] string? RegistrationNumber,
    [property: JsonPropertyName("update_billing_profile")] bool UpdateBillingProfile,
    [property: JsonPropertyName("billing_email"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? BillingEmail,
    [property: JsonPropertyName("tax_id")] string? TaxId);

public sealed record AccountOrganizationInvitationCreateRequest(
    [property: JsonPropertyName("correlation_id")] string CorrelationId,
    [property: JsonPropertyName("email")] string Email,
    [property: JsonPropertyName("role")] string Role);

public sealed record AccountOrganizationInvitationIssued(
    [property: JsonPropertyName("email")] string Email,
    [property: JsonPropertyName("role")] string Role,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("expires_at")] string ExpiresAt,
    [property: JsonPropertyName("created_at")] string CreatedAt);

public sealed record AccountOrganizationAccount(
    [property: JsonPropertyName("display_name")] string DisplayName,
    [property: JsonPropertyName("lifecycle_state")] string LifecycleState,
    [property: JsonPropertyName("role")] string Role);

public sealed record AccountOrganizationPermissions(
    [property: JsonPropertyName("manage_members")] bool ManageMembers,
    [property: JsonPropertyName("leave_organization")] bool LeaveOrganization,
    [property: JsonPropertyName("view_billing")] bool ViewBilling,
    [property: JsonPropertyName("view_licenses")] bool ViewLicenses);

public sealed record AccountOrganizationProfile(
    [property: JsonPropertyName("legal_name")] string LegalName,
    [property: JsonPropertyName("registration_number"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? RegistrationNumber);

public sealed record AccountOrganizationCounts(
    [property: JsonPropertyName("licenses"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] int? Licenses,
    [property: JsonPropertyName("subscriptions"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] int? Subscriptions,
    [property: JsonPropertyName("orders"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] int? Orders);

public sealed record AccountOrganizationMember(
    [property: JsonPropertyName("email")] string Email,
    [property: JsonPropertyName("name"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Name,
    [property: JsonPropertyName("role")] string Role,
    [property: JsonPropertyName("management_handle")] string ManagementHandle);

public sealed record AccountOrganizationInvitation(
    [property: JsonPropertyName("email")] string Email,
    [property: JsonPropertyName("role")] string Role,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("expires_at")] string ExpiresAt,
    [property: JsonPropertyName("created_at")] string CreatedAt,
    [property: JsonPropertyName("management_handle")] string ManagementHandle);

public sealed record AccountOrganizationOverviewResponse(
    [property: JsonPropertyName("capability_id")] string CapabilityId,
    [property: JsonPropertyName("contract_version")] int ContractVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("account"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AccountOrganizationAccount? Account,
    [property: JsonPropertyName("permissions"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AccountOrganizationPermissions? Permissions,
    [property: JsonPropertyName("organization"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AccountOrganizationProfile? Organization,
    [property: JsonPropertyName("billing_email"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? BillingEmail,
    [property: JsonPropertyName("tax_id"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? TaxId,
    [property: JsonPropertyName("counts"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AccountOrganizationCounts? Counts,
    [property: JsonPropertyName("members")] IReadOnlyList<AccountOrganizationMember> Members,
    [property: JsonPropertyName("invitations")] IReadOnlyList<AccountOrganizationInvitation> Invitations,
    [property: JsonPropertyName("error"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AccountOrganizationError? Error);

public sealed record AccountOrganizationCreateResponse(
    [property: JsonPropertyName("capability_id")] string CapabilityId,
    [property: JsonPropertyName("contract_version")] int ContractVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("display_name"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? DisplayName,
    [property: JsonPropertyName("switch_required")] bool SwitchRequired,
    [property: JsonPropertyName("error"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AccountOrganizationError? Error);

public sealed record AccountOrganizationProfileUpdateResponse(
    [property: JsonPropertyName("capability_id")] string CapabilityId,
    [property: JsonPropertyName("contract_version")] int ContractVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("error"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AccountOrganizationError? Error);

public sealed record AccountOrganizationLeaveRequest(
    [property: JsonPropertyName("correlation_id")] string CorrelationId);

public sealed record AccountOrganizationLeaveResponse(
    [property: JsonPropertyName("capability_id")] string CapabilityId,
    [property: JsonPropertyName("contract_version")] int ContractVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("reauthentication_required")] bool ReauthenticationRequired,
    [property: JsonPropertyName("error"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AccountOrganizationError? Error);

public sealed record AccountOrganizationMemberManageRequest(
    [property: JsonPropertyName("correlation_id")] string CorrelationId,
    [property: JsonPropertyName("action")] string Action,
    [property: JsonPropertyName("management_handle")] string ManagementHandle,
    [property: JsonPropertyName("role"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Role);

public sealed record AccountOrganizationMemberManageResponse(
    [property: JsonPropertyName("capability_id")] string CapabilityId,
    [property: JsonPropertyName("contract_version")] int ContractVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("error"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AccountOrganizationError? Error);

public sealed record AccountOrganizationInvitationManageRequest(
    [property: JsonPropertyName("correlation_id")] string CorrelationId,
    [property: JsonPropertyName("action")] string Action,
    [property: JsonPropertyName("management_handle")] string ManagementHandle);

public sealed record AccountOrganizationInvitationManageResponse(
    [property: JsonPropertyName("capability_id")] string CapabilityId,
    [property: JsonPropertyName("contract_version")] int ContractVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("invitation"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AccountOrganizationInvitationIssued? Invitation,
    [property: JsonPropertyName("invitation_code"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? InvitationCode,
    [property: JsonPropertyName("error"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AccountOrganizationError? Error);

public sealed record AccountOrganizationInvitationCreateResponse(
    [property: JsonPropertyName("capability_id")] string CapabilityId,
    [property: JsonPropertyName("contract_version")] int ContractVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("invitation"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AccountOrganizationInvitationIssued? Invitation,
    [property: JsonPropertyName("invitation_code"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? InvitationCode,
    [property: JsonPropertyName("error"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AccountOrganizationError? Error);

public sealed record AccountOrganizationError(
    [property: JsonPropertyName("code")] string Code,
    [property: JsonPropertyName("message")] string Message,
    [property: JsonPropertyName("retryable")] bool Retryable);
