using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Application;

public interface IAccountOrganizationRemote
{
    Task<RemoteAccountOrganizationResult> GetAsync(
        string accessToken,
        CancellationToken cancellationToken);

    Task<RemoteAccountOrganizationCreateResult> CreateAsync(
        string accessToken,
        string displayName,
        string legalName,
        string billingEmail,
        string? registrationNumber,
        string? taxId,
        CancellationToken cancellationToken);

    Task<RemoteAccountOrganizationProfileUpdateResult> UpdateProfileAsync(
        string accessToken,
        bool updateOrganizationProfile,
        string? displayName,
        string? legalName,
        string? registrationNumber,
        bool updateBillingProfile,
        string? billingEmail,
        string? taxId,
        CancellationToken cancellationToken);

    Task<RemoteAccountOrganizationInvitationCreateResult> CreateInvitationAsync(
        string accessToken,
        string email,
        string role,
        CancellationToken cancellationToken);

    Task<RemoteAccountOrganizationInvitationManageResult> ManageInvitationAsync(
        string accessToken,
        string action,
        string managementHandle,
        CancellationToken cancellationToken);
}

public interface IAccountOrganizationService
{
    Task<AccountOrganizationOverviewResponse> GetAsync(
        AccountOrganizationOverviewRequest request,
        CancellationToken cancellationToken);

    Task<AccountOrganizationCreateResponse> CreateAsync(
        AccountOrganizationCreateRequest request,
        CancellationToken cancellationToken);

    Task<AccountOrganizationProfileUpdateResponse> UpdateProfileAsync(
        AccountOrganizationProfileUpdateRequest request,
        CancellationToken cancellationToken);

    Task<AccountOrganizationInvitationCreateResponse> CreateInvitationAsync(
        AccountOrganizationInvitationCreateRequest request,
        CancellationToken cancellationToken);

    Task<AccountOrganizationInvitationManageResponse> ManageInvitationAsync(
        AccountOrganizationInvitationManageRequest request,
        CancellationToken cancellationToken);
}

public sealed record RemoteAccountOrganizationCreateResult(
    string Status,
    string? DisplayName = null,
    bool SwitchRequired = false,
    string? ErrorCode = null,
    bool Retryable = false);

public sealed record RemoteAccountOrganizationProfileUpdateResult(
    string Status,
    string? ErrorCode = null,
    bool Retryable = false);

public sealed record RemoteAccountOrganizationInvitationCreateResult(
    string Status,
    AccountOrganizationInvitationIssued? Invitation = null,
    string? InvitationCode = null,
    string? ErrorCode = null,
    bool Retryable = false);

public sealed record RemoteAccountOrganizationInvitationManageResult(
    string Status,
    AccountOrganizationInvitationIssued? Invitation = null,
    string? InvitationCode = null,
    string? ErrorCode = null,
    bool Retryable = false);

public sealed record RemoteAccountOrganizationResult(
    string Status,
    AccountOrganizationAccount? Account = null,
    AccountOrganizationPermissions? Permissions = null,
    AccountOrganizationProfile? Organization = null,
    string? BillingEmail = null,
    string? TaxId = null,
    AccountOrganizationCounts? Counts = null,
    IReadOnlyList<AccountOrganizationMember>? Members = null,
    IReadOnlyList<AccountOrganizationInvitation>? Invitations = null,
    string? ErrorCode = null,
    bool Retryable = false);

public sealed class AccountOrganizationService : IAccountOrganizationService
{
    private readonly IAccountSessionService _accountSession;
    private readonly IAccountSessionSecretStore _secretStore;
    private readonly IAccountOrganizationRemote _remote;

    public AccountOrganizationService(
        IAccountSessionService accountSession,
        IAccountSessionSecretStore secretStore,
        IAccountOrganizationRemote remote)
    {
        _accountSession = accountSession;
        _secretStore = secretStore;
        _remote = remote;
    }

    public async Task<AccountOrganizationOverviewResponse> GetAsync(
        AccountOrganizationOverviewRequest request,
        CancellationToken cancellationToken)
    {
        var active = await ActiveAsync(
            request.CorrelationId,
            cancellationToken);
        if (active is null)
        {
            return Response(
                "AUTH_REQUIRED",
                error: Error(
                    "AUTH_REQUIRED",
                    "Sign in with BKE before opening organization details.",
                    false));
        }

        try
        {
            var result = await _remote.GetAsync(
                active.AccessToken,
                cancellationToken);

            if (result.Status == "not_organization")
            {
                return Response("NOT_ORGANIZATION");
            }

            if (result.Status != "ready" ||
                result.Account is null ||
                result.Permissions is null ||
                result.Organization is null ||
                result.Counts is null ||
                result.Members is null ||
                result.Invitations is null)
            {
                return Response(
                    "FAILED",
                    error: Error(
                        result.ErrorCode ?? "ORGANIZATION_UNAVAILABLE",
                        "BKE organization details are temporarily unavailable.",
                        result.Retryable));
            }

            return Response(
                "READY",
                result.Account,
                result.Permissions,
                result.Organization,
                result.BillingEmail,
                result.TaxId,
                result.Counts,
                result.Members,
                result.Invitations);
        }
        catch (UnauthorizedAccessException)
        {
            await _secretStore.ClearAsync(CancellationToken.None);
            return Response(
                "AUTH_REQUIRED",
                error: Error(
                    "SESSION_INVALID",
                    "The selected BKE account is no longer available. Sign in again.",
                    false));
        }
        catch (Exception error) when (
            error is HttpRequestException or
            InvalidDataException or
            TaskCanceledException)
        {
            return Response(
                "FAILED",
                error: Error(
                    "ORGANIZATION_UNAVAILABLE",
                    "BKE organization details are temporarily unavailable.",
                    true));
        }
    }

    public async Task<AccountOrganizationCreateResponse> CreateAsync(
        AccountOrganizationCreateRequest request,
        CancellationToken cancellationToken)
    {
        var active = await ActiveAsync(
            request.CorrelationId,
            cancellationToken);
        if (active is null)
        {
            return CreateResponse(
                "AUTH_REQUIRED",
                error: Error(
                    "AUTH_REQUIRED",
                    "Sign in with BKE before creating an organization.",
                    false));
        }

        try
        {
            var result = await _remote.CreateAsync(
                active.AccessToken,
                request.DisplayName,
                request.LegalName,
                request.BillingEmail,
                request.RegistrationNumber,
                request.TaxId,
                cancellationToken);

            if (result.Status == "created" &&
                !string.IsNullOrWhiteSpace(result.DisplayName) &&
                result.SwitchRequired)
            {
                return CreateResponse(
                    "CREATED",
                    result.DisplayName,
                    true);
            }

            var status = result.Status switch
            {
                "invalid_input" => "INVALID_INPUT",
                "email_not_verified" => "EMAIL_NOT_VERIFIED",
                "legal_reacceptance_required" =>
                    "LEGAL_REACCEPTANCE_REQUIRED",
                _ => "FAILED",
            };
            var message = result.Status switch
            {
                "invalid_input" =>
                    "The organization details were not accepted.",
                "email_not_verified" =>
                    "Verify your BKE email before creating an organization.",
                "legal_reacceptance_required" =>
                    "Accept the current BKE Legal documents before creating an organization.",
                "rate_limited" =>
                    "Organization creation is temporarily rate limited.",
                _ =>
                    "BKE organization creation is temporarily unavailable.",
            };

            return CreateResponse(
                status,
                error: Error(
                    result.ErrorCode ?? "ORGANIZATION_CREATE_UNAVAILABLE",
                    message,
                    result.Retryable));
        }
        catch (UnauthorizedAccessException)
        {
            await _secretStore.ClearAsync(CancellationToken.None);
            return CreateResponse(
                "AUTH_REQUIRED",
                error: Error(
                    "SESSION_INVALID",
                    "The BKE account session is no longer valid. Sign in again.",
                    false));
        }
        catch (Exception error) when (
            error is HttpRequestException or
            InvalidDataException or
            TaskCanceledException)
        {
            return CreateResponse(
                "OUTCOME_UNKNOWN",
                error: Error(
                    "ORGANIZATION_CREATE_OUTCOME_UNKNOWN",
                    "The organization creation result could not be confirmed. Switch accounts and check the available BKE accounts before retrying.",
                    false));
        }
    }


    public async Task<AccountOrganizationProfileUpdateResponse> UpdateProfileAsync(
        AccountOrganizationProfileUpdateRequest request,
        CancellationToken cancellationToken)
    {
        var active = await ActiveAsync(
            request.CorrelationId,
            cancellationToken);
        if (active is null)
        {
            return ProfileUpdateResponse(
                "AUTH_REQUIRED",
                Error(
                    "AUTH_REQUIRED",
                    "Sign in with BKE before updating organization details.",
                    false));
        }

        try
        {
            var result = await _remote.UpdateProfileAsync(
                active.AccessToken,
                request.UpdateOrganizationProfile,
                request.DisplayName,
                request.LegalName,
                request.RegistrationNumber,
                request.UpdateBillingProfile,
                request.BillingEmail,
                request.TaxId,
                cancellationToken);

            if (result.Status == "updated")
            {
                return ProfileUpdateResponse("UPDATED");
            }

            var status = result.Status switch
            {
                "invalid_input" => "INVALID_INPUT",
                "not_organization" => "NOT_ORGANIZATION",
                "account_forbidden" => "ACCOUNT_FORBIDDEN",
                _ => "FAILED",
            };

            var message = result.Status switch
            {
                "invalid_input" =>
                    "The organization profile update was not accepted.",
                "not_organization" =>
                    "The selected BKE account is not an Organization account.",
                "account_forbidden" =>
                    "The selected BKE account role cannot update these organization fields.",
                "rate_limited" =>
                    "Organization profile updates are temporarily rate limited.",
                _ =>
                    "BKE organization profile update is temporarily unavailable.",
            };

            return ProfileUpdateResponse(
                status,
                Error(
                    result.ErrorCode ??
                        "ORGANIZATION_PROFILE_UPDATE_UNAVAILABLE",
                    message,
                    result.Retryable));
        }
        catch (UnauthorizedAccessException)
        {
            await _secretStore.ClearAsync(CancellationToken.None);
            return ProfileUpdateResponse(
                "AUTH_REQUIRED",
                Error(
                    "SESSION_INVALID",
                    "The BKE account session is no longer valid. Sign in again.",
                    false));
        }
        catch (Exception error) when (
            error is HttpRequestException or
            InvalidDataException or
            TaskCanceledException)
        {
            return ProfileUpdateResponse(
                "OUTCOME_UNKNOWN",
                Error(
                    "ORGANIZATION_PROFILE_UPDATE_OUTCOME_UNKNOWN",
                    "The organization profile update result could not be confirmed. Refresh organization details before deciding whether to submit another update.",
                    false));
        }
    }


    public async Task<AccountOrganizationInvitationCreateResponse> CreateInvitationAsync(
        AccountOrganizationInvitationCreateRequest request,
        CancellationToken cancellationToken)
    {
        var active = await ActiveAsync(
            request.CorrelationId,
            cancellationToken);
        if (active is null)
        {
            return InvitationCreateResponse(
                "AUTH_REQUIRED",
                error: Error(
                    "AUTH_REQUIRED",
                    "Sign in with BKE before inviting an organization member.",
                    false));
        }

        try
        {
            var result = await _remote.CreateInvitationAsync(
                active.AccessToken,
                request.Email,
                request.Role,
                cancellationToken);

            if (result.Status == "created" &&
                result.Invitation is not null &&
                !string.IsNullOrWhiteSpace(result.InvitationCode))
            {
                return InvitationCreateResponse(
                    "CREATED",
                    result.Invitation,
                    result.InvitationCode);
            }

            var status = result.Status switch
            {
                "invalid_input" => "INVALID_INPUT",
                "not_organization" => "NOT_ORGANIZATION",
                "account_forbidden" => "ACCOUNT_FORBIDDEN",
                "conflict" => "CONFLICT",
                _ => "FAILED",
            };

            var message = result.Status switch
            {
                "invalid_input" =>
                    "The organization invitation details were not accepted.",
                "not_organization" =>
                    "The selected BKE account is not an Organization account.",
                "account_forbidden" =>
                    "The selected BKE account role cannot invite organization members.",
                "conflict" =>
                    "The invited email already has an incompatible membership or pending invitation state.",
                "rate_limited" =>
                    "Organization invitations are temporarily rate limited.",
                _ =>
                    "BKE organization invitation issuance is temporarily unavailable.",
            };

            return InvitationCreateResponse(
                status,
                error: Error(
                    result.ErrorCode ??
                        "ORGANIZATION_INVITATION_UNAVAILABLE",
                    message,
                    result.Retryable));
        }
        catch (UnauthorizedAccessException)
        {
            await _secretStore.ClearAsync(CancellationToken.None);
            return InvitationCreateResponse(
                "AUTH_REQUIRED",
                error: Error(
                    "SESSION_INVALID",
                    "The BKE account session is no longer valid. Sign in again.",
                    false));
        }
        catch (Exception error) when (
            error is HttpRequestException or
            InvalidDataException or
            TaskCanceledException)
        {
            return InvitationCreateResponse(
                "OUTCOME_UNKNOWN",
                error: Error(
                    "ORGANIZATION_INVITATION_OUTCOME_UNKNOWN",
                    "The invitation result could not be confirmed. Refresh organization details before deciding whether to issue another invitation.",
                    false));
        }
    }


    public async Task<AccountOrganizationInvitationManageResponse> ManageInvitationAsync(
        AccountOrganizationInvitationManageRequest request,
        CancellationToken cancellationToken)
    {
        var active = await ActiveAsync(
            request.CorrelationId,
            cancellationToken);
        if (active is null)
        {
            return InvitationManageResponse(
                "AUTH_REQUIRED",
                error: Error(
                    "AUTH_REQUIRED",
                    "Sign in with BKE before managing organization invitations.",
                    false));
        }

        try
        {
            var result = await _remote.ManageInvitationAsync(
                active.AccessToken,
                request.Action,
                request.ManagementHandle,
                cancellationToken);

            if (result.Status == "resent" &&
                result.Invitation is not null &&
                !string.IsNullOrWhiteSpace(result.InvitationCode))
            {
                return InvitationManageResponse(
                    "RESENT",
                    result.Invitation,
                    result.InvitationCode);
            }

            if (result.Status == "revoked" &&
                result.Invitation is not null &&
                result.InvitationCode is null)
            {
                return InvitationManageResponse(
                    "REVOKED",
                    result.Invitation);
            }

            var status = result.Status switch
            {
                "invalid_input" => "INVALID_INPUT",
                "not_organization" => "NOT_ORGANIZATION",
                "account_forbidden" => "ACCOUNT_FORBIDDEN",
                "invitation_not_found" => "INVITATION_NOT_FOUND",
                "invitation_not_pending" => "INVITATION_NOT_PENDING",
                "invitation_expired" => "INVITATION_EXPIRED",
                _ => "FAILED",
            };

            var message = result.Status switch
            {
                "invalid_input" =>
                    "The organization invitation management request was not accepted.",
                "not_organization" =>
                    "The selected BKE account is not an Organization account.",
                "account_forbidden" =>
                    "The selected BKE account role cannot manage organization invitations.",
                "invitation_not_found" =>
                    "The selected invitation is no longer available. Refresh organization details.",
                "invitation_not_pending" =>
                    "The selected invitation is no longer pending. Refresh organization details.",
                "invitation_expired" =>
                    "The selected invitation has expired. Refresh organization details.",
                "rate_limited" =>
                    "Organization invitation management is temporarily rate limited.",
                _ =>
                    "BKE organization invitation management is temporarily unavailable.",
            };

            return InvitationManageResponse(
                status,
                error: Error(
                    result.ErrorCode ??
                        "ORGANIZATION_INVITATION_MANAGEMENT_UNAVAILABLE",
                    message,
                    result.Retryable));
        }
        catch (UnauthorizedAccessException)
        {
            await _secretStore.ClearAsync(CancellationToken.None);
            return InvitationManageResponse(
                "AUTH_REQUIRED",
                error: Error(
                    "SESSION_INVALID",
                    "The BKE account session is no longer valid. Sign in again.",
                    false));
        }
        catch (Exception error) when (
            error is HttpRequestException or
            InvalidDataException or
            TaskCanceledException)
        {
            return InvitationManageResponse(
                "OUTCOME_UNKNOWN",
                error: Error(
                    "ORGANIZATION_INVITATION_MANAGEMENT_OUTCOME_UNKNOWN",
                    "The invitation management result could not be confirmed. Refresh organization details before deciding whether to resend or revoke again.",
                    false));
        }
    }


    private async Task<ActiveAccountSessionState?> ActiveAsync(
        string correlationId,
        CancellationToken cancellationToken)
    {
        var status = await _accountSession.StatusAsync(
            new AccountSessionStatusRequest(correlationId),
            cancellationToken);
        if (status.Status != "AUTHENTICATED")
        {
            return null;
        }

        return await _secretStore.ReadAsync(cancellationToken)
            as ActiveAccountSessionState;
    }

    private static AccountOrganizationOverviewResponse Response(
        string status,
        AccountOrganizationAccount? account = null,
        AccountOrganizationPermissions? permissions = null,
        AccountOrganizationProfile? organization = null,
        string? billingEmail = null,
        string? taxId = null,
        AccountOrganizationCounts? counts = null,
        IReadOnlyList<AccountOrganizationMember>? members = null,
        IReadOnlyList<AccountOrganizationInvitation>? invitations = null,
        AccountOrganizationError? error = null) =>
        new(
            LocalAgentContract.AccountOrganizationCapabilityId,
            LocalAgentContract.AccountOrganizationContractVersion,
            status,
            account,
            permissions,
            organization,
            billingEmail,
            taxId,
            counts,
            members ?? Array.Empty<AccountOrganizationMember>(),
            invitations ?? Array.Empty<AccountOrganizationInvitation>(),
            error);

    private static AccountOrganizationCreateResponse CreateResponse(
        string status,
        string? displayName = null,
        bool switchRequired = false,
        AccountOrganizationError? error = null) =>
        new(
            LocalAgentContract.AccountOrganizationCapabilityId,
            LocalAgentContract.AccountOrganizationContractVersion,
            status,
            displayName,
            switchRequired,
            error);

    private static AccountOrganizationProfileUpdateResponse ProfileUpdateResponse(
        string status,
        AccountOrganizationError? error = null) =>
        new(
            LocalAgentContract.AccountOrganizationCapabilityId,
            LocalAgentContract.AccountOrganizationContractVersion,
            status,
            error);

    private static AccountOrganizationInvitationCreateResponse InvitationCreateResponse(
        string status,
        AccountOrganizationInvitationIssued? invitation = null,
        string? invitationCode = null,
        AccountOrganizationError? error = null) =>
        new(
            LocalAgentContract.AccountOrganizationCapabilityId,
            LocalAgentContract.AccountOrganizationContractVersion,
            status,
            invitation,
            invitationCode,
            error);

    private static AccountOrganizationInvitationManageResponse InvitationManageResponse(
        string status,
        AccountOrganizationInvitationIssued? invitation = null,
        string? invitationCode = null,
        AccountOrganizationError? error = null) =>
        new(
            LocalAgentContract.AccountOrganizationCapabilityId,
            LocalAgentContract.AccountOrganizationContractVersion,
            status,
            invitation,
            invitationCode,
            error);

    private static AccountOrganizationError Error(
        string code,
        string message,
        bool retryable) =>
        new(code, message, retryable);
}
