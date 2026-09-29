using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Application;

public interface IAccountOrganizationRemote
{
    Task<RemoteAccountOrganizationResult> GetAsync(
        string accessToken,
        CancellationToken cancellationToken);
}

public interface IAccountOrganizationService
{
    Task<AccountOrganizationOverviewResponse> GetAsync(
        AccountOrganizationOverviewRequest request,
        CancellationToken cancellationToken);
}

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

    private static AccountOrganizationError Error(
        string code,
        string message,
        bool retryable) =>
        new(code, message, retryable);
}
