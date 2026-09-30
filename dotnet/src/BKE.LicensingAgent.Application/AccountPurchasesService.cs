using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Application;

public interface IAccountPurchasesRemote
{
    Task<RemoteAccountPurchasesResult> GetAsync(
        string accessToken,
        CancellationToken cancellationToken);
}

public interface IAccountPurchasesService
{
    Task<AccountPurchasesResponse> GetAsync(
        AccountPurchasesRequest request,
        CancellationToken cancellationToken);
}

public sealed record RemoteAccountPurchasesResult(
    string Status,
    AccountPurchasesAccount? Account = null,
    AccountPurchasesPermissions? Permissions = null,
    IReadOnlyList<AccountPurchasesLicense>? Licenses = null,
    IReadOnlyList<AccountPurchasesSubscription>? Subscriptions = null,
    IReadOnlyList<AccountPurchasesOrder>? Orders = null,
    string? ErrorCode = null,
    bool Retryable = false);

public sealed class AccountPurchasesService : IAccountPurchasesService
{
    private readonly IAccountSessionService _accountSession;
    private readonly IAccountSessionSecretStore _secretStore;
    private readonly IAccountPurchasesRemote _remote;

    public AccountPurchasesService(
        IAccountSessionService accountSession,
        IAccountSessionSecretStore secretStore,
        IAccountPurchasesRemote remote)
    {
        _accountSession = accountSession;
        _secretStore = secretStore;
        _remote = remote;
    }

    public async Task<AccountPurchasesResponse> GetAsync(
        AccountPurchasesRequest request,
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
                    "Sign in with BKE before opening purchases and licenses.",
                    false));
        }

        try
        {
            var result = await _remote.GetAsync(
                active.AccessToken,
                cancellationToken);

            if (result.Status == "account_forbidden")
            {
                return Response(
                    "FORBIDDEN",
                    error: Error(
                        result.ErrorCode ?? "ACCOUNT_FORBIDDEN",
                        "The selected BKE account no longer permits this view.",
                        false));
            }

            if (result.Status != "ready" ||
                result.Account is null ||
                result.Permissions is null ||
                result.Licenses is null ||
                result.Subscriptions is null ||
                result.Orders is null)
            {
                return Response(
                    "FAILED",
                    error: Error(
                        result.ErrorCode ?? "ACCOUNT_PURCHASES_UNAVAILABLE",
                        result.Status == "rate_limited"
                            ? "BKE purchases and licenses are temporarily rate limited."
                            : "BKE purchases and licenses are temporarily unavailable.",
                        result.Retryable));
            }

            return Response(
                "READY",
                result.Account,
                result.Permissions,
                result.Licenses,
                result.Subscriptions,
                result.Orders,
                null);
        }
        catch (UnauthorizedAccessException)
        {
            await _secretStore.ClearAsync(CancellationToken.None);
            return Response(
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
            return Response(
                "FAILED",
                error: Error(
                    "ACCOUNT_PURCHASES_UNAVAILABLE",
                    "BKE purchases and licenses are temporarily unavailable.",
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

    private static AccountPurchasesResponse Response(
        string status,
        AccountPurchasesAccount? account = null,
        AccountPurchasesPermissions? permissions = null,
        IReadOnlyList<AccountPurchasesLicense>? licenses = null,
        IReadOnlyList<AccountPurchasesSubscription>? subscriptions = null,
        IReadOnlyList<AccountPurchasesOrder>? orders = null,
        AccountPurchasesError? error = null) =>
        new(
            LocalAgentContract.AccountPurchasesCapabilityId,
            LocalAgentContract.AccountPurchasesContractVersion,
            status,
            account,
            permissions,
            licenses ?? Array.Empty<AccountPurchasesLicense>(),
            subscriptions ?? Array.Empty<AccountPurchasesSubscription>(),
            orders ?? Array.Empty<AccountPurchasesOrder>(),
            error);

    private static AccountPurchasesError Error(
        string code,
        string message,
        bool retryable) =>
        new(code, message, retryable);
}
