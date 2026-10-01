using System.Text.Json;
using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Application;

public interface IAccountBillingRemote
{
    Task<RemoteAccountBillingResult> GetAsync(
        string accessToken,
        CancellationToken cancellationToken);
}

public interface IAccountBillingService
{
    Task<AccountBillingResponse> GetAsync(
        AccountBillingRequest request,
        CancellationToken cancellationToken);
}

public sealed record RemoteAccountBillingResult(
    string Status,
    AccountBillingAccount? Account = null,
    AccountBillingPermissions? Permissions = null,
    IReadOnlyList<AccountBillingInvoice>? Invoices = null,
    IReadOnlyList<AccountBillingPayment>? Payments = null,
    string? ErrorCode = null,
    bool Retryable = false);

public sealed class AccountBillingService : IAccountBillingService
{
    private readonly IAccountSessionService _accountSession;
    private readonly IAccountSessionSecretStore _secretStore;
    private readonly IAccountBillingRemote _remote;

    public AccountBillingService(
        IAccountSessionService accountSession,
        IAccountSessionSecretStore secretStore,
        IAccountBillingRemote remote)
    {
        _accountSession = accountSession;
        _secretStore = secretStore;
        _remote = remote;
    }

    public async Task<AccountBillingResponse> GetAsync(
        AccountBillingRequest request,
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
                    "Sign in with BKE before opening billing history.",
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
                        "The selected BKE account no longer permits billing history.",
                        false));
            }

            if (result.Status != "ready" ||
                result.Account is null ||
                result.Permissions is null ||
                result.Invoices is null ||
                result.Payments is null)
            {
                return Response(
                    "FAILED",
                    error: Error(
                        result.ErrorCode ?? "ACCOUNT_BILLING_UNAVAILABLE",
                        result.Status == "rate_limited"
                            ? "BKE billing history is temporarily rate limited."
                            : "BKE billing history is temporarily unavailable.",
                        result.Retryable));
            }

            return Response(
                "READY",
                result.Account,
                result.Permissions,
                result.Invoices,
                result.Payments);
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
            JsonException or
            TaskCanceledException)
        {
            return Response(
                "FAILED",
                error: Error(
                    "ACCOUNT_BILLING_UNAVAILABLE",
                    "BKE billing history is temporarily unavailable.",
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

    private static AccountBillingResponse Response(
        string status,
        AccountBillingAccount? account = null,
        AccountBillingPermissions? permissions = null,
        IReadOnlyList<AccountBillingInvoice>? invoices = null,
        IReadOnlyList<AccountBillingPayment>? payments = null,
        AccountBillingError? error = null) =>
        new(
            LocalAgentContract.AccountBillingCapabilityId,
            LocalAgentContract.AccountBillingContractVersion,
            status,
            account,
            permissions,
            invoices ?? Array.Empty<AccountBillingInvoice>(),
            payments ?? Array.Empty<AccountBillingPayment>(),
            error);

    private static AccountBillingError Error(
        string code,
        string message,
        bool retryable) =>
        new(code, message, retryable);
}
