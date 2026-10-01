using System.Text.Json;
using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Application;

public interface IAccountPendingOrdersRemote
{
    Task<RemoteAccountPendingOrderContinueResult> ContinueAsync(
        string accessToken,
        string orderContinueHandle,
        CancellationToken cancellationToken);

    Task<RemoteAccountPendingOrderCancelResult> CancelAsync(
        string accessToken,
        string orderCancelHandle,
        CancellationToken cancellationToken);
}

public interface IAccountPendingOrdersService
{
    Task<AccountPendingOrderContinueResponse> ContinueAsync(
        AccountPendingOrderContinueRequest request,
        CancellationToken cancellationToken);

    Task<AccountPendingOrderCancelResponse> CancelAsync(
        AccountPendingOrderCancelRequest request,
        CancellationToken cancellationToken);
}

public sealed record RemoteAccountPendingOrderContinueResult(
    string Status,
    string? CheckoutUrl = null,
    string? ErrorCode = null,
    bool Retryable = false);

public sealed record RemoteAccountPendingOrderCancelResult(
    string Status,
    string? ErrorCode = null,
    bool Retryable = false);

public sealed class AccountPendingOrdersService :
    IAccountPendingOrdersService
{
    private readonly IAccountSessionService _accountSession;
    private readonly IAccountSessionSecretStore _secretStore;
    private readonly IAccountPendingOrdersRemote _remote;

    public AccountPendingOrdersService(
        IAccountSessionService accountSession,
        IAccountSessionSecretStore secretStore,
        IAccountPendingOrdersRemote remote)
    {
        _accountSession = accountSession;
        _secretStore = secretStore;
        _remote = remote;
    }

    public async Task<AccountPendingOrderContinueResponse>
        ContinueAsync(
            AccountPendingOrderContinueRequest request,
            CancellationToken cancellationToken)
    {
        var active = await ActiveAsync(
            request.CorrelationId,
            cancellationToken);
        if (active is null)
        {
            return ContinueResponse(
                "AUTH_REQUIRED",
                error: Error(
                    "AUTH_REQUIRED",
                    "Sign in with BKE before continuing a pending order.",
                    false));
        }

        try
        {
            var result = await _remote.ContinueAsync(
                active.AccessToken,
                request.OrderContinueHandle,
                cancellationToken);

            if (result.Status == "continued" &&
                !string.IsNullOrWhiteSpace(result.CheckoutUrl))
            {
                return ContinueResponse(
                    "CONTINUED",
                    result.CheckoutUrl);
            }

            return ContinueResponse(
                LocalStatus(result.Status),
                error: Error(
                    result.ErrorCode ??
                        "ORDER_CONTINUE_UNAVAILABLE",
                    ContinueFailureMessage(result.Status),
                    result.Retryable));
        }
        catch (UnauthorizedAccessException)
        {
            await _secretStore.ClearAsync(
                CancellationToken.None);
            return ContinueResponse(
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
            return ContinueResponse(
                "OUTCOME_UNKNOWN",
                error: Error(
                    "ORDER_CONTINUE_OUTCOME_UNKNOWN",
                    "Pending-order continuation could not be confirmed. Refresh purchases before trying another order action.",
                    false));
        }
    }

    public async Task<AccountPendingOrderCancelResponse>
        CancelAsync(
            AccountPendingOrderCancelRequest request,
            CancellationToken cancellationToken)
    {
        var active = await ActiveAsync(
            request.CorrelationId,
            cancellationToken);
        if (active is null)
        {
            return CancelResponse(
                "AUTH_REQUIRED",
                Error(
                    "AUTH_REQUIRED",
                    "Sign in with BKE before cancelling a pending order.",
                    false));
        }

        try
        {
            var result = await _remote.CancelAsync(
                active.AccessToken,
                request.OrderCancelHandle,
                cancellationToken);

            if (result.Status == "cancelled")
            {
                return CancelResponse("CANCELLED");
            }

            return CancelResponse(
                LocalStatus(result.Status),
                Error(
                    result.ErrorCode ??
                        "ORDER_CANCEL_UNAVAILABLE",
                    CancelFailureMessage(result.Status),
                    result.Retryable));
        }
        catch (UnauthorizedAccessException)
        {
            await _secretStore.ClearAsync(
                CancellationToken.None);
            return CancelResponse(
                "AUTH_REQUIRED",
                Error(
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
            return CancelResponse(
                "OUTCOME_UNKNOWN",
                Error(
                    "ORDER_CANCEL_OUTCOME_UNKNOWN",
                    "Pending-order cancellation could not be confirmed. Refresh purchases before trying another order action.",
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

    private static string LocalStatus(string status) =>
        status switch
        {
            "account_forbidden" => "FORBIDDEN",
            "order_not_found" => "NOT_FOUND",
            "account_not_active" => "ACCOUNT_NOT_ACTIVE",
            "checkout_creation_in_progress" =>
                "CHECKOUT_CREATION_IN_PROGRESS",
            "legal_acceptance_required" =>
                "LEGAL_ACCEPTANCE_REQUIRED",
            "legal_reacceptance_required" =>
                "LEGAL_REACCEPTANCE_REQUIRED",
            "invalid_input" => "INVALID_INPUT",
            _ => "FAILED",
        };

    private static string ContinueFailureMessage(
        string status) =>
        status switch
        {
            "account_forbidden" =>
                "The selected BKE account role cannot continue pending orders.",
            "order_not_found" =>
                "This pending order is no longer available.",
            "account_not_active" =>
                "Pending orders cannot be continued while the selected BKE account is inactive.",
            "checkout_creation_in_progress" =>
                "Checkout creation is already in progress. Refresh purchases before trying again.",
            "legal_acceptance_required" =>
                "Current BKE Legal documents must be accepted before the pending order can continue.",
            "legal_reacceptance_required" =>
                "Updated BKE Legal documents must be accepted before the pending order can continue.",
            "rate_limited" =>
                "Pending-order continuation is temporarily rate limited.",
            "invalid_input" =>
                "The pending-order continuation request is invalid.",
            _ =>
                "BKE could not continue the pending order.",
        };

    private static string CancelFailureMessage(
        string status) =>
        status switch
        {
            "account_forbidden" =>
                "The selected BKE account role cannot cancel pending orders.",
            "order_not_found" =>
                "This pending order is no longer available.",
            "account_not_active" =>
                "Pending orders cannot be cancelled while the selected BKE account is inactive.",
            "legal_acceptance_required" =>
                "Current BKE Legal documents must be accepted before the pending order can be cancelled.",
            "legal_reacceptance_required" =>
                "Updated BKE Legal documents must be accepted before the pending order can be cancelled.",
            "rate_limited" =>
                "Pending-order cancellation is temporarily rate limited.",
            "invalid_input" =>
                "The pending-order cancellation request is invalid.",
            _ =>
                "BKE could not cancel the pending order.",
        };

    private static AccountPendingOrderContinueResponse
        ContinueResponse(
            string status,
            string? checkoutUrl = null,
            AccountPendingOrderError? error = null) =>
        new(
            LocalAgentContract.AccountPendingOrdersCapabilityId,
            LocalAgentContract.AccountPendingOrdersContractVersion,
            status,
            checkoutUrl,
            error);

    private static AccountPendingOrderCancelResponse
        CancelResponse(
            string status,
            AccountPendingOrderError? error = null) =>
        new(
            LocalAgentContract.AccountPendingOrdersCapabilityId,
            LocalAgentContract.AccountPendingOrdersContractVersion,
            status,
            error);

    private static AccountPendingOrderError Error(
        string code,
        string message,
        bool retryable) =>
        new(code, message, retryable);
}
