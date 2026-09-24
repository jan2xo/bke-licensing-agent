using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Application;

public interface IStoreCheckoutStartRemote
{
    Task<RemoteStoreCheckoutStartResult> StartAsync(
        string accessToken,
        StoreCheckoutStartRequest request,
        CancellationToken cancellationToken);
}

public interface IStoreCheckoutStartService
{
    Task<StoreCheckoutStartResponse> StartAsync(
        StoreCheckoutStartRequest request,
        CancellationToken cancellationToken);
}

public sealed record RemoteStoreCheckoutStartResult(
    string Status,
    string CorrelationId,
    string? OrderId,
    string? CheckoutUrl,
    bool? Complimentary,
    string? ErrorCode);

public sealed class StoreCheckoutStartService : IStoreCheckoutStartService
{
    private readonly IAccountSessionService _accountSession;
    private readonly IAccountSessionSecretStore _secretStore;
    private readonly IStoreCheckoutStartRemote _remote;

    public StoreCheckoutStartService(
        IAccountSessionService accountSession,
        IAccountSessionSecretStore secretStore,
        IStoreCheckoutStartRemote remote)
    {
        _accountSession = accountSession;
        _secretStore = secretStore;
        _remote = remote;
    }

    public async Task<StoreCheckoutStartResponse> StartAsync(
        StoreCheckoutStartRequest request,
        CancellationToken cancellationToken)
    {
        var session = await _accountSession.StatusAsync(
            new AccountSessionStatusRequest(request.CorrelationId),
            cancellationToken);

        if (session.Status != "AUTHENTICATED")
        {
            return Response(
                "AUTH_REQUIRED",
                request.CorrelationId,
                null,
                null,
                null,
                session.Error is null
                    ? Error(
                        "AUTH_REQUIRED",
                        "Sign in with a BKE account before starting checkout.")
                    : Error(
                        session.Error.Code,
                        session.Error.Message));
        }

        var stored = await _secretStore.ReadAsync(cancellationToken);
        if (stored is not ActiveAccountSessionState active)
        {
            return Response(
                "AUTH_REQUIRED",
                request.CorrelationId,
                null,
                null,
                null,
                Error(
                    "SESSION_STATE_UNAVAILABLE",
                    "The BKE account session is not available to checkout."));
        }

        RemoteStoreCheckoutStartResult result;
        try
        {
            result = await _remote.StartAsync(
                active.AccessToken,
                request,
                cancellationToken);
        }
        catch (UnauthorizedAccessException)
        {
            await _secretStore.ClearAsync(cancellationToken);
            return Response(
                "AUTH_REQUIRED",
                request.CorrelationId,
                null,
                null,
                null,
                Error(
                    "SESSION_INVALID",
                    "The BKE account session is no longer valid. Sign in again."));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception error) when (
            error is HttpRequestException or TaskCanceledException)
        {
            return Response(
                "RESULT_UNKNOWN",
                request.CorrelationId,
                null,
                null,
                null,
                Error(
                    "CHECKOUT_RESULT_UNKNOWN",
                    "Checkout may have reached BKE Digital Solutions, but the result could not be confirmed. Do not retry automatically."));
        }
        catch (InvalidDataException)
        {
            return Response(
                "FAILED",
                request.CorrelationId,
                null,
                null,
                null,
                Error(
                    "INVALID_REMOTE_RESPONSE",
                    "Checkout authority returned an invalid response."));
        }

        if (result.CorrelationId != request.CorrelationId)
        {
            return Response(
                "FAILED",
                request.CorrelationId,
                null,
                null,
                null,
                Error(
                    "CORRELATION_MISMATCH",
                    "Checkout authority returned a mismatched correlation identifier."));
        }

        if (result.Status == "ready")
        {
            if (
                string.IsNullOrWhiteSpace(result.OrderId) ||
                string.IsNullOrWhiteSpace(result.CheckoutUrl) ||
                result.Complimentary is null)
            {
                return Response(
                    "FAILED",
                    request.CorrelationId,
                    null,
                    null,
                    null,
                    Error(
                        "INVALID_REMOTE_RESPONSE",
                        "Checkout authority omitted required checkout result fields."));
            }

            return Response(
                "READY",
                request.CorrelationId,
                result.OrderId,
                result.CheckoutUrl,
                result.Complimentary,
                null);
        }

        var code = result.ErrorCode ?? "CHECKOUT_FAILED";
        return code switch
        {
            "LEGAL_REACCEPTANCE_REQUIRED" =>
                Response(
                    "LEGAL_REACCEPTANCE_REQUIRED",
                    request.CorrelationId,
                    null,
                    null,
                    null,
                    Error(code, "Current BKE Legal documents must be accepted before checkout can continue.")),
            "LEGAL_ACCEPTANCE_REQUIRED" =>
                Response(
                    "LEGAL_ACCEPTANCE_REQUIRED",
                    request.CorrelationId,
                    null,
                    null,
                    null,
                    Error(code, "The selected purchase requires Legal acceptance.")),
            "GIFT_CHECKOUT_DISABLED" =>
                Response(
                    "GIFT_CHECKOUT_DISABLED",
                    request.CorrelationId,
                    null,
                    null,
                    null,
                    Error(code, "Gift Claim Code purchases are not enabled in this environment.")),
            "INVALID_PURCHASE_PLAN" or
            "INVALID_CATALOG_PRODUCT" or
            "INVALID_CATALOG_EDITION" or
            "OFFER_NOT_AVAILABLE" =>
                Response(
                    "PLAN_NOT_AVAILABLE",
                    request.CorrelationId,
                    null,
                    null,
                    null,
                    Error(code, "The selected purchase is no longer available. Refresh the Store.")),
            "FORBIDDEN" or "ACCOUNT_ROLE_FORBIDDEN" =>
                Response(
                    "ACCOUNT_FORBIDDEN",
                    request.CorrelationId,
                    null,
                    null,
                    null,
                    Error(code, "This BKE account role cannot make this purchase.")),
            "ACCOUNT_NOT_ACTIVE" or "ACCOUNT_NOT_FOUND" =>
                Response(
                    "ACCOUNT_UNAVAILABLE",
                    request.CorrelationId,
                    null,
                    null,
                    null,
                    Error(code, "The authenticated BKE account is not available for purchases.")),
            "CHECKOUT_CREATION_IN_PROGRESS" =>
                Response(
                    "CHECKOUT_IN_PROGRESS",
                    request.CorrelationId,
                    null,
                    null,
                    null,
                    Error(code, "A checkout creation attempt already exists for this purchase request.")),
            "RATE_LIMITED" =>
                Response(
                    "FAILED",
                    request.CorrelationId,
                    null,
                    null,
                    null,
                    Error(code, "Checkout is temporarily rate limited.")),
            _ =>
                Response(
                    "FAILED",
                    request.CorrelationId,
                    null,
                    null,
                    null,
                    Error(
                        code,
                        "Checkout could not be started. No automatic retry will be attempted.")),
        };
    }

    private static StoreCheckoutStartResponse Response(
        string status,
        string correlationId,
        string? orderId,
        string? checkoutUrl,
        bool? complimentary,
        StoreCheckoutStartError? error) =>
        new(
            LocalAgentContract.StoreCheckoutStartCapabilityId,
            LocalAgentContract.StoreCheckoutStartContractVersion,
            status,
            correlationId,
            orderId,
            checkoutUrl,
            complimentary,
            error);

    private static StoreCheckoutStartError Error(
        string code,
        string message) =>
        new(code, message, false);
}
