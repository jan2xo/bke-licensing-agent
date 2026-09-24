using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Application;

public interface IStoreCheckoutStatusRemote
{
    Task<RemoteStoreCheckoutStatusResult> CheckAsync(
        string accessToken,
        string correlationId,
        CancellationToken cancellationToken);
}

public interface IStoreCheckoutStatusService
{
    Task<StoreCheckoutStatusResponse> CheckAsync(
        StoreCheckoutStatusRequest request,
        CancellationToken cancellationToken);
}

public sealed record RemoteStoreCheckoutStatusResult(
    string Status,
    string CorrelationId,
    string? OrderId,
    string? OrderNumber,
    string? OrderStatus,
    string? FulfillmentMode,
    string? PaymentStatus,
    string? CheckoutUrl,
    string? PaidAt,
    string? ErrorCode);

public sealed class StoreCheckoutStatusService : IStoreCheckoutStatusService
{
    private readonly IAccountSessionService _accountSession;
    private readonly IAccountSessionSecretStore _secretStore;
    private readonly IStoreCheckoutStatusRemote _remote;

    public StoreCheckoutStatusService(
        IAccountSessionService accountSession,
        IAccountSessionSecretStore secretStore,
        IStoreCheckoutStatusRemote remote)
    {
        _accountSession = accountSession;
        _secretStore = secretStore;
        _remote = remote;
    }

    public async Task<StoreCheckoutStatusResponse> CheckAsync(
        StoreCheckoutStatusRequest request,
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
                error: session.Error is null
                    ? Error(
                        "AUTH_REQUIRED",
                        "Sign in with a BKE account before checking checkout status.",
                        false)
                    : Error(
                        session.Error.Code,
                        session.Error.Message,
                        false));
        }

        var stored = await _secretStore.ReadAsync(cancellationToken);
        if (stored is not ActiveAccountSessionState active)
        {
            return Response(
                "AUTH_REQUIRED",
                request.CorrelationId,
                error: Error(
                    "SESSION_STATE_UNAVAILABLE",
                    "The BKE account session is not available to recover checkout status.",
                    false));
        }

        RemoteStoreCheckoutStatusResult result;
        try
        {
            result = await _remote.CheckAsync(
                active.AccessToken,
                request.CorrelationId,
                cancellationToken);
        }
        catch (UnauthorizedAccessException)
        {
            await _secretStore.ClearAsync(cancellationToken);
            return Response(
                "AUTH_REQUIRED",
                request.CorrelationId,
                error: Error(
                    "SESSION_INVALID",
                    "The BKE account session is no longer valid. Sign in again.",
                    false));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception error) when (
            error is HttpRequestException or TaskCanceledException)
        {
            return Response(
                "UNAVAILABLE",
                request.CorrelationId,
                error: Error(
                    "CHECKOUT_STATUS_UNAVAILABLE",
                    "Checkout status could not be verified. This read-only check may be retried.",
                    true));
        }
        catch (InvalidDataException)
        {
            return Response(
                "FAILED",
                request.CorrelationId,
                error: Error(
                    "INVALID_REMOTE_RESPONSE",
                    "Checkout-status authority returned an invalid response.",
                    false));
        }

        if (result.CorrelationId != request.CorrelationId)
        {
            return Response(
                "FAILED",
                request.CorrelationId,
                error: Error(
                    "CORRELATION_MISMATCH",
                    "Checkout-status authority returned a mismatched correlation identifier.",
                    false));
        }

        if (result.Status == "not_found")
        {
            return Response(
                "NOT_FOUND",
                request.CorrelationId);
        }

        if (result.Status == "found")
        {
            if (
                string.IsNullOrWhiteSpace(result.OrderId) ||
                string.IsNullOrWhiteSpace(result.OrderNumber) ||
                string.IsNullOrWhiteSpace(result.OrderStatus) ||
                string.IsNullOrWhiteSpace(result.FulfillmentMode) ||
                string.IsNullOrWhiteSpace(result.PaymentStatus))
            {
                return Response(
                    "FAILED",
                    request.CorrelationId,
                    error: Error(
                        "INVALID_REMOTE_RESPONSE",
                        "Checkout-status authority omitted required recovery fields.",
                        false));
            }

            return Response(
                "FOUND",
                request.CorrelationId,
                result.OrderId,
                result.OrderNumber,
                result.OrderStatus,
                result.FulfillmentMode,
                result.PaymentStatus,
                result.CheckoutUrl,
                result.PaidAt,
                null);
        }

        var code = result.ErrorCode ?? "CHECKOUT_STATUS_FAILED";
        return code switch
        {
            "RATE_LIMITED" =>
                Response(
                    "UNAVAILABLE",
                    request.CorrelationId,
                    error: Error(
                        code,
                        "Checkout-status verification is temporarily rate limited.",
                        true)),
            "IDENTITY_UNAVAILABLE" or
            "COMMERCE_UNAVAILABLE" or
            "PAYMENTS_UNAVAILABLE" =>
                Response(
                    "UNAVAILABLE",
                    request.CorrelationId,
                    error: Error(
                        code,
                        "Checkout-status authority is temporarily unavailable.",
                        true)),
            "FORBIDDEN" =>
                Response(
                    "ACCOUNT_FORBIDDEN",
                    request.CorrelationId,
                    error: Error(
                        code,
                        "This BKE account cannot access the requested checkout state.",
                        false)),
            "CHECKOUT_STATE_CONFLICT" =>
                Response(
                    "FAILED",
                    request.CorrelationId,
                    error: Error(
                        code,
                        "Checkout recovery state is inconsistent and cannot be trusted.",
                        false)),
            _ =>
                Response(
                    "FAILED",
                    request.CorrelationId,
                    error: Error(
                        code,
                        "Checkout status could not be recovered.",
                        false)),
        };
    }

    private static StoreCheckoutStatusResponse Response(
        string status,
        string correlationId,
        string? orderId = null,
        string? orderNumber = null,
        string? orderStatus = null,
        string? fulfillmentMode = null,
        string? paymentStatus = null,
        string? checkoutUrl = null,
        string? paidAt = null,
        StoreCheckoutStatusError? error = null) =>
        new(
            LocalAgentContract.StoreCheckoutStatusCapabilityId,
            LocalAgentContract.StoreCheckoutStatusContractVersion,
            status,
            correlationId,
            orderId,
            orderNumber,
            orderStatus,
            fulfillmentMode,
            paymentStatus,
            checkoutUrl,
            paidAt,
            error);

    private static StoreCheckoutStatusError Error(
        string code,
        string message,
        bool retryable) =>
        new(code, message, retryable);
}
