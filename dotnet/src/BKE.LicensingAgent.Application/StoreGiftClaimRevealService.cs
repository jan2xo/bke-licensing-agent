using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Application;

public interface IStoreGiftClaimRevealRemote
{
    Task<RemoteStoreGiftClaimRevealResult> RevealAsync(
        string accessToken,
        string correlationId,
        CancellationToken cancellationToken);
}

public interface IStoreGiftClaimRevealService
{
    Task<StoreGiftClaimRevealResponse> RevealAsync(
        StoreGiftClaimRevealRequest request,
        CancellationToken cancellationToken);
}

public sealed record RemoteStoreGiftClaimRevealResult(
    string Status,
    string CorrelationId,
    string? OrderId = null,
    string? ClaimCodeId = null,
    string? ClaimCode = null,
    string? ErrorCode = null);

public sealed class StoreGiftClaimRevealService : IStoreGiftClaimRevealService
{
    private readonly IAccountSessionService _accountSession;
    private readonly IAccountSessionSecretStore _secretStore;
    private readonly IStoreGiftClaimRevealRemote _remote;

    public StoreGiftClaimRevealService(
        IAccountSessionService accountSession,
        IAccountSessionSecretStore secretStore,
        IStoreGiftClaimRevealRemote remote)
    {
        _accountSession = accountSession;
        _secretStore = secretStore;
        _remote = remote;
    }

    public async Task<StoreGiftClaimRevealResponse> RevealAsync(
        StoreGiftClaimRevealRequest request,
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
                        "Sign in with the BKE account that created this gift checkout before revealing its Claim Code.",
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
                    "The BKE account session is not available to recover this gift Claim Code.",
                    false));
        }

        RemoteStoreGiftClaimRevealResult result;
        try
        {
            result = await _remote.RevealAsync(
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
                    "GIFT_CLAIM_REVEAL_UNAVAILABLE",
                    "The gift Claim Code could not be verified. This reveal check may be retried.",
                    true));
        }
        catch (InvalidDataException)
        {
            return Response(
                "FAILED",
                request.CorrelationId,
                error: Error(
                    "INVALID_REMOTE_RESPONSE",
                    "Gift Claim Code authority returned an invalid response.",
                    false));
        }

        if (result.CorrelationId != request.CorrelationId)
        {
            return Response(
                "FAILED",
                request.CorrelationId,
                error: Error(
                    "CORRELATION_MISMATCH",
                    "Gift Claim Code authority returned a mismatched correlation identifier.",
                    false));
        }

        return result.Status switch
        {
            "available" when
                !string.IsNullOrWhiteSpace(result.OrderId) &&
                !string.IsNullOrWhiteSpace(result.ClaimCodeId) &&
                !string.IsNullOrWhiteSpace(result.ClaimCode) =>
                Response(
                    "AVAILABLE",
                    request.CorrelationId,
                    result.OrderId,
                    result.ClaimCodeId,
                    result.ClaimCode),
            "available" =>
                Response(
                    "FAILED",
                    request.CorrelationId,
                    error: Error(
                        "INVALID_REMOTE_RESPONSE",
                        "Gift Claim Code authority omitted required reveal fields.",
                        false)),
            "fulfillment_pending" =>
                Response(
                    "PENDING",
                    request.CorrelationId,
                    result.OrderId,
                    error: Error(
                        "FULFILLMENT_PENDING",
                        "Payment is settled but the gift Claim Code has not finished materializing yet.",
                        true)),
            "not_ready" =>
                Response(
                    "PENDING",
                    request.CorrelationId,
                    result.OrderId,
                    error: Error(
                        "PAYMENT_NOT_SETTLED",
                        "The gift checkout is not settled yet.",
                        true)),
            "not_found" =>
                Response(
                    "NOT_FOUND",
                    request.CorrelationId,
                    error: Error(
                        "GIFT_CHECKOUT_NOT_FOUND",
                        "No gift checkout is available for this correlation in the current BKE account session.",
                        false)),
            "cancelled" =>
                Response(
                    "CANCELLED",
                    request.CorrelationId,
                    result.OrderId,
                    error: Error(
                        "GIFT_CHECKOUT_CANCELLED",
                        "The gift checkout was cancelled.",
                        false)),
            "claim_code_already_used" =>
                Response(
                    "ALREADY_USED",
                    request.CorrelationId,
                    result.OrderId,
                    error: Error(
                        "CLAIM_CODE_ALREADY_USED",
                        "The gift Claim Code has already been redeemed.",
                        false)),
            "claim_code_revoked" =>
                Response(
                    "REVOKED",
                    request.CorrelationId,
                    result.OrderId,
                    error: Error(
                        "CLAIM_CODE_REVOKED",
                        "The gift Claim Code has been revoked.",
                        false)),
            "claim_code_expired" =>
                Response(
                    "EXPIRED",
                    request.CorrelationId,
                    result.OrderId,
                    error: Error(
                        "CLAIM_CODE_EXPIRED",
                        "The gift Claim Code has expired.",
                        false)),
            "claim_code_not_found" =>
                Response(
                    "FAILED",
                    request.CorrelationId,
                    result.OrderId,
                    error: Error(
                        "CLAIM_CODE_NOT_FOUND",
                        "Gift fulfillment exists but its Claim Code cannot be found.",
                        false)),
            "account_forbidden" or "FORBIDDEN" =>
                Response(
                    "ACCOUNT_FORBIDDEN",
                    request.CorrelationId,
                    result.OrderId,
                    error: Error(
                        "ACCOUNT_FORBIDDEN",
                        "This BKE account cannot reveal the gift Claim Code.",
                        false)),
            "account_not_found" or "account_not_active" or
            "suspended_account" or "closed_account" =>
                Response(
                    "ACCOUNT_UNAVAILABLE",
                    request.CorrelationId,
                    result.OrderId,
                    error: Error(
                        "ACCOUNT_UNAVAILABLE",
                        "The authenticated BKE account cannot reveal this gift Claim Code.",
                        false)),
            "NOT_GIFT_ORDER" =>
                Response(
                    "NOT_GIFT_ORDER",
                    request.CorrelationId,
                    result.OrderId,
                    error: Error(
                        "NOT_GIFT_ORDER",
                        "The recovered checkout is not a GIFT Claim Code order.",
                        false)),
            "RATE_LIMITED" or "COMMERCE_UNAVAILABLE" or "CLAIM_CODE_UNAVAILABLE" =>
                Response(
                    "UNAVAILABLE",
                    request.CorrelationId,
                    result.OrderId,
                    error: Error(
                        result.Status,
                        "Gift Claim Code authority is temporarily unavailable.",
                        true)),
            "CLAIM_CODE_CARDINALITY_CONFLICT" =>
                Response(
                    "FAILED",
                    request.CorrelationId,
                    result.OrderId,
                    error: Error(
                        result.Status,
                        "Gift fulfillment state is inconsistent and cannot be trusted.",
                        false)),
            _ when !string.IsNullOrWhiteSpace(result.ErrorCode) =>
                Response(
                    "FAILED",
                    request.CorrelationId,
                    result.OrderId,
                    error: Error(
                        result.ErrorCode,
                        "Gift Claim Code reveal failed closed.",
                        false)),
            _ => throw new InvalidDataException(
                "Unknown gift Claim Code reveal authority status."),
        };
    }

    private static StoreGiftClaimRevealResponse Response(
        string status,
        string correlationId,
        string? orderId = null,
        string? claimCodeId = null,
        string? claimCode = null,
        StoreGiftClaimRevealError? error = null) =>
        new(
            LocalAgentContract.StoreGiftClaimRevealCapabilityId,
            LocalAgentContract.StoreGiftClaimRevealContractVersion,
            status,
            correlationId,
            orderId,
            claimCodeId,
            claimCode,
            error);

    private static StoreGiftClaimRevealError Error(
        string code,
        string message,
        bool retryable) =>
        new(code, message, retryable);
}
