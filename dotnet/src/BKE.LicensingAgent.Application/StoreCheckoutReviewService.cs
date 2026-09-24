using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Application;

public interface IStoreCheckoutReviewRemote
{
    Task<RemoteStoreCheckoutReviewResult> ReviewAsync(
        string accessToken,
        string purchasePlanId,
        CancellationToken cancellationToken);
}

public interface IStoreCheckoutReviewService
{
    Task<StoreCheckoutReviewResponse> ReviewAsync(
        StoreCheckoutReviewRequest request,
        CancellationToken cancellationToken);
}

public sealed record RemoteStoreCheckoutReviewResult(
    string Status,
    IReadOnlyList<string> PurchaseModes,
    StoreCheckoutReviewProduct? Product,
    StoreCheckoutReviewEdition? Edition,
    StoreCatalogPlan? Plan,
    IReadOnlyList<StoreCheckoutReviewLegalDocument> LegalDocuments,
    IReadOnlyList<StoreCheckoutReviewPendingLegalDocument> PendingLegal);

public sealed class StoreCheckoutReviewService : IStoreCheckoutReviewService
{
    private readonly IAccountSessionService _accountSession;
    private readonly IAccountSessionSecretStore _secretStore;
    private readonly IStoreCheckoutReviewRemote _remote;

    public StoreCheckoutReviewService(
        IAccountSessionService accountSession,
        IAccountSessionSecretStore secretStore,
        IStoreCheckoutReviewRemote remote)
    {
        _accountSession = accountSession;
        _secretStore = secretStore;
        _remote = remote;
    }

    public async Task<StoreCheckoutReviewResponse> ReviewAsync(
        StoreCheckoutReviewRequest request,
        CancellationToken cancellationToken)
    {
        var session = await _accountSession.StatusAsync(
            new AccountSessionStatusRequest(request.CorrelationId),
            cancellationToken);

        if (session.Status != "AUTHENTICATED")
        {
            return Response(
                "AUTH_REQUIRED",
                [],
                null,
                null,
                null,
                [],
                [],
                session.Error is null
                    ? Error(
                        "AUTH_REQUIRED",
                        "Sign in with a BKE account before reviewing a purchase.",
                        false)
                    : Error(
                        session.Error.Code,
                        session.Error.Message,
                        session.Error.Retryable));
        }

        var stored = await _secretStore.ReadAsync(cancellationToken);
        if (stored is not ActiveAccountSessionState active)
        {
            return Response(
                "AUTH_REQUIRED",
                [],
                null,
                null,
                null,
                [],
                [],
                Error(
                    "SESSION_STATE_UNAVAILABLE",
                    "The BKE account session is not available to purchase review.",
                    false));
        }

        RemoteStoreCheckoutReviewResult result;
        try
        {
            result = await _remote.ReviewAsync(
                active.AccessToken,
                request.PurchasePlanId,
                cancellationToken);
        }
        catch (UnauthorizedAccessException)
        {
            await _secretStore.ClearAsync(cancellationToken);
            return Response(
                "AUTH_REQUIRED",
                [],
                null,
                null,
                null,
                [],
                [],
                Error(
                    "SESSION_INVALID",
                    "The BKE account session is no longer valid. Sign in again.",
                    false));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (HttpRequestException)
        {
            return Response(
                "FAILED",
                [],
                null,
                null,
                null,
                [],
                [],
                Error(
                    "REMOTE_UNAVAILABLE",
                    "Purchase review is temporarily unavailable.",
                    true));
        }
        catch (InvalidDataException)
        {
            return Response(
                "FAILED",
                [],
                null,
                null,
                null,
                [],
                [],
                Error(
                    "INVALID_REMOTE_RESPONSE",
                    "Purchase review returned an invalid response.",
                    false));
        }

        return result.Status switch
        {
            "ready" when
                result.Product is not null &&
                result.Edition is not null &&
                result.Plan is not null =>
                Response(
                    "READY",
                    result.PurchaseModes,
                    result.Product,
                    result.Edition,
                    result.Plan,
                    result.LegalDocuments,
                    [],
                    null),
            "plan_not_available" =>
                Response(
                    "PLAN_NOT_AVAILABLE",
                    [],
                    null,
                    null,
                    null,
                    [],
                    [],
                    Error(
                        "PLAN_NOT_AVAILABLE",
                        "The selected purchase plan is not available.",
                        false)),
            "account_forbidden" =>
                Response(
                    "ACCOUNT_FORBIDDEN",
                    [],
                    null,
                    null,
                    null,
                    [],
                    [],
                    Error(
                        "ACCOUNT_FORBIDDEN",
                        "This BKE account role cannot make purchases.",
                        false)),
            "account_not_found" or "account_not_active" =>
                Response(
                    "ACCOUNT_UNAVAILABLE",
                    [],
                    null,
                    null,
                    null,
                    [],
                    [],
                    Error(
                        "ACCOUNT_UNAVAILABLE",
                        "The authenticated BKE account is not available for purchases.",
                        false)),
            "legal_reacceptance_required" =>
                Response(
                    "LEGAL_REACCEPTANCE_REQUIRED",
                    [],
                    null,
                    null,
                    null,
                    [],
                    result.PendingLegal,
                    Error(
                        "LEGAL_REACCEPTANCE_REQUIRED",
                        "Current BKE Legal documents must be accepted before purchase review can continue.",
                        false)),
            "legal_acceptance_required" =>
                Response(
                    "LEGAL_ACCEPTANCE_REQUIRED",
                    [],
                    null,
                    null,
                    null,
                    [],
                    [],
                    Error(
                        "LEGAL_ACCEPTANCE_REQUIRED",
                        "The selected purchase requires Legal acceptance.",
                        false)),
            "rate_limited" =>
                Response(
                    "FAILED",
                    [],
                    null,
                    null,
                    null,
                    [],
                    [],
                    Error(
                        "RATE_LIMITED",
                        "Purchase review is temporarily rate limited.",
                        true)),
            "identity_unavailable" or
            "account_unavailable" or
            "legal_unavailable" or
            "commerce_unavailable" or
            "catalog_unavailable" =>
                Response(
                    "FAILED",
                    [],
                    null,
                    null,
                    null,
                    [],
                    [],
                    Error(
                        result.Status.ToUpperInvariant(),
                        "A required BKE purchase-review authority is temporarily unavailable.",
                        true)),
            _ => throw new InvalidDataException(
                "Unknown purchase-review authority status."),
        };
    }

    private static StoreCheckoutReviewResponse Response(
        string status,
        IReadOnlyList<string> purchaseModes,
        StoreCheckoutReviewProduct? product,
        StoreCheckoutReviewEdition? edition,
        StoreCatalogPlan? plan,
        IReadOnlyList<StoreCheckoutReviewLegalDocument> legalDocuments,
        IReadOnlyList<StoreCheckoutReviewPendingLegalDocument> pendingLegal,
        StoreCheckoutReviewError? error) =>
        new(
            LocalAgentContract.StoreCheckoutReviewCapabilityId,
            LocalAgentContract.StoreCheckoutReviewContractVersion,
            status,
            purchaseModes,
            product,
            edition,
            plan,
            legalDocuments,
            pendingLegal,
            error);

    private static StoreCheckoutReviewError Error(
        string code,
        string message,
        bool retryable) =>
        new(code, message, retryable);
}
