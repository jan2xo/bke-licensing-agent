using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Application;

public interface IStoreCatalogRemote
{
    Task<RemoteStoreCatalogSnapshot> GetAsync(
        string accessToken,
        CancellationToken cancellationToken);
}

public interface IStoreCatalogService
{
    Task<StoreCatalogResponse> GetAsync(
        StoreCatalogRequest request,
        CancellationToken cancellationToken);
}

public sealed record RemoteStoreCatalogSnapshot(
    bool GiftCheckoutEnabled,
    IReadOnlyList<StoreCatalogProduct> Products);

public sealed class StoreCatalogService : IStoreCatalogService
{
    private readonly IAccountSessionService _accountSession;
    private readonly IAccountSessionSecretStore _secretStore;
    private readonly IStoreCatalogRemote _remote;

    public StoreCatalogService(
        IAccountSessionService accountSession,
        IAccountSessionSecretStore secretStore,
        IStoreCatalogRemote remote)
    {
        _accountSession = accountSession;
        _secretStore = secretStore;
        _remote = remote;
    }

    public async Task<StoreCatalogResponse> GetAsync(
        StoreCatalogRequest request,
        CancellationToken cancellationToken)
    {
        var session = await _accountSession.StatusAsync(
            new AccountSessionStatusRequest(request.CorrelationId),
            cancellationToken);

        if (session.Status != "AUTHENTICATED")
        {
            return Response(
                "AUTH_REQUIRED",
                false,
                [],
                session.Error is null
                    ? Error(
                        "AUTH_REQUIRED",
                        "Sign in with a BKE account before loading the Store.",
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
                false,
                [],
                Error(
                    "SESSION_STATE_UNAVAILABLE",
                    "The BKE account session is not available to the Store provider.",
                    false));
        }

        try
        {
            var snapshot = await _remote.GetAsync(
                active.AccessToken,
                cancellationToken);
            return Response(
                "READY",
                snapshot.GiftCheckoutEnabled,
                snapshot.Products,
                null);
        }
        catch (UnauthorizedAccessException)
        {
            await _secretStore.ClearAsync(cancellationToken);
            return Response(
                "AUTH_REQUIRED",
                false,
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
                false,
                [],
                Error(
                    "REMOTE_UNAVAILABLE",
                    "The BKE Store is temporarily unavailable.",
                    true));
        }
        catch (InvalidDataException)
        {
            return Response(
                "FAILED",
                false,
                [],
                Error(
                    "INVALID_REMOTE_RESPONSE",
                    "The BKE Store returned an invalid response.",
                    false));
        }
    }

    private static StoreCatalogResponse Response(
        string status,
        bool giftCheckoutEnabled,
        IReadOnlyList<StoreCatalogProduct> products,
        StoreCatalogError? error) =>
        new(
            LocalAgentContract.StoreCatalogCapabilityId,
            LocalAgentContract.StoreCatalogContractVersion,
            status,
            giftCheckoutEnabled,
            products,
            error);

    private static StoreCatalogError Error(
        string code,
        string message,
        bool retryable) =>
        new(code, message, retryable);
}
