using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Application;

public interface ISoftwareCatalogRemote
{
    Task<IReadOnlyList<RemoteSoftwareCatalogItem>> GetAsync(
        string accessToken,
        CancellationToken cancellationToken);
}

public interface ILocalProductInventory
{
    Task<IReadOnlyDictionary<string, LocalInstalledProduct>> ReadAsync(
        CancellationToken cancellationToken);
}

public sealed record RemoteSoftwareCatalogItem(
    string ProductId,
    string DisplayName,
    string Summary,
    string? ExecutionType,
    bool Entitled,
    bool Installable,
    string? LatestVersion);

public sealed record LocalInstalledProduct(
    string ProductId,
    string Version,
    string InstallProvenance = "LEGACY_UNKNOWN",
    string UninstallStrategy = "NONE",
    string? UninstallExecutable = null,
    IReadOnlyList<string>? UninstallArguments = null);

public sealed class SoftwareCatalogService : ISoftwareCatalogService
{
    private readonly IAccountSessionService _accountSession;
    private readonly IAccountSessionSecretStore _secretStore;
    private readonly ISoftwareCatalogRemote _remote;
    private readonly ILocalProductInventory _inventory;

    public SoftwareCatalogService(
        IAccountSessionService accountSession,
        IAccountSessionSecretStore secretStore,
        ISoftwareCatalogRemote remote,
        ILocalProductInventory inventory)
    {
        _accountSession = accountSession;
        _secretStore = secretStore;
        _remote = remote;
        _inventory = inventory;
    }

    public async Task<SoftwareCatalogResponse> GetAsync(
        SoftwareCatalogRequest request,
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
                session.Error is null
                    ? null
                    : Error(session.Error.Code, session.Error.Message, session.Error.Retryable));
        }

        var stored = await _secretStore.ReadAsync(cancellationToken);
        if (stored is not ActiveAccountSessionState active)
        {
            return Response(
                "AUTH_REQUIRED",
                [],
                Error(
                    "SESSION_STATE_UNAVAILABLE",
                    "The BKE account session is not available to the local catalog provider.",
                    false));
        }

        IReadOnlyList<RemoteSoftwareCatalogItem> remoteItems;
        try
        {
            remoteItems = await _remote.GetAsync(active.AccessToken, cancellationToken);
        }
        catch (UnauthorizedAccessException)
        {
            await _secretStore.ClearAsync(cancellationToken);
            return Response(
                "AUTH_REQUIRED",
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
                Error(
                    "REMOTE_UNAVAILABLE",
                    "The BKE software catalog is temporarily unavailable.",
                    true));
        }
        catch (InvalidDataException)
        {
            return Response(
                "FAILED",
                [],
                Error(
                    "INVALID_REMOTE_RESPONSE",
                    "The BKE software catalog returned an invalid response.",
                    false));
        }

        IReadOnlyDictionary<string, LocalInstalledProduct> installed;
        try
        {
            installed = await _inventory.ReadAsync(cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return Response(
                "FAILED",
                [],
                Error(
                    "LOCAL_INVENTORY_UNAVAILABLE",
                    "The local BKE software inventory is unavailable.",
                    true));
        }

        var items = remoteItems
            .Select(item => Merge(item, installed))
            .OrderBy(item => item.DisplayName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(item => item.ProductId, StringComparer.Ordinal)
            .ToArray();

        return Response("READY", items, null);
    }

    private static SoftwareCatalogItem Merge(
        RemoteSoftwareCatalogItem remote,
        IReadOnlyDictionary<string, LocalInstalledProduct> installed)
    {
        installed.TryGetValue(remote.ProductId, out var local);
        var installedVersion = local?.Version;
        var state = ResolveState(remote, installedVersion);

        return new SoftwareCatalogItem(
            remote.ProductId,
            remote.DisplayName,
            remote.Summary,
            remote.ExecutionType,
            remote.Entitled,
            remote.Installable,
            state,
            remote.LatestVersion,
            installedVersion);
    }

    private static string ResolveState(
        RemoteSoftwareCatalogItem remote,
        string? installedVersion)
    {
        if (!string.IsNullOrWhiteSpace(installedVersion))
        {
            if (!remote.Entitled)
            {
                return "INSTALLED_NOT_ENTITLED";
            }

            if (!string.IsNullOrWhiteSpace(remote.LatestVersion) &&
                !string.Equals(installedVersion, remote.LatestVersion, StringComparison.Ordinal))
            {
                return "UPDATE_AVAILABLE";
            }

            return "INSTALLED";
        }

        if (!remote.Entitled)
        {
            return "NOT_ENTITLED";
        }

        if (remote.ExecutionType is null)
        {
            return "POLICY_UNASSIGNED";
        }

        if (remote.LatestVersion is null)
        {
            return "RELEASE_UNAVAILABLE";
        }

        return remote.Installable
            ? "INSTALLABLE"
            : "UNAVAILABLE";
    }

    private static SoftwareCatalogResponse Response(
        string status,
        IReadOnlyList<SoftwareCatalogItem> items,
        SoftwareCatalogError? error) =>
        new(
            LocalAgentContract.SoftwareCatalogCapabilityId,
            LocalAgentContract.SoftwareCatalogContractVersion,
            status,
            items,
            error);

    private static SoftwareCatalogError Error(
        string code,
        string message,
        bool retryable) =>
        new(code, message, retryable);
}
