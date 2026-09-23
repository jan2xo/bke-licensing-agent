using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Application;

public interface IStandaloneUpdateAuthorizationRemote
{
    Task<StandaloneUpdateAuthorizationResult> AuthorizeAsync(
        string accessToken,
        string productId,
        string currentVersion,
        CancellationToken cancellationToken);
}

public interface IStandaloneSoftwareUpdater
{
    Task<StandaloneUpdateResult> UpdateAsync(
        LocalInstalledProduct installed,
        StandaloneUpdateAuthorization authorization,
        CancellationToken cancellationToken);
}

public interface ISoftwareUpdateService
{
    Task<SoftwareUpdateResponse> UpdateAsync(
        SoftwareUpdateRequest request,
        CancellationToken cancellationToken);
}

public sealed record StandaloneUpdateAuthorization(
    string ProductId,
    string CurrentVersion,
    string TargetVersion,
    string Repository,
    string Tag,
    string PolicyJson);

public sealed record StandaloneUpdateAuthorizationResult(
    string Status,
    StandaloneUpdateAuthorization? Authorization = null);

public sealed record StandaloneUpdateResult(
    string Status,
    string Reason,
    bool Retryable);

public sealed class SoftwareUpdateService : ISoftwareUpdateService
{
    private static readonly TimeSpan UpdateStartGuard = TimeSpan.FromMinutes(10);
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly Dictionary<string, DateTimeOffset> _recentStarts = new(StringComparer.Ordinal);
    private readonly IAccountSessionService _accountSession;
    private readonly IAccountSessionSecretStore _secretStore;
    private readonly ILocalProductInventory _inventory;
    private readonly IStandaloneUpdateAuthorizationRemote _remote;
    private readonly IStandaloneSoftwareUpdater _updater;

    public SoftwareUpdateService(
        IAccountSessionService accountSession,
        IAccountSessionSecretStore secretStore,
        ILocalProductInventory inventory,
        IStandaloneUpdateAuthorizationRemote remote,
        IStandaloneSoftwareUpdater updater)
    {
        _accountSession = accountSession;
        _secretStore = secretStore;
        _inventory = inventory;
        _remote = remote;
        _updater = updater;
    }

    public async Task<SoftwareUpdateResponse> UpdateAsync(
        SoftwareUpdateRequest request,
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var session = await _accountSession.StatusAsync(
                new AccountSessionStatusRequest(request.CorrelationId),
                cancellationToken);
            if (session.Status != "AUTHENTICATED")
            {
                return Response("AUTH_REQUIRED", "auth_required",
                    Error(session.Error?.Code ?? "AUTH_REQUIRED",
                        session.Error?.Message ?? "Sign in with a BKE account before updating software.", false));
            }

            var stored = await _secretStore.ReadAsync(cancellationToken);
            if (stored is not ActiveAccountSessionState active)
            {
                return Response("AUTH_REQUIRED", "auth_required",
                    Error("SESSION_STATE_UNAVAILABLE", "The BKE account session is not available to the updater.", false));
            }

            IReadOnlyDictionary<string, LocalInstalledProduct> installed;
            try { installed = await _inventory.ReadAsync(cancellationToken); }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch
            {
                return Response("FAILED", "local_inventory_unavailable",
                    Error("LOCAL_INVENTORY_UNAVAILABLE", "The local BKE software inventory is unavailable.", true));
            }

            if (!installed.TryGetValue(request.ProductId, out var product))
                return Response("NOT_INSTALLED", "not_installed", null);

            if (product.InstallProvenance != "BKE_MANAGED_PACKAGE" ||
                product.UninstallStrategy != "MANAGED_DIRECTORY")
            {
                return Response("FAILED", "unsupported_provenance",
                    Error("UNSUPPORTED_PROVENANCE",
                        "This installed product is not a BKE-managed package and cannot use managed in-place update.", false));
            }

            var now = DateTimeOffset.UtcNow;
            if (_recentStarts.TryGetValue(request.ProductId, out var startedAt))
            {
                if (now - startedAt < UpdateStartGuard)
                    return Response("IN_PROGRESS", "update_in_progress", null);
                _recentStarts.Remove(request.ProductId);
            }

            StandaloneUpdateAuthorizationResult authorization;
            try
            {
                authorization = await _remote.AuthorizeAsync(
                    active.AccessToken, request.ProductId, product.Version, cancellationToken);
            }
            catch (UnauthorizedAccessException)
            {
                await _secretStore.ClearAsync(cancellationToken);
                return Response("AUTH_REQUIRED", "session_invalid",
                    Error("SESSION_INVALID", "The BKE account session is no longer valid. Sign in again.", false));
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (HttpRequestException)
            {
                return Response("FAILED", "authorization_unavailable",
                    Error("AUTHORIZATION_UNAVAILABLE", "BKE update authorization is temporarily unavailable.", true));
            }
            catch (InvalidDataException)
            {
                return Response("FAILED", "invalid_authorization_response",
                    Error("INVALID_AUTHORIZATION_RESPONSE", "BKE update authorization returned an invalid response.", false));
            }

            if (authorization.Status == "UP_TO_DATE")
                return Response("UP_TO_DATE", "up_to_date", null);

            if (authorization.Status != "UPDATE_AVAILABLE" || authorization.Authorization is null)
                return AuthorizationFailure(authorization.Status);

            try
            {
                var result = await _updater.UpdateAsync(product, authorization.Authorization, cancellationToken);
                if (result.Status == "STARTED")
                {
                    _recentStarts[request.ProductId] = DateTimeOffset.UtcNow;
                    return Response("STARTED", result.Reason, null);
                }
                return Response("FAILED", result.Reason,
                    Error(result.Status, UpdateMessage(result.Status), result.Retryable));
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch
            {
                return Response("FAILED", "privileged_update_failed",
                    Error("PRIVILEGED_UPDATE_FAILED", "The BKE Licensing Agent could not start the verified update.", true));
            }
        }
        finally { _gate.Release(); }
    }

    private static SoftwareUpdateResponse AuthorizationFailure(string status) => status switch
    {
        "NOT_ENTITLED" => Response("FAILED", "not_entitled",
            Error("NOT_ENTITLED", "This BKE account is not entitled to update the selected product.", false)),
        "UNSUPPORTED_EXECUTION_TYPE" => Response("FAILED", "unsupported_execution_type",
            Error("UNSUPPORTED_EXECUTION_TYPE", "This product is not a standalone BKE-managed installation.", false)),
        "RELEASE_UNAVAILABLE" => Response("FAILED", "release_unavailable",
            Error("RELEASE_UNAVAILABLE", "No eligible update release is currently available for this machine.", true)),
        "DISTRIBUTION_UNAVAILABLE" => Response("FAILED", "distribution_unavailable",
            Error("DISTRIBUTION_UNAVAILABLE", "This product does not have a configured software release source.", false)),
        "NOT_FOUND" => Response("FAILED", "product_not_found",
            Error("PRODUCT_NOT_FOUND", "The selected BKE product is not available in the catalog.", false)),
        _ => Response("FAILED", "authorization_failed",
            Error("AUTHORIZATION_FAILED", "BKE update authorization failed.", false)),
    };

    private static string UpdateMessage(string status) => status switch
    {
        "UNSUPPORTED_PLATFORM" => "Managed product update is not supported on this platform.",
        "TARGET_POLICY_UNAVAILABLE" => "No trusted install-target policy is provisioned for this product on this machine.",
        "TARGET_MISMATCH" => "The installed product does not match its verified BKE install target.",
        "UPDATE_POLICY_INVALID" => "Digital Solutions returned an invalid or expired update policy.",
        "RELEASE_PACKAGE_UNAVAILABLE" => "The authorized GitHub Release does not contain an eligible BKE package.",
        "RELEASE_METADATA_INVALID" => "The authorized GitHub Release package metadata is invalid.",
        "RELEASE_DOWNLOAD_FAILED" => "The authorized GitHub Release package could not be downloaded.",
        "PRIVILEGED_HANDOFF_FAILED" => "The verified update package could not be handed to the privileged updater.",
        _ => "The verified update could not be started.",
    };

    private static SoftwareUpdateResponse Response(string status, string state, SoftwareUpdateError? error) =>
        new(LocalAgentContract.SoftwareUpdateCapabilityId, LocalAgentContract.SoftwareUpdateContractVersion, status, state, error);

    private static SoftwareUpdateError Error(string code, string message, bool retryable) =>
        new(code, message, retryable);
}
