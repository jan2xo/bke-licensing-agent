using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Infrastructure;

/// <summary>
/// Legacy local updater UX is an account-authenticated *discovery* projection.
/// Digital Solutions alone authorizes product updates; actual privileged updates
/// reauthorize and verify its signed v2 policy in SoftwareUpdateService.
/// This class never consumes or translates a legacy key-based update lease.
/// </summary>
public sealed class Gen2UpdateService : IUpdateService
{
    private readonly IAccountSessionService _accountSession;
    private readonly IAccountSessionSecretStore _secretStore;
    private readonly ILocalProductInventory _inventory;
    private readonly IStandaloneUpdateAuthorizationRemote _remote;
    private readonly ISoftwareUpdateService _updater;

    public Gen2UpdateService(
        IAccountSessionService accountSession,
        IAccountSessionSecretStore secretStore,
        ILocalProductInventory inventory,
        IStandaloneUpdateAuthorizationRemote remote,
        ISoftwareUpdateService updater)
    {
        _accountSession = accountSession;
        _secretStore = secretStore;
        _inventory = inventory;
        _remote = remote;
        _updater = updater;
    }

    public async Task<UpdateCheckResponse> CheckAsync(
        UpdateCheckRequest request,
        CancellationToken cancellationToken)
    {
        // No requested-version pinning: Digital Solutions determines the eligible
        // published version. Never use arbitrary local inventory as entitlement.
        if (!string.IsNullOrEmpty(request.RequestedVersion) ||
            string.IsNullOrWhiteSpace(request.ProductId) ||
            string.IsNullOrWhiteSpace(request.CurrentVersion) ||
            request.ProductId.Length > 128 ||
            request.CurrentVersion.Length > 64)
        {
            return Failed("InvalidRequest", "Invalid product update context.", false);
        }

        var session = await _accountSession.StatusAsync(
            new AccountSessionStatusRequest(Guid.NewGuid().ToString("N")),
            cancellationToken);
        if (session.Status != "AUTHENTICATED")
            return Failed("AuthRequired", "Sign in to BKE before checking product updates.", false);

        var stored = await _secretStore.ReadAsync(cancellationToken);
        if (stored is not ActiveAccountSessionState active)
            return Failed("AuthRequired", "The BKE account session is not available.", false);

        IReadOnlyDictionary<string, LocalInstalledProduct> inventory;
        try
        {
            inventory = await _inventory.ReadAsync(cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch
        {
            return Failed("ProviderUnavailable", "Installed product inventory is unavailable.", true);
        }

        if (!inventory.TryGetValue(request.ProductId, out var installed) ||
            installed.Version != request.CurrentVersion)
        {
            return Failed("InvalidRequest", "The selected product/version is not installed.", false);
        }

        if (!Managed(installed))
            return Failed("PolicyDenied", "This product does not support BKE-managed updates.", false);

        StandaloneUpdateAuthorizationResult result;
        try
        {
            // Remote owns bearer session protocol and strict v2 response shape.
            // This is a UX hint, NOT a signed privileged-execution grant.
            result = await _remote.AuthorizeAsync(
                active.AccessToken, installed.ProductId, installed.Version, cancellationToken);
        }
        catch (UnauthorizedAccessException)
        {
            await _secretStore.ClearAsync(cancellationToken);
            return Failed("AuthRequired", "The BKE session was revoked; sign in again.", false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (HttpRequestException)
        {
            return Failed("ProviderUnavailable", "Digital Solutions update authority is unavailable.", true);
        }
        catch (InvalidDataException)
        {
            return Failed("VerificationFailure", "Digital Solutions returned an invalid update policy.", false);
        }

        if (result.Status == "UP_TO_DATE")
            return Success("UpToDate", null);

        if (result.Status == "UPDATE_AVAILABLE" && result.Authorization is { } policy &&
            policy.ProductId == installed.ProductId &&
            policy.CurrentVersion == installed.Version &&
            !string.IsNullOrWhiteSpace(policy.TargetVersion) &&
            policy.TargetVersion != installed.Version)
        {
            return Success("UpdateAvailable", policy.TargetVersion);
        }

        return result.Status switch
        {
            "NOT_ENTITLED" => Failed("PolicyDenied", "The account does not own this product.", false),
            "NOT_FOUND" => Failed("InvalidRequest", "This product is not in the catalog.", false),
            "UNSUPPORTED_EXECUTION_TYPE" => Failed("PolicyDenied", "The product is not standalone.", false),
            "RELEASE_UNAVAILABLE" => Failed("ProviderUnavailable", "No eligible release is published.", true),
            "DISTRIBUTION_UNAVAILABLE" => Failed("PolicyDenied", "No trusted release source is configured.", false),
            _ => Failed("VerificationFailure", "Unrecognized product-update authorization.", false),
        };
    }

    public async Task<OpenUpdateCenterResponse> OpenCenterAsync(
        OpenUpdateCenterRequest request,
        CancellationToken cancellationToken)
    {
        // Preserve the legacy local command's exact product/version binding.
        // Never replay the cached v1 package-policy path. The existing modern
        // updater reauthorizes with DS and cryptographically verifies signed v2
        // release metadata before any privileged install/update handoff.
        if (string.IsNullOrWhiteSpace(request.ProductId) ||
            string.IsNullOrWhiteSpace(request.Version) ||
            string.IsNullOrWhiteSpace(request.CorrelationId))
            return new("update_failed", "invalid_request", request.CorrelationId);

        IReadOnlyDictionary<string, LocalInstalledProduct> inventory;
        try
        {
            inventory = await _inventory.ReadAsync(cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch
        {
            return new("update_failed", "local_inventory_unavailable", request.CorrelationId);
        }

        if (!inventory.TryGetValue(request.ProductId, out var installed))
            return new("no_update", "not_installed", request.CorrelationId);

        if (installed.Version != request.Version || !Managed(installed))
            return new("update_failed", "product_context_mismatch", request.CorrelationId);

        var update = await _updater.UpdateAsync(
            new SoftwareUpdateRequest(request.CorrelationId, request.ProductId),
            cancellationToken);

        return update.Status switch
        {
            "STARTED" => new("update_started", "staged", request.CorrelationId),
            "UP_TO_DATE" => new("no_update", "up_to_date", request.CorrelationId),
            "IN_PROGRESS" => new("no_update", "update_in_progress", request.CorrelationId),
            "NOT_INSTALLED" => new("no_update", "not_installed", request.CorrelationId),
            "AUTH_REQUIRED" => new("update_failed", "auth_required", request.CorrelationId),
            _ => new("update_failed", update.State, request.CorrelationId),
        };
    }

    private static bool Managed(LocalInstalledProduct installed) =>
        installed.InstallProvenance == "BKE_MANAGED_PACKAGE" &&
        installed.UninstallStrategy == "MANAGED_DIRECTORY";

    private static UpdateCheckResponse Success(string status, string? version) =>
        new(LocalAgentContract.UpdateCapabilityId,
            LocalAgentContract.UpdateContractVersion, status, version, null);

    private static UpdateCheckResponse Failed(string code, string message, bool retryable) =>
        new(LocalAgentContract.UpdateCapabilityId,
            LocalAgentContract.UpdateContractVersion, "Failed", null,
            new UpdateCapabilityError(code, message, retryable));
}
