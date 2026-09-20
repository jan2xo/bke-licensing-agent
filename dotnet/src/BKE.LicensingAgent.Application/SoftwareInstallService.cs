using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Application;

public interface IStandaloneProvisionAuthorizationRemote
{
    Task<StandaloneProvisionAuthorizationResult> AuthorizeAsync(
        string accessToken,
        string productId,
        CancellationToken cancellationToken);
}

public interface IStandaloneSoftwareProvisioner
{
    Task<StandaloneProvisioningResult> ProvisionAsync(
        StandaloneProvisionAuthorization authorization,
        CancellationToken cancellationToken);
}

public interface ISoftwareInstallService
{
    Task<SoftwareInstallResponse> InstallAsync(
        SoftwareInstallRequest request,
        CancellationToken cancellationToken);
}

public sealed record StandaloneProvisionAuthorization(
    string ProductId,
    string Version,
    string Repository,
    string Tag);

public sealed record StandaloneProvisionAuthorizationResult(
    string Status,
    StandaloneProvisionAuthorization? Authorization = null);

public sealed record StandaloneProvisioningResult(
    string Status,
    string Reason,
    bool Retryable);

public sealed class SoftwareInstallService : ISoftwareInstallService
{
    private static readonly TimeSpan ProvisionStartGuard = TimeSpan.FromMinutes(10);
    private readonly SemaphoreSlim _installGate = new(1, 1);
    private readonly Dictionary<string, DateTimeOffset> _recentStarts =
        new(StringComparer.Ordinal);
    private readonly IAccountSessionService _accountSession;
    private readonly IAccountSessionSecretStore _secretStore;
    private readonly ILocalProductInventory _inventory;
    private readonly IStandaloneProvisionAuthorizationRemote _remote;
    private readonly IStandaloneSoftwareProvisioner _provisioner;

    public SoftwareInstallService(
        IAccountSessionService accountSession,
        IAccountSessionSecretStore secretStore,
        ILocalProductInventory inventory,
        IStandaloneProvisionAuthorizationRemote remote,
        IStandaloneSoftwareProvisioner provisioner)
    {
        _accountSession = accountSession;
        _secretStore = secretStore;
        _inventory = inventory;
        _remote = remote;
        _provisioner = provisioner;
    }

    public async Task<SoftwareInstallResponse> InstallAsync(
        SoftwareInstallRequest request,
        CancellationToken cancellationToken)
    {
        await _installGate.WaitAsync(cancellationToken);
        try
        {
            return await InstallCoreAsync(request, cancellationToken);
        }
        finally
        {
            _installGate.Release();
        }
    }

    private async Task<SoftwareInstallResponse> InstallCoreAsync(
        SoftwareInstallRequest request,
        CancellationToken cancellationToken)
    {
        var session = await _accountSession.StatusAsync(
            new AccountSessionStatusRequest(request.CorrelationId),
            cancellationToken);

        if (session.Status != "AUTHENTICATED")
        {
            return Response(
                "AUTH_REQUIRED",
                "auth_required",
                Error(
                    session.Error?.Code ?? "AUTH_REQUIRED",
                    session.Error?.Message ?? "Sign in with a BKE account before installing software.",
                    false));
        }

        var stored = await _secretStore.ReadAsync(cancellationToken);
        if (stored is not ActiveAccountSessionState active)
        {
            return Response(
                "AUTH_REQUIRED",
                "auth_required",
                Error(
                    "SESSION_STATE_UNAVAILABLE",
                    "The BKE account session is not available to the installer.",
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
                "local_inventory_unavailable",
                Error(
                    "LOCAL_INVENTORY_UNAVAILABLE",
                    "The local BKE software inventory is unavailable.",
                    true));
        }

        if (installed.ContainsKey(request.ProductId))
        {
            _recentStarts.Remove(request.ProductId);
            return Response(
                "ALREADY_INSTALLED",
                "already_installed",
                null);
        }

        var now = DateTimeOffset.UtcNow;
        if (_recentStarts.TryGetValue(request.ProductId, out var startedAt))
        {
            if (now - startedAt < ProvisionStartGuard)
            {
                return Response(
                    "IN_PROGRESS",
                    "provision_in_progress",
                    null);
            }

            _recentStarts.Remove(request.ProductId);
        }

        StandaloneProvisionAuthorizationResult authorization;
        try
        {
            authorization = await _remote.AuthorizeAsync(
                active.AccessToken,
                request.ProductId,
                cancellationToken);
        }
        catch (UnauthorizedAccessException)
        {
            await _secretStore.ClearAsync(cancellationToken);
            return Response(
                "AUTH_REQUIRED",
                "session_invalid",
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
                "authorization_unavailable",
                Error(
                    "AUTHORIZATION_UNAVAILABLE",
                    "BKE install authorization is temporarily unavailable.",
                    true));
        }
        catch (InvalidDataException)
        {
            return Response(
                "FAILED",
                "invalid_authorization_response",
                Error(
                    "INVALID_AUTHORIZATION_RESPONSE",
                    "BKE install authorization returned an invalid response.",
                    false));
        }

        if (authorization.Status != "AUTHORIZED" ||
            authorization.Authorization is null)
        {
            return AuthorizationFailure(authorization.Status);
        }

        try
        {
            var result = await _provisioner.ProvisionAsync(
                authorization.Authorization,
                cancellationToken);

            if (result.Status == "STARTED")
            {
                _recentStarts[request.ProductId] = DateTimeOffset.UtcNow;
                return Response("STARTED", result.Reason, null);
            }

            return Response(
                "FAILED",
                result.Reason,
                Error(
                    result.Status,
                    ProvisioningMessage(result.Status),
                    result.Retryable));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return Response(
                "FAILED",
                "privileged_provision_failed",
                Error(
                    "PRIVILEGED_PROVISION_FAILED",
                    "The BKE Licensing Agent could not start the verified installation.",
                    true));
        }
    }

    private static SoftwareInstallResponse AuthorizationFailure(string status) =>
        status switch
        {
            "NOT_ENTITLED" => Response(
                "FAILED",
                "not_entitled",
                Error(
                    "NOT_ENTITLED",
                    "This BKE account is not entitled to install the selected product.",
                    false)),
            "UNSUPPORTED_EXECUTION_TYPE" => Response(
                "FAILED",
                "unsupported_execution_type",
                Error(
                    "UNSUPPORTED_EXECUTION_TYPE",
                    "This product is not a standalone Launcher-managed installation.",
                    false)),
            "RELEASE_UNAVAILABLE" => Response(
                "FAILED",
                "release_unavailable",
                Error(
                    "RELEASE_UNAVAILABLE",
                    "No eligible release is currently available for this machine.",
                    true)),
            "DISTRIBUTION_UNAVAILABLE" => Response(
                "FAILED",
                "distribution_unavailable",
                Error(
                    "DISTRIBUTION_UNAVAILABLE",
                    "This product does not have a configured software release source.",
                    false)),
            "NOT_FOUND" => Response(
                "FAILED",
                "product_not_found",
                Error(
                    "PRODUCT_NOT_FOUND",
                    "The selected BKE product is not available in the catalog.",
                    false)),
            _ => Response(
                "FAILED",
                "authorization_failed",
                Error(
                    "AUTHORIZATION_FAILED",
                    "BKE install authorization failed.",
                    false)),
        };

    private static string ProvisioningMessage(string status) => status switch
    {
        "TARGET_POLICY_UNAVAILABLE" =>
            "No trusted install-target policy is provisioned for this product on this machine.",
        "TARGET_ALREADY_EXISTS" =>
            "The authorized installation target already exists on this machine.",
        "RELEASE_PACKAGE_UNAVAILABLE" =>
            "The authorized GitHub Release does not contain an eligible BKE package.",
        "RELEASE_METADATA_INVALID" =>
            "The authorized GitHub Release package metadata is invalid.",
        "RELEASE_DOWNLOAD_FAILED" =>
            "The authorized GitHub Release package could not be downloaded.",
        "PRIVILEGED_HANDOFF_FAILED" =>
            "The verified package could not be handed to the privileged installer.",
        _ => "The verified installation could not be started.",
    };

    private static SoftwareInstallResponse Response(
        string status,
        string state,
        SoftwareInstallError? error) =>
        new(
            LocalAgentContract.SoftwareInstallCapabilityId,
            LocalAgentContract.SoftwareInstallContractVersion,
            status,
            state,
            error);

    private static SoftwareInstallError Error(
        string code,
        string message,
        bool retryable) =>
        new(code, message, retryable);
}
