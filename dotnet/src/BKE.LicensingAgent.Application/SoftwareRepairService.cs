using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Application;

public interface IStandaloneRepairAuthorizationRemote
{
    Task<StandaloneRepairAuthorizationResult> AuthorizeAsync(
        string accessToken,
        string productId,
        string currentVersion,
        CancellationToken cancellationToken);
}

public interface IStandaloneSoftwareRepairer
{
    Task<StandaloneRepairResult> RepairAsync(
        LocalInstalledProduct installed,
        StandaloneRepairAuthorization authorization,
        CancellationToken cancellationToken);
}

public interface ISoftwareRepairService
{
    Task<SoftwareRepairResponse> RepairAsync(
        SoftwareRepairRequest request,
        CancellationToken cancellationToken);
}

public sealed record StandaloneRepairAuthorization(
    string ProductId,
    string RepairVersion,
    string Repository,
    string Tag,
    string PolicyJson);

public sealed record StandaloneRepairAuthorizationResult(
    string Status,
    StandaloneRepairAuthorization? Authorization = null);

public sealed record StandaloneRepairResult(
    string Status,
    string Reason,
    bool Retryable);

public sealed class SoftwareRepairService : ISoftwareRepairService
{
    private static readonly TimeSpan RepairStartGuard = TimeSpan.FromMinutes(10);
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly Dictionary<string, DateTimeOffset> _recentStarts = new(StringComparer.Ordinal);
    private readonly IAccountSessionService _accountSession;
    private readonly IAccountSessionSecretStore _secretStore;
    private readonly ILocalProductInventory _inventory;
    private readonly IStandaloneRepairAuthorizationRemote _remote;
    private readonly IStandaloneSoftwareRepairer _repairer;

    public SoftwareRepairService(
        IAccountSessionService accountSession,
        IAccountSessionSecretStore secretStore,
        ILocalProductInventory inventory,
        IStandaloneRepairAuthorizationRemote remote,
        IStandaloneSoftwareRepairer repairer)
    {
        _accountSession = accountSession;
        _secretStore = secretStore;
        _inventory = inventory;
        _remote = remote;
        _repairer = repairer;
    }

    public async Task<SoftwareRepairResponse> RepairAsync(
        SoftwareRepairRequest request,
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
                        session.Error?.Message ?? "Sign in with a BKE account before repairing software.", false));
            }

            var stored = await _secretStore.ReadAsync(cancellationToken);
            if (stored is not ActiveAccountSessionState active)
            {
                return Response("AUTH_REQUIRED", "auth_required",
                    Error("SESSION_STATE_UNAVAILABLE", "The BKE account session is not available to Repair.", false));
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
                        "This installed product is not a BKE-managed package and cannot use managed Repair.", false));
            }

            var now = DateTimeOffset.UtcNow;
            if (_recentStarts.TryGetValue(request.ProductId, out var startedAt))
            {
                if (now - startedAt < RepairStartGuard)
                    return Response("IN_PROGRESS", "repair_in_progress", null);
                _recentStarts.Remove(request.ProductId);
            }

            StandaloneRepairAuthorizationResult authorization;
            try
            {
                authorization = await _remote.AuthorizeAsync(
                    active.AccessToken,
                    request.ProductId,
                    product.Version,
                    cancellationToken);
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
                    Error("AUTHORIZATION_UNAVAILABLE", "BKE Repair authorization is temporarily unavailable.", true));
            }
            catch (InvalidDataException)
            {
                return Response("FAILED", "invalid_authorization_response",
                    Error("INVALID_AUTHORIZATION_RESPONSE", "BKE Repair authorization returned an invalid response.", false));
            }

            if (authorization.Status != "REPAIR_AUTHORIZED" ||
                authorization.Authorization is null)
            {
                return AuthorizationFailure(authorization.Status);
            }

            try
            {
                var result = await _repairer.RepairAsync(
                    product,
                    authorization.Authorization,
                    cancellationToken);
                if (result.Status == "STARTED")
                {
                    _recentStarts[request.ProductId] = DateTimeOffset.UtcNow;
                    return Response("STARTED", result.Reason, null);
                }

                return Response("FAILED", result.Reason,
                    Error(result.Status, RepairMessage(result.Status), result.Retryable));
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch
            {
                return Response("FAILED", "privileged_repair_failed",
                    Error("PRIVILEGED_REPAIR_FAILED", "The BKE Licensing Agent could not start verified Repair.", true));
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    private static SoftwareRepairResponse AuthorizationFailure(string status) => status switch
    {
        "NOT_ENTITLED" => Response("FAILED", "not_entitled",
            Error("NOT_ENTITLED", "This BKE account is not entitled to repair the selected product.", false)),
        "UNSUPPORTED_EXECUTION_TYPE" => Response("FAILED", "unsupported_execution_type",
            Error("UNSUPPORTED_EXECUTION_TYPE", "This product is not a standalone BKE-managed installation.", false)),
        "DISTRIBUTION_UNAVAILABLE" => Response("FAILED", "distribution_unavailable",
            Error("DISTRIBUTION_UNAVAILABLE", "This product does not have a configured software release source.", false)),
        "NOT_FOUND" => Response("FAILED", "product_not_found",
            Error("PRODUCT_NOT_FOUND", "The selected BKE product is not available in the catalog.", false)),
        _ => Response("FAILED", "authorization_failed",
            Error("AUTHORIZATION_FAILED", "BKE Repair authorization failed.", false)),
    };

    private static string RepairMessage(string status) => status switch
    {
        "UNSUPPORTED_PLATFORM" => "Managed product Repair is not supported on this platform.",
        "TARGET_POLICY_UNAVAILABLE" => "No trusted install-target policy is provisioned for this product on this machine.",
        "TARGET_MISMATCH" => "The installed product does not match its verified BKE install target.",
        "REPAIR_POLICY_INVALID" => "Digital Solutions returned an invalid or expired Repair policy.",
        "RELEASE_PACKAGE_UNAVAILABLE" => "The authorized GitHub Release does not contain the installed BKE version package.",
        "RELEASE_METADATA_INVALID" => "The authorized GitHub Release package metadata is invalid.",
        "RELEASE_DOWNLOAD_FAILED" => "The authorized GitHub Release package could not be downloaded.",
        "PRIVILEGED_HANDOFF_FAILED" => "The verified Repair package could not be handed to the privileged replacement helper.",
        _ => "Verified Repair could not be started.",
    };

    private static SoftwareRepairResponse Response(
        string status,
        string state,
        SoftwareRepairError? error) =>
        new(
            LocalAgentContract.SoftwareRepairCapabilityId,
            LocalAgentContract.SoftwareRepairContractVersion,
            status,
            state,
            error);

    private static SoftwareRepairError Error(
        string code,
        string message,
        bool retryable) =>
        new(code, message, retryable);
}
