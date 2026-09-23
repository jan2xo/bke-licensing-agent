using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Application;

public interface IStandaloneSoftwareRemover
{
    Task<StandaloneRemovalResult> RemoveAsync(
        LocalInstalledProduct product,
        CancellationToken cancellationToken);
}

public interface ISoftwareRemoveService
{
    Task<SoftwareRemoveResponse> RemoveAsync(
        SoftwareRemoveRequest request,
        CancellationToken cancellationToken);
}

public sealed record StandaloneRemovalResult(
    string Status,
    string Reason,
    bool Retryable);

public sealed class SoftwareRemoveService : ISoftwareRemoveService
{
    private readonly SemaphoreSlim _removeGate = new(1, 1);
    private readonly IAccountSessionService _accountSession;
    private readonly ILocalProductInventory _inventory;
    private readonly IStandaloneSoftwareRemover _remover;

    public SoftwareRemoveService(
        IAccountSessionService accountSession,
        ILocalProductInventory inventory,
        IStandaloneSoftwareRemover remover)
    {
        _accountSession = accountSession;
        _inventory = inventory;
        _remover = remover;
    }

    public async Task<SoftwareRemoveResponse> RemoveAsync(
        SoftwareRemoveRequest request,
        CancellationToken cancellationToken)
    {
        await _removeGate.WaitAsync(cancellationToken);
        try
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
                        session.Error?.Message ?? "Sign in with a BKE account before removing software.",
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

            if (!installed.TryGetValue(request.ProductId, out var product))
            {
                return Response("NOT_INSTALLED", "not_installed", null);
            }

            StandaloneRemovalResult result;
            try
            {
                result = await _remover.RemoveAsync(
                    product,
                    cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch
            {
                return Response(
                    "FAILED",
                    "privileged_remove_failed",
                    Error(
                        "PRIVILEGED_REMOVE_FAILED",
                        "The BKE Licensing Agent could not remove the managed product.",
                        true));
            }

            return result.Status switch
            {
                "REMOVED" => Response("REMOVED", result.Reason, null),
                "NOT_INSTALLED" => Response("NOT_INSTALLED", result.Reason, null),
                _ => Response(
                    "FAILED",
                    result.Reason,
                    Error(
                        result.Status,
                        RemovalMessage(result.Status),
                        result.Retryable)),
            };
        }
        finally
        {
            _removeGate.Release();
        }
    }

    private static string RemovalMessage(string status) => status switch
    {
        "UNSUPPORTED_PLATFORM" =>
            "Managed product removal is not supported on this platform.",
        "TARGET_POLICY_UNAVAILABLE" =>
            "No verified BKE install-target policy is available for this product.",
        "TARGET_MISMATCH" =>
            "The installed product does not match its verified BKE install target.",
        "PROTECTED_TARGET" =>
            "The requested removal target is protected BKE platform infrastructure.",
        "UNINSTALL_STRATEGY_UNAVAILABLE" =>
            "This installation has no trusted uninstall strategy.",
        "UNINSTALL_STRATEGY_MISMATCH" =>
            "The installed product uninstall strategy does not match signed BKE policy.",
        "UNINSTALL_EXECUTABLE_MISSING" =>
            "The product uninstaller is missing from the verified install root.",
        "UNINSTALL_VERIFICATION_FAILED" =>
            "The product uninstaller completed but the installed product is still present.",
        "REMOVE_FAILED" =>
            "The managed product could not be removed.",
        _ =>
            "The BKE Licensing Agent could not remove the managed product.",
    };

    private static SoftwareRemoveResponse Response(
        string status,
        string state,
        SoftwareRemoveError? error) =>
        new(
            LocalAgentContract.SoftwareRemoveCapabilityId,
            LocalAgentContract.SoftwareRemoveContractVersion,
            status,
            state,
            error);

    private static SoftwareRemoveError Error(
        string code,
        string message,
        bool retryable) =>
        new(code, message, retryable);
}
