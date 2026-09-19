using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Application;

public interface ILocalProductLauncher
{
    Task<LocalProductLaunchResult> OpenAsync(
        string productId,
        CancellationToken cancellationToken);
}

public interface ISoftwareOpenService
{
    Task<SoftwareOpenResponse> OpenAsync(
        SoftwareOpenRequest request,
        CancellationToken cancellationToken);
}

public sealed record LocalProductLaunchResult(
    string Status,
    string Reason,
    bool Retryable);

public sealed class SoftwareOpenService : ISoftwareOpenService
{
    private readonly ISoftwareCatalogService _catalog;
    private readonly ILocalProductLauncher _launcher;

    public SoftwareOpenService(
        ISoftwareCatalogService catalog,
        ILocalProductLauncher launcher)
    {
        _catalog = catalog;
        _launcher = launcher;
    }

    public async Task<SoftwareOpenResponse> OpenAsync(
        SoftwareOpenRequest request,
        CancellationToken cancellationToken)
    {
        var catalog = await _catalog.GetAsync(
            new SoftwareCatalogRequest(request.CorrelationId),
            cancellationToken);

        if (catalog.Status == "AUTH_REQUIRED")
        {
            return Response(
                "AUTH_REQUIRED",
                "auth_required",
                catalog.Error is null
                    ? Error(
                        "AUTH_REQUIRED",
                        "Sign in with a BKE account before opening software.",
                        false)
                    : Error(
                        catalog.Error.Code,
                        catalog.Error.Message,
                        catalog.Error.Retryable));
        }

        if (catalog.Status != "READY")
        {
            return Response(
                "FAILED",
                "catalog_unavailable",
                Error(
                    catalog.Error?.Code ?? "CATALOG_UNAVAILABLE",
                    catalog.Error?.Message ??
                        "The BKE software catalog is currently unavailable.",
                    catalog.Error?.Retryable ?? true));
        }

        var product = catalog.Items.SingleOrDefault(
            item => string.Equals(
                item.ProductId,
                request.ProductId,
                StringComparison.Ordinal));

        if (product is null)
        {
            return Response(
                "FAILED",
                "product_not_found",
                Error(
                    "PRODUCT_NOT_FOUND",
                    "The selected BKE product is not available in the catalog.",
                    false));
        }

        if (!string.Equals(
                product.ExecutionType,
                "STANDALONE",
                StringComparison.Ordinal))
        {
            return Response(
                "FAILED",
                "unsupported_execution_type",
                Error(
                    "UNSUPPORTED_EXECUTION_TYPE",
                    "This product is not a standalone Launcher-openable application.",
                    false));
        }

        if (!product.Entitled ||
            product.State == "INSTALLED_NOT_ENTITLED")
        {
            return Response(
                "FAILED",
                "not_entitled",
                Error(
                    "NOT_ENTITLED",
                    "This BKE account is not entitled to open the selected product.",
                    false));
        }

        if (product.State is not ("INSTALLED" or "UPDATE_AVAILABLE"))
        {
            return Response(
                "FAILED",
                "not_installed",
                Error(
                    "NOT_INSTALLED",
                    "The selected product is not installed on this machine.",
                    false));
        }

        LocalProductLaunchResult result;
        try
        {
            result = await _launcher.OpenAsync(
                request.ProductId,
                cancellationToken);
        }
        catch (OperationCanceledException) when (
            cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return Response(
                "FAILED",
                "launch_failed",
                Error(
                    "LAUNCH_FAILED",
                    "The BKE Licensing Agent could not start the installed product.",
                    true));
        }

        if (result.Status == "STARTED")
        {
            return Response(
                "STARTED",
                result.Reason,
                null);
        }

        return Response(
            "FAILED",
            result.Reason,
            Error(
                result.Status,
                LaunchMessage(result.Status),
                result.Retryable));
    }

    private static string LaunchMessage(string status) => status switch
    {
        "NOT_INSTALLED" =>
            "The selected product is not installed on this machine.",
        "UNTRUSTED_INSTALL_LOCATION" =>
            "The installed product is outside the trusted BKE application root.",
        "ENTRY_POINT_UNAVAILABLE" =>
            "The installed product entry point is unavailable.",
        "UNSUPPORTED_PLATFORM" =>
            "Opening managed standalone products is not supported on this platform.",
        "NO_ACTIVE_USER_SESSION" =>
            "No active Windows user session is available to receive the product window.",
        "INTERACTIVE_LAUNCH_FAILED" =>
            "Windows could not start the product in the active user session.",
        _ =>
            "The BKE Licensing Agent could not start the installed product.",
    };

    private static SoftwareOpenResponse Response(
        string status,
        string state,
        SoftwareOpenError? error) =>
        new(
            LocalAgentContract.SoftwareOpenCapabilityId,
            LocalAgentContract.SoftwareOpenContractVersion,
            status,
            state,
            error);

    private static SoftwareOpenError Error(
        string code,
        string message,
        bool retryable) =>
        new(code, message, retryable);
}
