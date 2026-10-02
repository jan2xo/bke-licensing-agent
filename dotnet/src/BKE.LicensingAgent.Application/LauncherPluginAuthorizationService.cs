using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Application;

public sealed class LauncherPluginAuthorizationService
    : ILauncherPluginAuthorizationService
{
    private readonly ISoftwareCatalogService _catalog;

    public LauncherPluginAuthorizationService(
        ISoftwareCatalogService catalog)
    {
        _catalog = catalog;
    }

    public async Task<LauncherPluginAuthorizeResponse> AuthorizeAsync(
        LauncherPluginAuthorizeRequest request,
        CancellationToken cancellationToken)
    {
        var catalog = await _catalog.GetAsync(
            new SoftwareCatalogRequest(request.CorrelationId),
            cancellationToken);

        if (catalog.Status == "AUTH_REQUIRED")
        {
            return Response(
                "AUTH_REQUIRED",
                false,
                "auth_required",
                FromCatalogError(catalog.Error));
        }

        if (catalog.Status != "READY")
        {
            return Response(
                "FAILED",
                false,
                "catalog_unavailable",
                FromCatalogError(catalog.Error) ??
                Error(
                    "CATALOG_UNAVAILABLE",
                    "The BKE software catalog is unavailable.",
                    true));
        }

        var matches = catalog.Items
            .Where(item => string.Equals(
                item.ProductId,
                request.ProductId,
                StringComparison.Ordinal))
            .Take(2)
            .ToArray();

        if (matches.Length == 0)
        {
            return Response(
                "DENIED",
                false,
                "not_found",
                null);
        }

        if (matches.Length != 1)
        {
            return Response(
                "FAILED",
                false,
                "catalog_ambiguous",
                Error(
                    "CATALOG_AMBIGUOUS",
                    "The BKE software catalog returned duplicate product identities.",
                    false));
        }

        var product = matches[0];

        if (!string.Equals(
                product.ExecutionType,
                "LAUNCHER_PLUGIN",
                StringComparison.Ordinal))
        {
            return Response(
                "DENIED",
                false,
                "unsupported_execution_type",
                null);
        }

        if (!product.Entitled)
        {
            return Response(
                "DENIED",
                false,
                "not_entitled",
                null);
        }

        if (string.IsNullOrWhiteSpace(product.LatestVersion))
        {
            return Response(
                "DENIED",
                false,
                "release_unavailable",
                null);
        }

        if (!string.Equals(
                product.LatestVersion,
                request.Version,
                StringComparison.Ordinal))
        {
            return Response(
                "DENIED",
                false,
                "version_mismatch",
                null);
        }

        return Response(
            "AUTHORIZED",
            true,
            "authorized",
            null);
    }

    private static LauncherPluginAuthorizeResponse Response(
        string status,
        bool authorized,
        string reason,
        LauncherPluginAuthorizeError? error) =>
        new(
            LocalAgentContract.LauncherPluginAuthorizeCapabilityId,
            LocalAgentContract.LauncherPluginAuthorizeContractVersion,
            status,
            authorized,
            reason,
            error);

    private static LauncherPluginAuthorizeError? FromCatalogError(
        SoftwareCatalogError? error) =>
        error is null
            ? null
            : Error(
                error.Code,
                error.Message,
                error.Retryable);

    private static LauncherPluginAuthorizeError Error(
        string code,
        string message,
        bool retryable) =>
        new(code, message, retryable);
}
