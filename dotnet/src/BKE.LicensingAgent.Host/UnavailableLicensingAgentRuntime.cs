using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Host;

internal sealed class UnavailableLicensingAgentRuntime : ILicensingAgentRuntime
{
    private const string NotMigratedReason = "vnext_provider_not_migrated";

    public Task<AuthorizationResponse> AuthorizeAsync(
        AuthorizeRequest request,
        CancellationToken cancellationToken) =>
        Task.FromResult(new AuthorizationResponse(false, NotMigratedReason));

    public Task<AuthorizationResponse> ActivateAsync(
        ActivateRequest request,
        CancellationToken cancellationToken) =>
        Task.FromResult(new AuthorizationResponse(false, NotMigratedReason));

    public Task<OpenLicenseCenterResponse> OpenLicenseCenterAsync(
        OpenLicenseCenterRequest request,
        CancellationToken cancellationToken) =>
        Task.FromResult(new OpenLicenseCenterResponse(
            "agent_unavailable",
            NotMigratedReason,
            false,
            request.CorrelationId));

    public Task<UpdateCheckResponse> CheckUpdatesAsync(
        UpdateCheckRequest request,
        CancellationToken cancellationToken) =>
        Task.FromResult(new UpdateCheckResponse(
            LocalAgentContract.UpdateCapabilityId,
            LocalAgentContract.UpdateContractVersion,
            "Failed",
            null,
            new UpdateCapabilityError(
                "ProviderUnavailable",
                "The .NET 10 update provider has not been migrated yet.",
                true)));

    public Task<OpenUpdateCenterResponse> OpenUpdateCenterAsync(
        OpenUpdateCenterRequest request,
        CancellationToken cancellationToken) =>
        Task.FromResult(new OpenUpdateCenterResponse(
            "agent_unavailable",
            NotMigratedReason,
            request.CorrelationId));
}
