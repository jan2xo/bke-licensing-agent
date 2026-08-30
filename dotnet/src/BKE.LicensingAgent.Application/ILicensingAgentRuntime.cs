using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Application;

public interface ILicensingAgentRuntime
{
    Task<AuthorizationResponse> AuthorizeAsync(AuthorizeRequest request, CancellationToken cancellationToken);

    Task<AuthorizationResponse> ActivateAsync(ActivateRequest request, CancellationToken cancellationToken);

    Task<OpenLicenseCenterResponse> OpenLicenseCenterAsync(
        OpenLicenseCenterRequest request,
        CancellationToken cancellationToken);

    Task<UpdateCheckResponse> CheckUpdatesAsync(
        UpdateCheckRequest request,
        CancellationToken cancellationToken);

    Task<OpenUpdateCenterResponse> OpenUpdateCenterAsync(
        OpenUpdateCenterRequest request,
        CancellationToken cancellationToken);
}
