using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Infrastructure;

public sealed class Gen2UpdateService : IUpdateService
{
    private readonly UpdateProvider _discovery;
    private readonly PrivilegedUpdateCenterProvider _center;

    public Gen2UpdateService(UpdateProvider discovery, PrivilegedUpdateCenterProvider center)
    {
        _discovery = discovery;
        _center = center;
    }

    public Task<UpdateCheckResponse> CheckAsync(
        UpdateCheckRequest request,
        CancellationToken cancellationToken) =>
        _discovery.CheckAsync(request, cancellationToken);

    public Task<OpenUpdateCenterResponse> OpenCenterAsync(
        OpenUpdateCenterRequest request,
        CancellationToken cancellationToken) =>
        _center.OpenAsync(request, cancellationToken);
}
