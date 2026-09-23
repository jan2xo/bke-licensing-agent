using BKE.LicensingAgent.Application;

namespace BKE.LicensingAgent.Infrastructure;

public sealed class AccountSessionDeviceContextProvider : IAccountSessionDeviceContextProvider
{
    public AccountSessionDeviceContext Get()
    {
        var identity = MachineIdentityProvider.Calculate();
        return new AccountSessionDeviceContext(
            identity.DeviceId,
            Environment.MachineName,
            MachineIdentityProvider.ProtocolPlatform(identity.Platform),
            MachineIdentityProvider.ProtocolArchitecture(identity.Architecture));
    }
}
