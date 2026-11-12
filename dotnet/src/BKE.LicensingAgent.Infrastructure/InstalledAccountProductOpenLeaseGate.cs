using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Infrastructure;

/// <summary>
/// Agent Host's PREPRODUCTION opt-in execution gate. Only a freshly issued,
/// independently verified JWS can permit the Launcher-mediated Open method
/// to proceed to its separate protected installation launch provider.
/// No cached lease, HTTP-supplied key, local flag, or catalog row grants access.
/// </summary>
public sealed class InstalledAccountProductOpenLeaseGate : IAccountProductOpenLeaseGate
{
    private readonly IAccountSessionService _accounts;
    private readonly IAccountSessionSecretStore _secrets;
    private readonly IReadOnlyDictionary<string, AccountProductLeaseTrustedKey> _issuerKeys;

    public InstalledAccountProductOpenLeaseGate(
        IAccountSessionService accounts,
        IAccountSessionSecretStore secrets,
        IReadOnlyDictionary<string, AccountProductLeaseTrustedKey> issuerKeys)
    {
        _accounts = accounts ?? throw new ArgumentNullException(nameof(accounts));
        _secrets = secrets ?? throw new ArgumentNullException(nameof(secrets));
        _issuerKeys = issuerKeys ?? throw new ArgumentNullException(nameof(issuerKeys));
        if (_issuerKeys.Count == 0)
            throw new InvalidOperationException("Installed DS issuer trust is not provisioned.");
    }

    public async Task<bool> VerifyFreshOpenAsync(
        string productId, CancellationToken cancellationToken)
    {
        var status = await _accounts.StatusAsync(
            new AccountSessionStatusRequest("account-lease-open"),
            cancellationToken);
        if (status.Status != "AUTHENTICATED")
            return false;

        if (await _secrets.ReadAsync(cancellationToken)
            is not ActiveAccountSessionState session)
            return false;

        // DS policy is rechecked on every fresh issuance; the resulting JWS
        // is only one gate, never a substitute for installed inventory checks.
        var machine = MachineIdentityProvider.Calculate();
        string platform = MachineIdentityProvider.ProtocolPlatform(machine.Platform);
        string architecture =
            MachineIdentityProvider.ProtocolArchitecture(machine.Architecture);
        if (platform != "windows" || architecture is not ("x64" or "arm64" or "x86"))
            return false;

        // The protected DPAPI/TPM issuer consumer is Windows-only; do not
        // rely on protocol-platform strings for CA1416 reachability analysis.
        if (!OperatingSystem.IsWindows())
            return false;

        using var remote = AgentAccountProductLeaseRemote.CreatePreferred(
            session, _issuerKeys, allowSoftwareFallback: false);
        var result = await remote.RequestVerifiedAsync(
            session, productId, "OPEN", platform, architecture,
            cancellationToken);
        return result.Ok &&
               result.Claims is not null &&
               result.Claims.ProductId == productId &&
               result.Claims.AllowedActions.Contains("OPEN", StringComparer.Ordinal) &&
               result.Claims.ExpiresAt > DateTimeOffset.UtcNow;
    }
}
