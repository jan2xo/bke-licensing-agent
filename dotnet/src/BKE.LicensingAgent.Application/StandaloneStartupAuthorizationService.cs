using System.Text.RegularExpressions;
using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Application;

/// <summary>
/// Kernel-observed peer identity. Never deserialize this type from product IPC.
/// Only an Agent-owned, connected native transport may construct an authority
/// from a peer it observed using the operating system's process handle.
/// </summary>
public sealed record StandaloneStartupProcessEvidence(
    int ProcessId,
    long StartedUtcTicks,
    string ImagePath,
    string ImageSha256,
    string UserSid,
    DateTimeOffset ObservedAt,
    bool WindowsKernelObserved);

/// <summary>
/// Signed installer/release provenance resolved by a trusted Agent registry.
/// Unprotected SQLite inventory, path prefix and mutable product JSON alone
/// are NOT sufficient to construct this evidence.
/// </summary>
public sealed record TrustedStandaloneStartupInstallation(
    string ProductId,
    string Version,
    string InstallationId,
    string ImagePath,
    string ImageSha256,
    string AllowedUserSid);

/// <summary>
/// DS SQL activation mode or a separately verified signed offline projection.
/// A local product assertion cannot implement this port.
/// </summary>
public sealed record TrustedStandaloneStartupPolicy(
    string ProductId,
    string Version,
    string ActivationMode);

public interface IStandaloneStartupPeerAttestor
{
    Task<StandaloneStartupProcessEvidence?> ObserveConnectedPeerAsync(
        CancellationToken cancellationToken);
    Task<bool> IsSameLivePeerAsync(
        StandaloneStartupProcessEvidence original,
        CancellationToken cancellationToken);
}

public interface ITrustedStandaloneStartupRegistry
{
    Task<TrustedStandaloneStartupInstallation?> ResolveVerifiedAsync(
        StandaloneStartupProcessEvidence peer,
        CancellationToken cancellationToken);
}

public interface ITrustedStandaloneStartupPolicySource
{
    Task<TrustedStandaloneStartupPolicy?> ReadVerifiedAsync(
        string productId,
        string version,
        CancellationToken cancellationToken);
}

public interface IStandaloneStartupAudit
{
    /// <summary>Must durably record an authenticated grant before returning true.</summary>
    Task<bool> CommitGrantAsync(
        TrustedStandaloneStartupInstallation installation,
        StandaloneStartupProcessEvidence peer,
        string credential,
        CancellationToken cancellationToken);
}

public sealed record StandaloneStartupDecision(
    bool Authorized,
    string Reason,
    string? Credential = null);

/// <summary>
/// PREPRODUCTION-only, not a product-facing endpoint. All independently
/// supplied trust ports are mandatory: no runtime composition is provided by
/// this source slice, and the current Host cannot grant through this service.
/// </summary>
public sealed class StandaloneStartupAuthorizationService
{
    private static readonly Regex ProductPattern = new(
        "^[a-z0-9]+(?:-[a-z0-9]+)*$", RegexOptions.CultureInvariant);
    private static readonly Regex VersionPattern = new(
        @"^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$", RegexOptions.CultureInvariant);
    private static readonly Regex DigestPattern = new(
        "^[0-9a-f]{64}$", RegexOptions.CultureInvariant);

    private static readonly TimeSpan StartupWindow = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan AttestationWindow = TimeSpan.FromSeconds(5);
    private readonly SemaphoreSlim _singleFlight = new(1, 1);
    private readonly HashSet<string> _grantedProcessIdentities = new(StringComparer.Ordinal);
    private readonly IStandaloneStartupPeerAttestor _peer;
    private readonly ITrustedStandaloneStartupRegistry _registry;
    private readonly ITrustedStandaloneStartupPolicySource _policies;
    private readonly ISoftwareCatalogService _catalog;
    private readonly IAuthorizationService _commercial;
    private readonly IAccountProductOpenLeaseGate? _signedAccount;
    private readonly IStandaloneStartupAudit _audit;
    private readonly TimeProvider _clock;
    private readonly string _environment;

    public StandaloneStartupAuthorizationService(
        IStandaloneStartupPeerAttestor peer,
        ITrustedStandaloneStartupRegistry registry,
        ITrustedStandaloneStartupPolicySource policies,
        ISoftwareCatalogService catalog,
        IAuthorizationService commercial,
        IAccountProductOpenLeaseGate? signedAccount,
        IStandaloneStartupAudit audit,
        string environment,
        TimeProvider? clock = null)
    {
        _peer = peer ?? throw new ArgumentNullException(nameof(peer));
        _registry = registry ?? throw new ArgumentNullException(nameof(registry));
        _policies = policies ?? throw new ArgumentNullException(nameof(policies));
        _catalog = catalog ?? throw new ArgumentNullException(nameof(catalog));
        _commercial = commercial ?? throw new ArgumentNullException(nameof(commercial));
        _signedAccount = signedAccount;
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _environment = environment;
        _clock = clock ?? TimeProvider.System;
    }

    // No product-controlled parameters. Identity comes from the *connected*
    // OS peer, not a requested pid, path, user, product, key or account.
    public async Task<StandaloneStartupDecision> AuthorizeConnectedPeerAsync(
        CancellationToken cancellationToken)
    {
        // Production deliberately cannot enable this unfinished contract.
        if (_environment is not ("development" or "certification" or "utm"))
            return Deny("startup_gate_not_enabled");

        await _singleFlight.WaitAsync(cancellationToken);
        try
        {
            return await AuthorizeCoreAsync(cancellationToken);
        }
        finally
        {
            _singleFlight.Release();
        }
    }

    private async Task<StandaloneStartupDecision> AuthorizeCoreAsync(
        CancellationToken cancellationToken)
    {
        try
        {
            var peer = await _peer.ObserveConnectedPeerAsync(cancellationToken);
            var now = _clock.GetUtcNow();
            if (peer is null || !ValidPeer(peer, now))
                return Deny("unverified_peer");

            // A PID is not a stable identity without the kernel start time.
            var replayKey = $"{peer.ProcessId}:{peer.StartedUtcTicks}:{peer.UserSid}";
            if (_grantedProcessIdentities.Contains(replayKey))
                return Deny("startup_replay");

            var installed = await _registry.ResolveVerifiedAsync(peer, cancellationToken);
            if (!ValidInstallation(installed, peer))
                return Deny("untrusted_installed_product");

            var policy = await _policies.ReadVerifiedAsync(
                installed!.ProductId, installed.Version, cancellationToken);
            if (policy is null || policy.ProductId != installed.ProductId ||
                policy.Version != installed.Version ||
                policy.ActivationMode is not ("ACCOUNT" or "LICENSE_KEY" or "EITHER"))
                return Deny("activation_policy_unavailable");

            string? provenCredential = null;
            if ((policy.ActivationMode is "ACCOUNT" or "EITHER") &&
                await TryAccountAsync(installed, policy, cancellationToken))
                provenCredential = "ACCOUNT";

            if (provenCredential is null &&
                (policy.ActivationMode is "LICENSE_KEY" or "EITHER") &&
                await TryCommercialKeyAsync(installed, cancellationToken))
                provenCredential = "LICENSE_KEY";

            if (provenCredential is null)
                return Deny("independent_credential_required");

            // Check peer again AFTER potentially slow DS/crypto calls.
            if (!await _peer.IsSameLivePeerAsync(peer, cancellationToken))
                return Deny("peer_changed");

            // Record the grant before telling the product it may proceed.
            // No audit persistence -> no application authorization.
            if (!await _audit.CommitGrantAsync(
                    installed, peer, provenCredential, cancellationToken))
                return Deny("audit_unavailable");

            _grantedProcessIdentities.Add(replayKey);
            return new StandaloneStartupDecision(true, "authorized", provenCredential);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return Deny("startup_authority_unavailable");
        }
    }

    private async Task<bool> TryAccountAsync(
        TrustedStandaloneStartupInstallation installed,
        TrustedStandaloneStartupPolicy policy,
        CancellationToken cancellationToken)
    {
        if (_signedAccount is null)
            return false;

        try
        {
            var response = await _catalog.GetAsync(
                new SoftwareCatalogRequest("standalone-startup"),
                cancellationToken);
            if (response.Status != "READY")
                return false;

            var matches = response.Items
                .Where(x => x.ProductId == installed.ProductId)
                .Take(2).ToArray();
            if (matches.Length != 1)
                return false;
            var product = matches[0];
            if (product.ActivationMode != policy.ActivationMode ||
                product.ExecutionType != "STANDALONE" ||
                product.InstalledVersion != installed.Version ||
                !product.Entitled ||
                product.State is not ("INSTALLED" or "UPDATE_AVAILABLE"))
                return false;

            return await _signedAccount.VerifyFreshOpenAsync(
                installed.ProductId, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return false;
        }
    }

    private async Task<bool> TryCommercialKeyAsync(
        TrustedStandaloneStartupInstallation installed,
        CancellationToken cancellationToken)
    {
        try
        {
            var result = await _commercial.AuthorizeAsync(
                new AuthorizeRequest(
                    installed.ProductId, installed.Version, installed.InstallationId),
                cancellationToken);
            // The existing Agent authorizer verifies the signed commercial
            // lease, machine ID, installation ID, generation and revocation.
            return result.Authorized;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return false;
        }
    }

    private static bool ValidPeer(
        StandaloneStartupProcessEvidence peer,
        DateTimeOffset now)
    {
        if (!peer.WindowsKernelObserved || peer.ProcessId < 1 ||
            peer.StartedUtcTicks < DateTime.MinValue.Ticks ||
            peer.StartedUtcTicks > DateTime.MaxValue.Ticks ||
            string.IsNullOrWhiteSpace(peer.ImagePath) ||
            !DigestPattern.IsMatch(peer.ImageSha256) ||
            string.IsNullOrWhiteSpace(peer.UserSid) ||
            !peer.UserSid.StartsWith("S-1-", StringComparison.Ordinal) ||
            now - peer.ObservedAt < TimeSpan.Zero ||
            now - peer.ObservedAt > AttestationWindow)
            return false;

        var started = new DateTimeOffset(
            new DateTime(peer.StartedUtcTicks, DateTimeKind.Utc));
        return now - started >= TimeSpan.Zero &&
               now - started <= StartupWindow;
    }

    private static bool ValidInstallation(
        TrustedStandaloneStartupInstallation? installed,
        StandaloneStartupProcessEvidence peer) =>
        installed is not null &&
        ProductPattern.IsMatch(installed.ProductId) &&
        VersionPattern.IsMatch(installed.Version) &&
        Guid.TryParseExact(installed.InstallationId, "D", out _) &&
        string.Equals(installed.ImagePath, peer.ImagePath,
            StringComparison.OrdinalIgnoreCase) &&
        string.Equals(installed.ImageSha256, peer.ImageSha256,
            StringComparison.Ordinal) &&
        string.Equals(installed.AllowedUserSid, peer.UserSid,
            StringComparison.Ordinal) &&
        DigestPattern.IsMatch(installed.ImageSha256);

    private static StandaloneStartupDecision Deny(string reason) =>
        new(false, reason);
}
