using BKE.LicensingAgent.Application;

namespace BKE.LicensingAgent.Infrastructure;

/// <summary>
/// Source-only internal Agent lifecycle coordinator. No browser/Launcher/IPC
/// input controls this actor; the caller must supply the trusted persisted
/// ActiveAccountSessionState. Server state remains authoritative, and a
/// protected local receipt is only a recoverable reconciliation checkpoint.
/// </summary>
public sealed class AgentMachineKeyRegistrationCoordinator : IAccountSessionKeyLifecycle
{
    private readonly IAgentMachineKeyLifecycleSigner _keys;
    // DPAPI-protected algorithm-neutral receipt; no software key is created for TPM.
    private readonly WindowsDpapiEd25519MachineKeyStore _receipts;
    private readonly AgentMachineKeyEnrollmentRemote _remote;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public AgentMachineKeyRegistrationCoordinator(
        WindowsDpapiEd25519MachineKeyStore keys,
        AgentMachineKeyEnrollmentRemote remote)
        : this(keys, keys, remote) { }

    public AgentMachineKeyRegistrationCoordinator(
        WindowsTpmEcdsaP256MachineKeyStore keys,
        WindowsDpapiEd25519MachineKeyStore receiptStore,
        AgentMachineKeyEnrollmentRemote remote)
        : this(keys, receiptStore, remote) { }

    // Named certification friend may use an ephemeral ES256 fixture.
    internal AgentMachineKeyRegistrationCoordinator(
        IAgentMachineKeyLifecycleSigner keys,
        WindowsDpapiEd25519MachineKeyStore receipts,
        AgentMachineKeyEnrollmentRemote remote)
    {
        _keys = keys ?? throw new ArgumentNullException(nameof(keys));
        _receipts = receipts ?? throw new ArgumentNullException(nameof(receipts));
        _remote = remote ?? throw new ArgumentNullException(nameof(remote));
        if (!ReferenceEquals(remote.TrustedSigner, keys))
            throw new InvalidDataException("Receipt and remote must use the same protected signer instance.");
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public static AgentMachineKeyRegistrationCoordinator CreatePreferred(
        ActiveAccountSessionState trustedSession,
        string? dataDirectory = null,
        bool allowSoftwareFallback = false,
        string? baseUrl = null,
        HttpMessageHandler? handler = null)
    {
        var binding = AgentMachineKeyEnrollmentRemote.Binding(trustedSession);
        var signer = WindowsPreferredAgentMachineKey.Open(
            binding, dataDirectory, allowSoftwareFallback);
        if (signer is not IAgentMachineKeyLifecycleSigner lifecycle)
            throw new InvalidDataException("Unsupported protected Agent lifecycle owner.");
        var remote = new AgentMachineKeyEnrollmentRemote(signer, baseUrl, handler);
        return new AgentMachineKeyRegistrationCoordinator(
            lifecycle, new WindowsDpapiEd25519MachineKeyStore(dataDirectory), remote);
    }

    public async Task<AgentMachineKeyRegistrationReceipt> EnsureEnrolledAsync(
        ActiveAccountSessionState authenticatedSession,
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var binding = AgentMachineKeyEnrollmentRemote.Binding(authenticatedSession);
            var receipt = _receipts.ReadReceipt(binding, _keys);
            // Exact receipt lookup detects revocation and server-side drift.
            var remote = await _remote.StatusAsync(authenticatedSession,
                receipt?.RegistrationId, cancellationToken);

            if (receipt is not null)
            {
                if (remote.Status != "active" ||
                    receipt.RegistrationId != remote.RegistrationId ||
                    receipt.KeyThumbprint != remote.KeyThumbprint ||
                    receipt.Algorithm != remote.Algorithm ||
                    receipt.ValidUntil is not { } receiptUntil ||
                    remote.ValidUntil is not { } remoteUntil ||
                    receiptUntil.ToUnixTimeSeconds() != remoteUntil.ToUnixTimeSeconds() ||
                    receiptUntil <= DateTimeOffset.UtcNow)
                    throw new InvalidDataException(
                        "Protected registration receipt differs from DS authority; revoke/recover explicitly.");
                return receipt;
            }

            if (remote.Status == "active")
            {
                // Lost acknowledgment or crashed before receipt persistence:
                // no second enrollment and no regeneration of a missing key.
                var existing = _keys.GetOrCreateIdentity(binding, createIfMissing: false);
                if (remote.KeyThumbprint != existing.KeyThumbprint ||
                    remote.Algorithm != existing.Algorithm ||
                    remote.RegistrationId is null || remote.ValidUntil is null)
                    throw new InvalidDataException("Cannot recover a registration with an unproven local key.");
                var recovered = new AgentMachineKeyRegistrationReceipt(
                    remote.RegistrationId, existing.KeyThumbprint, remote.ValidUntil,
                    existing.Algorithm);
                _receipts.WriteReceipt(binding, recovered, _keys);
                return recovered;
            }

            if (remote.Status == "pending")
            {
                // Interrupted PENDING registration may only be re-challenged
                // for SAME local key with original device authorization proof.
                var existing = _keys.GetOrCreateIdentity(binding, createIfMissing: false);
                if (remote.KeyThumbprint != existing.KeyThumbprint ||
                    remote.Algorithm != existing.Algorithm ||
                    remote.RegistrationId is null)
                    throw new InvalidDataException("Cannot replace foreign pending key.");
            }
            else if (remote.Status != "none")
            {
                throw new InvalidDataException("Server key state requires explicit revocation/recovery.");
            }

            var confirmed = await _remote.EnrollAsync(authenticatedSession, cancellationToken);
            // Always read AFTER confirmation. A crash here is recoverable from
            // DS ACTIVE metadata plus exact surviving local public key.
            var nowActive = await _remote.StatusAsync(authenticatedSession,
                confirmed.RegistrationId, cancellationToken);
            if (nowActive.Status != "active" ||
                nowActive.RegistrationId != confirmed.RegistrationId ||
                nowActive.KeyThumbprint != confirmed.KeyThumbprint ||
                nowActive.Algorithm != confirmed.Algorithm ||
                nowActive.ValidUntil is null)
                throw new InvalidDataException("DS key enrollment acknowledgement was not durable.");
            var receiptNext = new AgentMachineKeyRegistrationReceipt(
                confirmed.RegistrationId, confirmed.KeyThumbprint, nowActive.ValidUntil,
                confirmed.Algorithm);
            _receipts.WriteReceipt(binding, receiptNext, _keys);
            return receiptNext;
        }
        finally { _gate.Release(); }
    }

    /// <summary>
    /// Server revocation must be observed before local key/receipt destruction.
    /// Does not silently recover foreign-session/corrupt protected material.
    /// This is also the optional fail-closed AccountSessionService logout hook.
    /// </summary>
    public async Task RevokeBeforeLogoutAsync(
        ActiveAccountSessionState authenticatedSession,
        CancellationToken cancellationToken) =>
        await RevokeAndClearAsync(authenticatedSession, cancellationToken);

    public async Task RevokeAndClearAsync(
        ActiveAccountSessionState authenticatedSession,
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var binding = AgentMachineKeyEnrollmentRemote.Binding(authenticatedSession);
            var receipt = _receipts.ReadReceipt(binding, _keys);
            var remote = await _remote.StatusAsync(authenticatedSession,
                receipt?.RegistrationId, cancellationToken);

            if (remote.Status == "none")
            {
                if (receipt is not null)
                    throw new InvalidDataException(
                        "DS cannot confirm terminal status for local registration receipt.");
                // No live registration in the current Agent session. Local
                // key from a crashed, never-persisted ENROLL may be discarded
                // only after authenticated DS confirms the empty session.
                if (!_keys.HasStoredIdentity) return;
                _ = _keys.GetOrCreateIdentity(binding, createIfMissing: false);
                _keys.RemoveLocalKey(binding);
                return;
            }

            if (remote.RegistrationId is null || remote.KeyThumbprint is null ||
                (receipt is not null &&
                 (receipt.RegistrationId != remote.RegistrationId ||
                  receipt.KeyThumbprint != remote.KeyThumbprint ||
                  receipt.Algorithm != remote.Algorithm)))
                throw new InvalidDataException("Cannot clear mismatched Agent registration authority.");
            var actual = _keys.GetOrCreateIdentity(binding, createIfMissing: false);
            if (actual.KeyThumbprint != remote.KeyThumbprint ||
                actual.Algorithm != remote.Algorithm)
                throw new InvalidDataException("Machine-key material does not match remote registration.");

            if (remote.Status != "revoked")
            {
                if (remote.Status is not ("active" or "pending" or "expired"))
                    throw new InvalidDataException("Unsupported Agent registration terminal state.");
                await _remote.RevokeRegistrationAsync(authenticatedSession,
                    remote.RegistrationId, actual.KeyThumbprint, cancellationToken);
            }
            _receipts.RemoveReceipt(binding, _keys);
            _keys.RemoveLocalKey(binding);
        }
        finally { _gate.Release(); }
    }
}
