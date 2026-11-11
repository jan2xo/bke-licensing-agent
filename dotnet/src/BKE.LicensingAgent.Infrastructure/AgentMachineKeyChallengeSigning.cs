namespace BKE.LicensingAgent.Infrastructure;

// Trusted host software-key abstraction used only for cross-process HTTP certification.
// Production implementation stays the Windows user-DPAPI encrypted key store.
// A single named friend assembly supplies an EPHEMERAL signing test double.
internal interface IAgentMachineKeyChallengeSigning
{
    AgentEd25519PublicIdentity GetOrCreateIdentity(
        AgentEd25519SessionBinding binding, bool createIfMissing = true);

    string SignChallenge(
        AgentEd25519SessionBinding binding, string registrationId, string challengeId,
        string messageBase64url, DateTimeOffset expiresAt,
        string? productId = null, string? action = null);
}
