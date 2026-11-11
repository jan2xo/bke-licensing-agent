using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace BKE.LicensingAgent.Infrastructure;

/// <summary>
/// Windows CNG Microsoft Platform Crypto Provider (TPM 2.0) persisted,
/// non-exportable ECDSA P-256 key. This is local provider provenance, not
/// remotely verified TPM attestation. Public registration should therefore
/// retain SOFTWARE-level assurance until a separate attestation is certified.
/// No private key bytes are ever imported or exported by this class.
/// </summary>
public sealed class WindowsTpmEcdsaP256MachineKeyStore : IAgentMachineKeySigner
{
    private const string Protocol = "bke.agent-key-proof.v1";
    private const string MetadataDomain = "bke.agent-tpm-p256-local-marker.v1";
    private readonly string _marker;
    private static readonly CngProvider Provider = CngProvider.MicrosoftPlatformCryptoProvider;

    private sealed record SignedKeyMarker(
        string Version, string KeyName, string BindingHash, string Thumbprint,
        string SignatureBase64url);

    public WindowsTpmEcdsaP256MachineKeyStore(string? dataDirectory = null)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("TPM CNG signing requires Windows.");
        string root = dataDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "BKE Digital Solutions", "Licensing Agent");
        if (string.IsNullOrWhiteSpace(root))
            throw new InvalidOperationException("Agent user profile is unavailable.");
        _marker = Path.Combine(Path.GetFullPath(root), "machine-trust",
            "agent-p256-tpm.marker.json");
    }

    public bool HasStoredIdentity => File.Exists(_marker);

    public AgentEd25519PublicIdentity GetOrCreateIdentity(
        AgentEd25519SessionBinding binding, bool createIfMissing = true)
    {
        var digest = BindingHash(binding);
        string name = KeyName(digest);
        if (File.Exists(_marker))
        {
            using var key = OpenValidated(name, digest);
            return PublicIdentity(key);
        }
        if (!createIfMissing)
            throw new InvalidDataException("TPM Agent identity is missing.");
        // A CNG key without its signed binding marker is an interrupted
        // enrollment. It may not be claimed or overwritten silently.
        if (CngKey.Exists(name, Provider))
            throw new InvalidDataException("Unreconciled TPM key requires explicit recovery.");
        CngKey created;
        try
        {
            created = CngKey.Create(CngAlgorithm.ECDsaP256, name,
                new CngKeyCreationParameters
                {
                    Provider = Provider,
                    ExportPolicy = CngExportPolicies.None,
                    KeyUsage = CngKeyUsages.Signing,
                    KeyCreationOptions = CngKeyCreationOptions.None,
                });
        }
        catch (CryptographicException error)
        {
            throw new AgentTpmUnavailableException(
                "TPM P-256 key creation was refused; explicit software fallback may be chosen.", error);
        }
        using (created)
        {
            bool published = false;
            string? temporary = null;
            try
            {
                var identity = PublicIdentity(created);
                byte[] proof = MarkerBytes(name, Convert.ToHexString(digest),
                    identity.KeyThumbprint);
                using var signer = new ECDsaCng(created);
                byte[] signature = signer.SignData(proof, HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
                var marker = new SignedKeyMarker(MetadataDomain, name,
                    Convert.ToHexString(digest), identity.KeyThumbprint,
                    Base64Url(signature));
                string directory = Path.GetDirectoryName(_marker)!;
                Directory.CreateDirectory(directory);
                temporary = Path.Combine(directory, ".agent-tpm-" + Guid.NewGuid().ToString("N"));
                File.WriteAllText(temporary, JsonSerializer.Serialize(marker), Encoding.UTF8);
                File.Move(temporary, _marker, overwrite: false);
                temporary = null;
                published = true;
                return identity;
            }
            finally
            {
                if (temporary is not null) { try { File.Delete(temporary); } catch { } }
                // Unpublished CNG keys must not be left as orphaned replacements.
                if (!published) { try { created.Delete(); } catch { } }
            }
        }
    }

    public string SignChallenge(
        AgentEd25519SessionBinding binding, string registrationId, string challengeId,
        string messageBase64url, DateTimeOffset expiresAt,
        string? productId = null, string? action = null)
    {
        byte[] digest = BindingHash(binding);
        if (!CanonicalUuid(registrationId) || !CanonicalUuid(challengeId))
            throw new InvalidDataException("TPM Agent challenge references must be canonical UUID.");
        var now = DateTimeOffset.UtcNow;
        if (expiresAt <= now || expiresAt > now.AddSeconds(35))
            throw new InvalidDataException("TPM Agent challenge expiry is invalid.");
        byte[] message = Decode(messageBase64url);
        try
        {
            string[] fields;
            try { fields = new UTF8Encoding(false, true).GetString(message).Split('\n'); }
            catch (DecoderFallbackException error)
            {
                throw new InvalidDataException("TPM Agent challenge must be UTF-8.", error);
            }
            if (fields.Length != 11 || fields[0] != Protocol ||
                fields[2] != challengeId || fields[3] != registrationId ||
                fields[4] != binding.SessionId || fields[5] != binding.AccountId ||
                fields[6] != binding.UserId || fields[7] != binding.DeviceId ||
                !CanonicalUuid(fields[2]) || !CanonicalUuid(fields[3]) ||
                !ValidNonce(fields[10]))
                throw new InvalidDataException("TPM Agent challenge changed its trusted binding.");
            if (fields[1] == "ENROLL")
            {
                if (productId is not null || action is not null ||
                    fields[8] != "-" || fields[9] != "-")
                    throw new InvalidDataException("ENROLL TPM challenge must be unscoped.");
            }
            else if (fields[1] == "LEASE")
            {
                if (!ValidProduct(productId) || action is not ("OPEN" or "USE") ||
                    fields[8] != productId || fields[9] != action)
                    throw new InvalidDataException("LEASE TPM challenge scope mismatch.");
            }
            else throw new InvalidDataException("TPM challenge purpose invalid.");

            using var key = OpenValidated(KeyName(digest), digest);
            using var ecdsa = new ECDsaCng(key);
            byte[] signature = ecdsa.SignData(message, HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            try
            {
                if (signature.Length != 64)
                    throw new InvalidDataException("TPM ES256 signature must be 64-byte P1363.");
                return Base64Url(signature);
            }
            finally { CryptographicOperations.ZeroMemory(signature); }
        }
        finally { CryptographicOperations.ZeroMemory(message); }
    }

    /// <summary>
    /// Local-only removal; authenticated DS revocation MUST happen beforehand.
    /// Do not silently rotate a remote registration by deleting this key.
    /// </summary>
    public void RemoveLocalKey(AgentEd25519SessionBinding binding)
    {
        var digest = BindingHash(binding);
        using var key = OpenValidated(KeyName(digest), digest);
        key.Delete();
        File.Delete(_marker);
    }

    private CngKey OpenValidated(string expectedName, byte[] digest)
    {
        SignedKeyMarker marker;
        try
        {
            string text = File.ReadAllText(_marker, Encoding.UTF8);
            if (text.Length < 80 || text.Length > 4096)
                throw new InvalidDataException("TPM binding marker size invalid.");
            marker = JsonSerializer.Deserialize<SignedKeyMarker>(text)
                ?? throw new InvalidDataException("TPM binding marker missing.");
        }
        catch (JsonException error)
        {
            throw new InvalidDataException("TPM binding marker malformed.", error);
        }
        if (marker.Version != MetadataDomain || marker.KeyName != expectedName ||
            marker.BindingHash != Convert.ToHexString(digest) ||
            marker.Thumbprint.Length != 43)
            throw new InvalidDataException("TPM key metadata belongs to a different Agent session.");
        if (!CngKey.Exists(expectedName, Provider))
            throw new InvalidDataException("Registered TPM key vanished; never re-create silently.");
        CngKey key = CngKey.Open(expectedName, Provider);
        try
        {
            var identity = PublicIdentity(key);
            if (identity.KeyThumbprint != marker.Thumbprint)
                throw new InvalidDataException("TPM key identity does not match its signed marker.");
            byte[] signature = Decode(marker.SignatureBase64url);
            try
            {
                using var pub = ECDsa.Create();
                using var signer = new ECDsaCng(key);
                byte[] spki = signer.ExportSubjectPublicKeyInfo();
                pub.ImportSubjectPublicKeyInfo(spki, out var count);
                if (count != spki.Length ||
                    !pub.VerifyData(MarkerBytes(marker.KeyName, marker.BindingHash,
                        marker.Thumbprint), signature, HashAlgorithmName.SHA256,
                        DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
                    throw new InvalidDataException("TPM key metadata signature invalid.");
                return key;
            }
            finally { CryptographicOperations.ZeroMemory(signature); }
        }
        catch { key.Dispose(); throw; }
    }

    private static AgentEd25519PublicIdentity PublicIdentity(CngKey key)
    {
        if (key.Provider != Provider || key.Algorithm.Algorithm != CngAlgorithm.ECDsaP256.Algorithm ||
            key.ExportPolicy != CngExportPolicies.None)
            throw new InvalidDataException("TPM provider, curve or export policy invalid.");
        using var signer = new ECDsaCng(key);
        byte[] spki = signer.ExportSubjectPublicKeyInfo();
        using var pub = ECDsa.Create();
        pub.ImportSubjectPublicKeyInfo(spki, out int read);
        if (read != spki.Length || pub.KeySize != 256)
            throw new InvalidDataException("TPM public key is not ECDSA P-256.");
        string pem = "-----BEGIN PUBLIC KEY-----\n" +
            Convert.ToBase64String(spki, Base64FormattingOptions.InsertLineBreaks)
                .Replace("\r\n", "\n") +
            "\n-----END PUBLIC KEY-----\n";
        // Local "tpm-unverified" means KSP was selected, not that DS validated
        // an attestation. The DS entitlement claim remains "software".
        return new AgentEd25519PublicIdentity(pem,
            Base64Url(SHA256.HashData(spki)), "tpm-unverified", "ES256");
    }

    private static byte[] BindingHash(AgentEd25519SessionBinding binding)
    {
        ArgumentNullException.ThrowIfNull(binding);
        foreach (var value in new[] { binding.SessionId, binding.AccountId,
                     binding.UserId, binding.DeviceId })
            if (string.IsNullOrWhiteSpace(value) || value.Length > 256 ||
                value.Any(ch => ch < '!' || ch > '~' || ch == '\\'))
                throw new InvalidDataException("TPM Agent binding must be canonical printable data.");
        return SHA256.HashData(Encoding.UTF8.GetBytes(
            "bke.agent-key-binding.v1\n" + binding.SessionId + "\n" +
            binding.AccountId + "\n" + binding.UserId + "\n" + binding.DeviceId));
    }

    private static string KeyName(byte[] bindingHash) =>
        "BKE-AGENT-P256-" + Convert.ToHexString(bindingHash);

    private static byte[] MarkerBytes(string name, string binding, string thumbprint) =>
        Encoding.UTF8.GetBytes(MetadataDomain + "\n" + name + "\n" + binding + "\n" + thumbprint);

    private static bool CanonicalUuid(string text) =>
        Guid.TryParseExact(text, "D", out var id) && id.ToString("D") == text;

    private static bool ValidProduct(string? text) =>
        text is { Length: > 0 and <= 128 } &&
        text.All(ch => char.IsAsciiLetterOrDigit(ch) || ch is '.' or '-' or '_');

    private static bool ValidNonce(string value)
    {
        try { return Decode(value).Length == 32; }
        catch (FormatException) { return false; }
    }

    private static byte[] Decode(string value)
    {
        if (string.IsNullOrEmpty(value) || value.Length > 4096 ||
            value.Any(ch => !char.IsAsciiLetterOrDigit(ch) && ch is not '-' and not '_'))
            throw new FormatException("Agent base64url is invalid.");
        var normalized = value.Replace('-', '+').Replace('_', '/');
        var bytes = Convert.FromBase64String(normalized.PadRight(
            (normalized.Length + 3) / 4 * 4, '='));
        if (Base64Url(bytes) != value) throw new FormatException("Noncanonical Agent base64url.");
        return bytes;
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

public sealed class AgentTpmUnavailableException : CryptographicException
{
    public AgentTpmUnavailableException(string message, CryptographicException inner)
        : base(message, inner) { }
}

/// <summary>
/// Explicit selection: retain an existing session key, prefer new TPM P-256,
/// and permit Ed25519 DPAPI fallback only when the caller deliberately allows
/// it and first TPM provision was unavailable. Never downgrade an enrolled TPM.
/// </summary>
public static class WindowsPreferredAgentMachineKey
{
    public static IAgentMachineKeySigner Open(
        AgentEd25519SessionBinding binding, string? dataDirectory = null,
        bool allowSoftwareFallback = false)
    {
        var hardware = new WindowsTpmEcdsaP256MachineKeyStore(dataDirectory);
        var software = new WindowsDpapiEd25519MachineKeyStore(dataDirectory);
        if (hardware.HasStoredIdentity && software.HasStoredIdentity)
            throw new InvalidDataException("Conflicting Agent hardware and software identity.");
        if (hardware.HasStoredIdentity)
        {
            hardware.GetOrCreateIdentity(binding, createIfMissing: false);
            return hardware;
        }
        if (software.HasStoredIdentity)
        {
            software.GetOrCreateIdentity(binding, createIfMissing: false);
            return software;
        }
        try
        {
            hardware.GetOrCreateIdentity(binding);
            return hardware;
        }
        catch (AgentTpmUnavailableException) when (allowSoftwareFallback)
        {
            software.GetOrCreateIdentity(binding);
            return software;
        }
    }
}
