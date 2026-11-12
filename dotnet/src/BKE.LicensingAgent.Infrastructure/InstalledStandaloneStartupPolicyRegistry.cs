using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using BKE.LicensingAgent.Application;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.OpenSsl;

namespace BKE.LicensingAgent.Infrastructure;

/// <summary>
/// PREPRODUCTION installed, signature-verified projection of DS SQL activation
/// mode and the exact authorized executable/installation/user binding.
/// It is NOT a live SQL policy reader. No signed policy means no grant.
/// </summary>
public sealed class InstalledStandaloneStartupPolicyRegistry :
    ITrustedStandaloneStartupRegistry, ITrustedStandaloneStartupPolicySource
{
    internal const string EnvelopeSchema = "bke.standalone-startup-envelope.v1";
    internal const string PayloadSchema = "bke.standalone-startup-policy.v1";
    internal const string Domain = "BKE-STANDALONE-STARTUP-POLICY-V1\n";
    private static readonly Regex Hex = new("^[0-9a-f]{64}$", RegexOptions.CultureInvariant);
    private static readonly Regex Slug = new("^[a-z0-9]+(?:-[a-z0-9]+)*$", RegexOptions.CultureInvariant);
    private static readonly Regex Version = new(
        @"^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$", RegexOptions.CultureInvariant);
    private static readonly Regex Kid = new("^[A-Za-z0-9._-]{1,128}$", RegexOptions.CultureInvariant);
    private static readonly string[] EnvelopeFields = ["schema", "kid", "payload", "signature"];
    private static readonly string[] PayloadFields = [
        "schema", "issuer_source_sha", "product_id", "version", "installation_id",
        "image_path", "image_sha256", "allowed_user_sid", "activation_mode",
        "not_before", "expires_at"
    ];

    private readonly IReadOnlyList<SignedInstallation> _policies;

    private InstalledStandaloneStartupPolicyRegistry(
        IReadOnlyList<SignedInstallation> policies) => _policies = policies;

    public static InstalledStandaloneStartupPolicyRegistry LoadInstalled(
        string environment,
        IReadOnlyDictionary<string, AccountProductLeaseTrustedKey> issuerKeys)
    {
        if (environment is not ("development" or "certification" or "utm") ||
            !OperatingSystem.IsWindows())
            throw new InvalidOperationException(
                "Installed startup authority is restricted to PREPRODUCTION Windows.");
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        if (string.IsNullOrWhiteSpace(programFiles))
            throw new InvalidDataException("Program Files trust root is unavailable.");
        var agentRoot = Path.GetFullPath(Path.Combine(
            programFiles, "BKE Digital Solutions", "Licensing Agent"));
        var expectedRuntime = Path.GetFullPath(Path.Combine(agentRoot, "runtime"));
        if (!string.Equals(
                Path.TrimEndingDirectorySeparator(Path.GetFullPath(AppContext.BaseDirectory)),
                Path.TrimEndingDirectorySeparator(expectedRuntime),
                StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Agent startup trust cannot run from an uninstalled binary.");

        var trust = Path.Combine(agentRoot, "trust");
        var dir = Path.Combine(trust, "standalone-startup-policies");
        foreach (var folder in new[] { agentRoot, expectedRuntime, trust, dir })
        {
            var info = new DirectoryInfo(folder);
            if (!info.Exists || (info.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Installed startup policy path is absent or redirected.");
        }

        var paths = Directory.GetFiles(dir, "*.json", SearchOption.TopDirectoryOnly);
        if (paths.Length is < 1 or > 128)
            throw new InvalidDataException("Installed startup policy count is invalid.");

        var records = new List<SignedInstallation>();
        var now = DateTimeOffset.UtcNow;
        foreach (var path in paths.Order(StringComparer.Ordinal))
        {
            var file = new FileInfo(path);
            if ((file.Attributes & FileAttributes.ReparsePoint) != 0 ||
                file.Length is < 100 or > 16384)
                throw new InvalidDataException("Installed startup policy is redirected or oversized.");
            var text = File.ReadAllText(path, new UTF8Encoding(false, true));
            records.Add(VerifyEnvelope(text, issuerKeys, programFiles, now));
        }

        // Ambiguous product-version or installed image identities are denied.
        if (records.GroupBy(p => (p.ProductId, p.Version)).Any(g => g.Count() != 1) ||
            records.GroupBy(p => (p.ImagePath.ToUpperInvariant(),
                                  p.AllowedUserSid.ToUpperInvariant()))
                .Any(g => g.Count() != 1))
            throw new InvalidDataException("Installed startup policy has ambiguous authority.");

        return new InstalledStandaloneStartupPolicyRegistry(records.AsReadOnly());
    }

    // Certification-only parser. Host always uses LoadInstalled and immutable
    // Program Files paths; it cannot inject arbitrary trusted roots or keys.
    internal static SignedInstallation VerifyEnvelope(
        string envelope,
        IReadOnlyDictionary<string, AccountProductLeaseTrustedKey> keys,
        string trustedProgramFiles,
        DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(envelope) ||
            Encoding.UTF8.GetByteCount(envelope) > 16384 ||
            envelope[0] == '\uFEFF' ||
            envelope.Contains("PRIVATE KEY", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Startup policy text is unavailable or unsafe.");

        using var json = JsonDocument.Parse(envelope, new JsonDocumentOptions {
            AllowTrailingCommas = false, CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 5
        });
        var root = json.RootElement;
        RequireFields(root, EnvelopeFields);
        if (Required(root, "schema") != EnvelopeSchema)
            throw new InvalidDataException("Unknown startup policy signature envelope.");
        string kid = Required(root, "kid");
        string payload = Required(root, "payload", 8192);
        string signature = Required(root, "signature", 256);
        if (!Kid.IsMatch(kid) || keys is null ||
            !keys.TryGetValue(kid, out var trusted) ||
            trusted.State is not ("ACTIVE" or "VERIFY_ONLY"))
            throw new InvalidDataException("Startup signer is not an installed trusted issuer.");

        // Exact canonical base64; no URL decoding or permissive padding.
        byte[] sig;
        try
        {
            sig = Convert.FromBase64String(signature);
        }
        catch (FormatException error)
        {
            throw new InvalidDataException("Invalid startup signature encoding.", error);
        }
        if (sig.Length != 64 ||
            !string.Equals(Convert.ToBase64String(sig), signature, StringComparison.Ordinal))
            throw new InvalidDataException("Invalid startup Ed25519 signature.");

        Ed25519PublicKeyParameters publicKey;
        try
        {
            using var reader = new StringReader(trusted.PublicKeyPem);
            publicKey = new PemReader(reader).ReadObject() as Ed25519PublicKeyParameters
                ?? throw new InvalidDataException("Installed startup key is not Ed25519.");
        }
        catch (Exception error)
        {
            throw new InvalidDataException("Malformed installed startup public key.", error);
        }

        var signedBytes = Encoding.UTF8.GetBytes(Domain + payload);
        var verifier = new Ed25519Signer();
        verifier.Init(false, publicKey);
        verifier.BlockUpdate(signedBytes, 0, signedBytes.Length);
        if (!verifier.VerifySignature(sig))
            throw new InvalidDataException("Invalid standalone startup policy signature.");

        using var policyDocument = JsonDocument.Parse(payload, new JsonDocumentOptions {
            AllowTrailingCommas = false, CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 5
        });
        var p = policyDocument.RootElement;
        RequireFields(p, PayloadFields);
        string product = Required(p, "product_id", 128);
        string version = Required(p, "version", 128);
        string installationId = Required(p, "installation_id", 64);
        string image = Required(p, "image_path", 2048);
        string sha = Required(p, "image_sha256", 64);
        string user = Required(p, "allowed_user_sid", 256);
        string mode = Required(p, "activation_mode", 16);
        DateTimeOffset from = RequiredTime(p, "not_before");
        DateTimeOffset until = RequiredTime(p, "expires_at");
        if (Required(p, "schema") != PayloadSchema ||
            Required(p, "issuer_source_sha") !=
                AccountProductLeaseInstalledTrust.ExactIssuerSourceSha ||
            !Slug.IsMatch(product) || !Version.IsMatch(version) ||
            !Guid.TryParseExact(installationId, "D", out _) ||
            !Hex.IsMatch(sha) || user.Length < 6 ||
            !user.StartsWith("S-1-", StringComparison.Ordinal) ||
            mode is not ("ACCOUNT" or "LICENSE_KEY" or "EITHER") ||
            from > now.AddSeconds(30) || until <= now ||
            until <= from || until - from > TimeSpan.FromDays(366))
            throw new InvalidDataException("Startup policy scope, mode or lifetime is invalid.");

        var rootPath = Path.GetFullPath(Path.Combine(
            trustedProgramFiles, "BKE Digital Solutions"));
        string normalized;
        try { normalized = Path.GetFullPath(image); }
        catch (Exception error) when (error is ArgumentException or NotSupportedException
            or PathTooLongException)
        {
            throw new InvalidDataException("Startup image path is invalid.", error);
        }
        if (!string.Equals(image, normalized, StringComparison.Ordinal) ||
            !normalized.StartsWith(
                Path.TrimEndingDirectorySeparator(rootPath) +
                Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Startup executable is outside trusted install root.");

        return new SignedInstallation(product, version, installationId,
            normalized, sha, user, mode);
    }

    public Task<TrustedStandaloneStartupInstallation?> ResolveVerifiedAsync(
        StandaloneStartupProcessEvidence peer, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var matching = _policies.Where(p =>
            string.Equals(p.ImagePath, peer.ImagePath, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(p.ImageSha256, peer.ImageSha256, StringComparison.Ordinal) &&
            string.Equals(p.AllowedUserSid, peer.UserSid, StringComparison.Ordinal))
            .Take(2).ToArray();
        return Task.FromResult<TrustedStandaloneStartupInstallation?>(
            matching.Length == 1
                ? new(matching[0].ProductId, matching[0].Version,
                    matching[0].InstallationId, matching[0].ImagePath,
                    matching[0].ImageSha256, matching[0].AllowedUserSid)
                : null);
    }

    public Task<TrustedStandaloneStartupPolicy?> ReadVerifiedAsync(
        string productId, string version, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var matching = _policies.Where(p =>
            p.ProductId == productId && p.Version == version).Take(2).ToArray();
        return Task.FromResult<TrustedStandaloneStartupPolicy?>(
            matching.Length == 1
                ? new(matching[0].ProductId, matching[0].Version,
                    matching[0].ActivationMode)
                : null);
    }

    internal static void RequireFields(JsonElement obj, string[] allowed)
    {
        if (obj.ValueKind != JsonValueKind.Object ||
            obj.EnumerateObject().Count() != allowed.Length ||
            !obj.EnumerateObject().Select(x => x.Name)
                .ToHashSet(StringComparer.Ordinal)
                .SetEquals(allowed))
            throw new InvalidDataException("Startup policy contains missing, unknown or duplicate fields.");
    }

    private static string Required(JsonElement obj, string key, int max = 256)
    {
        if (!obj.TryGetProperty(key, out var x) || x.ValueKind != JsonValueKind.String)
            throw new InvalidDataException("Startup policy required text missing.");
        var s = x.GetString() ?? "";
        if (s.Length is < 1 or > 8192 || s.Length > max || s.Trim() != s)
            throw new InvalidDataException("Startup policy text field invalid.");
        return s;
    }

    private static DateTimeOffset RequiredTime(JsonElement obj, string key)
    {
        var text = Required(obj, key, 64);
        if (!DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture,
                DateTimeStyles.RoundtripKind, out var value) ||
            value.Offset != TimeSpan.Zero ||
            value.ToString("O", CultureInfo.InvariantCulture) != text)
            throw new InvalidDataException("Startup policy time is not canonical UTC.");
        return value;
    }

    internal sealed record SignedInstallation(
        string ProductId, string Version, string InstallationId,
        string ImagePath, string ImageSha256, string AllowedUserSid,
        string ActivationMode);
}
