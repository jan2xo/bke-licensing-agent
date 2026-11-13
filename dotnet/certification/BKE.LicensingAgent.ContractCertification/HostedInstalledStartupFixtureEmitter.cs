using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using BKE.LicensingAgent.Infrastructure;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

/// <summary>
/// Emits ONLY a public issuer trust bundle and an ephemeral Ed25519 signed
/// startup policy for a single hosted disposable Windows certification run.
/// No private key is persisted or printed. Not a Digital Solutions issuer,
/// customer entitlement, production bootstrap, or release-authority tool.
/// This is called only by the cross-repo installed Render Dock CI denial test.
/// </summary>
internal static class HostedInstalledStartupFixtureEmitter
{
    private const string ProductId = "bke-render-dock";
    private const string Version = "1.0.3";
    private const string InstallationId = "00000000-0000-0000-0000-000000000138";
    private const string IssuerKid = "disposable-github-actions-test-only";

    public static void Emit(string outputDirectory, string imageToHash, string targetInstalledImage)
    {
        if (!OperatingSystem.IsWindows() ||
            Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true" ||
            Environment.GetEnvironmentVariable("BKE_ENVIRONMENT") != "certification")
            throw new InvalidOperationException(
                "Ephemeral startup signing fixture is restricted to disposable Windows GitHub Actions certification.");

        var temp = Environment.GetEnvironmentVariable("RUNNER_TEMP");
        if (string.IsNullOrWhiteSpace(temp))
            throw new InvalidOperationException("GitHub-hosted runner temporary root missing.");

        var tmpRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(temp));
        var output = Path.GetFullPath(outputDirectory);
        if (!output.StartsWith(tmpRoot + Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase) ||
            Directory.Exists(output) || File.Exists(output))
            throw new InvalidOperationException(
                "Fixture output must be a new directory inside RUNNER_TEMP; never a repository or installed trust folder.");

        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        if (string.IsNullOrWhiteSpace(programFiles))
            throw new InvalidOperationException("Windows Program Files path missing.");

        var expectedImage = Path.GetFullPath(Path.Combine(programFiles,
            "BKE Digital Solutions", "Render Dock", "RENDER DOCK.exe"));
        if (!string.Equals(Path.GetFullPath(targetInstalledImage), expectedImage,
                StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(
                "Signed test policy must bind only the exact Render Dock installed executable path.");

        var compiled = Path.GetFullPath(imageToHash);
        var info = new FileInfo(compiled);
        if (!info.Exists || info.Length is < 1024 or > 500_000_000 ||
            !compiled.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
            (info.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("Reviewed executable is unavailable, redirected or oversized.");

        var sid = WindowsIdentity.GetCurrent().User?.Value;
        if (string.IsNullOrWhiteSpace(sid) || !sid.StartsWith("S-1-", StringComparison.Ordinal))
            throw new InvalidOperationException("Real hosted Windows account SID unavailable.");

        var digest = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(compiled)))
            .ToLowerInvariant();
        var now = DateTimeOffset.UtcNow;

        // The signing private seed and signing object exist ONLY in this
        // disposable test process; neither is copied into Program Files,
        // uploaded as CI artifact, committed nor emitted to logs.
        var seed = RandomNumberGenerator.GetBytes(32);
        string signature;
        string publicPem;
        try
        {
            var signingKey = new Ed25519PrivateKeyParameters(seed, 0);
            var publicDer = Convert.FromHexString("302A300506032B6570032100")
                .Concat(signingKey.GeneratePublicKey().GetEncoded()).ToArray();
            publicPem = "-----BEGIN PUBLIC KEY-----\n" +
                Convert.ToBase64String(publicDer) + "\n-----END PUBLIC KEY-----\n";

            var payload = JsonSerializer.Serialize(new {
                schema = InstalledStandaloneStartupPolicyRegistry.PayloadSchema,
                issuer_source_sha = AccountProductLeaseInstalledTrust.ExactIssuerSourceSha,
                product_id = ProductId,
                version = Version,
                installation_id = InstallationId,
                image_path = expectedImage,
                image_sha256 = digest,
                allowed_user_sid = sid,
                activation_mode = "LICENSE_KEY",
                not_before = now.AddMinutes(-2).ToString("O"),
                expires_at = now.AddHours(2).ToString("O")
            });

            var message = Encoding.UTF8.GetBytes(
                InstalledStandaloneStartupPolicyRegistry.Domain + payload);
            var signer = new Ed25519Signer();
            signer.Init(true, signingKey);
            signer.BlockUpdate(message, 0, message.Length);
            signature = Convert.ToBase64String(signer.GenerateSignature());
            var policy = JsonSerializer.Serialize(new {
                schema = InstalledStandaloneStartupPolicyRegistry.EnvelopeSchema,
                kid = IssuerKid,
                payload,
                signature
            });
            var trust = JsonSerializer.Serialize(new {
                schema = AccountProductLeaseInstalledTrust.BundleSchema,
                issuer_source_sha = AccountProductLeaseInstalledTrust.ExactIssuerSourceSha,
                library_archive_sha256 = AccountProductLeaseInstalledTrust.ExactLibraryArchiveSha256,
                keys = new [] { new {
                    kid = IssuerKid,
                    public_key_pem = publicPem,
                    state = "ACTIVE"
                } }
            });

            // Verify with the REAL installed parsers before emitting any
            // public-only bundle. These tests do not establish DS issuance.
            var trusted = AccountProductLeaseInstalledTrust.Parse(trust);
            var verified = InstalledStandaloneStartupPolicyRegistry.VerifyEnvelope(
                policy, trusted, programFiles, now);
            if (verified.ProductId != ProductId ||
                verified.Version != Version ||
                verified.ImageSha256 != digest ||
                verified.AllowedUserSid != sid ||
                verified.ActivationMode != "LICENSE_KEY" ||
                verified.ImagePath != expectedImage)
                throw new InvalidOperationException(
                    "Fixture signature or exact installed identity did not verify.");

            var trustDir = Path.Combine(output, "account-product-lease-keys");
            var policyDir = Path.Combine(output, "standalone-startup-policies");
            Directory.CreateDirectory(trustDir);
            Directory.CreateDirectory(policyDir);
            File.WriteAllText(Path.Combine(trustDir, "issuers.json"),
                trust, new UTF8Encoding(false));
            File.WriteAllText(Path.Combine(policyDir, "bke-render-dock.json"),
                policy, new UTF8Encoding(false));
            Console.WriteLine("DISPOSABLE_SIGNED_POLICY_FIXTURE_PASS: public-only trust and exact-image test policy; no commercial credential.");
            Console.WriteLine("Image SHA256: " + digest);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
        }
    }
}
