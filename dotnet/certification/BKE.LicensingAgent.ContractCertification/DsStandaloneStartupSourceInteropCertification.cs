using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Infrastructure;

/// <summary>
/// CI-only cross-repository contract: verify bytes actually signed by the
/// pinned DS source function (under disposable mocked SQL + test Ed25519).
/// It is NOT a real DS key, enrollment, credential, installed SYSTEM grant,
/// actual SQL transaction, production issuer or permission for an install.
/// </summary>
internal static class DsStandaloneStartupSourceInteropCertification
{
    public static async Task VerifyAsync(string vectorPath, string expectedDsSha)
    {
        if (!OperatingSystem.IsWindows() ||
            Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true" ||
            Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT") != "github-hosted" ||
            Environment.GetEnvironmentVariable("RUNNER_OS") != "Windows")
            throw new InvalidOperationException(
                "DS-to-Agent source interop requires disposable hosted Windows CI.");
        if (expectedDsSha.Length != 40 ||
            expectedDsSha.Any(c => !Uri.IsHexDigit(c) ||
                char.IsUpper(c)))
            throw new InvalidDataException("Exact lowercase merged DS SHA required.");
        var root = Environment.GetEnvironmentVariable("RUNNER_TEMP") ??
            throw new InvalidOperationException("RUNNER_TEMP missing.");
        var allowed = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar)
            + Path.DirectorySeparatorChar;
        var filename = Path.GetFullPath(vectorPath);
        if (!filename.StartsWith(allowed, StringComparison.OrdinalIgnoreCase) ||
            !filename.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException(
                "Public test vector must stay under disposable runner temp.");
        var info = new FileInfo(filename);
        if (!info.Exists || info.Length is < 500 or > 24000 ||
            (info.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("DS source vector absent/redirected/oversized.");
        var raw = File.ReadAllText(filename, new UTF8Encoding(false, true));
        if (raw.Contains("PRIVATE KEY", StringComparison.OrdinalIgnoreCase) ||
            raw.Length > 24_000)
            throw new InvalidDataException("DS source vector contains private material.");
        using var document = JsonDocument.Parse(raw, new JsonDocumentOptions {
            AllowTrailingCommas = false, CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 6
        });
        var rootJson = document.RootElement;
        var names = rootJson.EnumerateObject().Select(p => p.Name).ToArray();
        var expectedFields = new HashSet<string>(StringComparer.Ordinal) {
            "schema", "classification", "ds_source_sha", "kid",
            "public_key_pem", "signed_policy_envelope"
        };
        if (names.Length != expectedFields.Count ||
            !names.ToHashSet(StringComparer.Ordinal).SetEquals(expectedFields) ||
            rootJson.GetProperty("schema").GetString() !=
                "bke.ds-agent-startup-source-interop.v1" ||
            rootJson.GetProperty("classification").GetString() !=
                "EPHEMERAL_TEST_KEY_NOT_REAL_DS_ISSUER" ||
            rootJson.GetProperty("ds_source_sha").GetString() != expectedDsSha)
            throw new InvalidDataException("DS fixture schema, signer class or SHA drift.");

        var kid = rootJson.GetProperty("kid").GetString() ??
            throw new InvalidDataException("DS issuer KID missing");
        var publicPem = rootJson.GetProperty("public_key_pem").GetString() ??
            throw new InvalidDataException("DS public SPKI missing");
        var envelope = rootJson.GetProperty("signed_policy_envelope").GetString() ??
            throw new InvalidDataException("DS policy envelope missing");
        if (!publicPem.StartsWith("-----BEGIN PUBLIC KEY-----",
                StringComparison.Ordinal) || publicPem.Length > 2048 ||
            envelope.Length > 16384)
            throw new InvalidDataException("DS public key or envelope bounds exceeded.");

        // This is the ACTUAL Agent installed issuer public trust parser,
        // including its immutable originally certified DS + library pin.
        var trustBundle = JsonSerializer.Serialize(new {
            schema = AccountProductLeaseInstalledTrust.BundleSchema,
            issuer_source_sha = AccountProductLeaseInstalledTrust.ExactIssuerSourceSha,
            library_archive_sha256 = AccountProductLeaseInstalledTrust.ExactLibraryArchiveSha256,
            keys = new [] { new {
                kid, public_key_pem = publicPem, state = "ACTIVE"
            } }
        });
        var keys = AccountProductLeaseInstalledTrust.Parse(trustBundle);
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var now = DateTimeOffset.UtcNow;
        var verified = InstalledStandaloneStartupPolicyRegistry.VerifyEnvelope(
            envelope, keys, programFiles, now);
        var expectedImage = Path.GetFullPath(Path.Combine(programFiles,
            "BKE Digital Solutions", "Render Dock", "RENDER DOCK.exe"));
        if (verified.ProductId != "bke-render-dock" ||
            verified.Version != "1.0.3" ||
            verified.ActivationMode != "LICENSE_KEY" ||
            verified.InstallationId != "00000000-0000-0000-0000-000000000001" ||
            !string.Equals(verified.ImagePath, expectedImage,
                StringComparison.OrdinalIgnoreCase) ||
            verified.ImageSha256 != new string('a', 64) ||
            verified.AllowedUserSid != "S-1-5-21-101-202-303-1001")
            throw new InvalidDataException(
                "Actual Agent verifier rejected DS SQL-mode/test-image/SID binding.");

        var registry = InstalledStandaloneStartupPolicyRegistry.ForCertification(
            [envelope], keys, programFiles, now);
        var observed = new StandaloneStartupProcessEvidence(
            19999, DateTime.UtcNow.AddSeconds(-1).Ticks,
            expectedImage, verified.ImageSha256, verified.AllowedUserSid,
            now, WindowsKernelObserved: true);
        var installation = await registry.ResolveVerifiedAsync(
            observed, CancellationToken.None);
        var mode = await registry.ReadVerifiedAsync(
            "bke-render-dock", "1.0.3", CancellationToken.None);
        if (installation?.InstallationId != verified.InstallationId ||
            mode?.ActivationMode != "LICENSE_KEY")
            throw new InvalidDataException(
                "DS signed test policy failed native Agent installed identity lookup.");
        if (await registry.ResolveVerifiedAsync(
                observed with { ImageSha256 = new string('b', 64) },
                CancellationToken.None) is not null ||
            await registry.ResolveVerifiedAsync(
                observed with { UserSid = "S-1-5-21-999-999-999-111" },
                CancellationToken.None) is not null)
            throw new InvalidDataException("DS signed vector allowed wrong image or SID.");

        void Reject(string changed, string reason)
        {
            bool rejected = false;
            try
            {
                _ = InstalledStandaloneStartupPolicyRegistry.VerifyEnvelope(
                    changed, keys, programFiles, now);
            }
            catch (Exception error) when (error is InvalidDataException or
                JsonException or FormatException or CryptographicException)
            {
                rejected = true;
            }
            if (!rejected)
                throw new InvalidDataException(
                    "Agent accepted altered DS producer bytes: " + reason);
        }
        if (!envelope.Contains("LICENSE_KEY", StringComparison.Ordinal))
            throw new InvalidDataException("DS signed payload missing SQL mode.");
        Reject(envelope.Replace("LICENSE_KEY", "ACCOUNT", StringComparison.Ordinal),
            "tampered DS-selected activation mode");
        using var original = JsonDocument.Parse(envelope);
        var e = original.RootElement;
        Reject(JsonSerializer.Serialize(new {
            schema = InstalledStandaloneStartupPolicyRegistry.EnvelopeSchema,
            kid = kid + "-impostor",
            payload = e.GetProperty("payload").GetString(),
            signature = e.GetProperty("signature").GetString()
        }), "unregistered signing identity");

        Console.WriteLine(
            "DS_SOURCE_TO_AGENT_NATIVE_ED25519_INTEROP_PASS: exact pinned " +
            "real DS test-signature bytes verified by Agent, image/SID/mode " +
            "matched, tampering denied; mocked SQL and test key ONLY.");
    }
}
