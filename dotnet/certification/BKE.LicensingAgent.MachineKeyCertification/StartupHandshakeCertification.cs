using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Infrastructure;
using BKE.LicensingAgent.Provisioner;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

/// <summary>
/// Test-only native proof bridge. Uses actual Windows DPAPI + signed installed
/// target code, never a production API or an exported protected signing seed.
/// </summary>
internal static class StartupHandshakeCertification
{
    private static readonly JsonSerializerOptions JsonOptions =
        new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    public static void Emit(string output)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var productRoot = Path.Combine(programFiles, "BKE Digital Solutions", "Render Dock");
        if (Directory.Exists(productRoot))
            throw new InvalidOperationException("Disposable product root must be absent.");
        var exe = Path.Combine(productRoot, "RENDER DOCK.exe");
        var temp = Path.Combine(Path.GetTempPath(), "bke-startup-handshake-" + Guid.NewGuid().ToString("N"));
        var data = Path.Combine(temp, "ProgramData", "BKE Digital Solutions", "Licensing Agent");
        var privileged = Path.Combine(data, "privileged");
        var keys = Path.Combine(privileged, "target-keys");
        var policies = Path.Combine(privileged, "target-policies");
        var key = new Ed25519PrivateKeyParameters(RandomNumberGenerator.GetBytes(32), 0);
        var createdParent = !Directory.Exists(Path.GetDirectoryName(productRoot));
        try
        {
            Directory.CreateDirectory(productRoot);
            Directory.CreateDirectory(keys);
            Directory.CreateDirectory(policies);
            File.WriteAllText(exe, "DISPOSABLE BKE CROSS-REPO TEST BINARY, NOT A RELEASE", new UTF8Encoding(false));
            var pub = key.GeneratePublicKey().GetEncoded();
            var pem = "-----BEGIN PUBLIC KEY-----\n" +
                Convert.ToBase64String(Convert.FromHexString("302A300506032B6570032100").Concat(pub).ToArray()) +
                "\n-----END PUBLIC KEY-----\n";
            File.WriteAllText(Path.Combine(keys, "handshake-target.pem"), pem, new UTF8Encoding(false));
            var unsigned = new SortedDictionary<string, object?>(StringComparer.Ordinal) {
                ["schema"] = "bke.install-target-policy.v1",
                ["policy_id"] = "handshake-fixture", ["revision"] = 1,
                ["product_id"] = "bke-render-dock", ["platform"] = "windows",
                ["architecture"] = "x64", ["install_root"] = productRoot,
                ["entry_point"] = "RENDER DOCK.exe",
                ["signing_key_id"] = "handshake-target", ["algorithm"] = "Ed25519"
            };
            var canonical = JsonSerializer.SerializeToUtf8Bytes(unsigned, JsonOptions);
            var signer = new Ed25519Signer();
            signer.Init(true, key);
            signer.BlockUpdate(canonical, 0, canonical.Length);
            var signed = new SortedDictionary<string, object?>(unsigned, StringComparer.Ordinal) {
                ["signature"] = Convert.ToBase64String(signer.GenerateSignature())
            };
            File.WriteAllText(Path.Combine(policies, "render-dock.json"),
                JsonSerializer.Serialize(signed, JsonOptions), new UTF8Encoding(false));

            var authority = StartupMachineAttestor.ForCertification(data, programFiles);
            var candidate = authority.EnrollmentCandidate();
            var installation = Guid.NewGuid().ToString("D");
            var observed = authority.RequireSignedTarget("bke-render-dock", "1.0.3",
                installation, "S-1-5-21-111-222-333-1001");
            if (observed.ImagePath != exe ||
                observed.ImageSha256 != Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(exe))).ToLowerInvariant())
                throw new InvalidDataException("Privileged installed image was not actually observed.");
            var proof = authority.IssueInstalled("bke-render-dock", "1.0.3",
                installation, "S-1-5-21-111-222-333-1001");
            using var doc = JsonDocument.Parse(candidate);
            var publicPem = doc.RootElement.GetProperty("public_key_pem").GetString()!;
            var der = Convert.FromBase64String(publicPem.Replace(
                "-----BEGIN PUBLIC KEY-----", "").Replace("-----END PUBLIC KEY-----", "").Trim());
            var fingerprint = Convert.ToHexString(SHA256.HashData(der)).ToLowerInvariant();
            var fixture = new {
                schema = "bke.agent-ds-agent-startup-handshake-fixture.v1",
                candidate, proof, fingerprint
            };
            File.WriteAllText(output, JsonSerializer.Serialize(fixture, JsonOptions), new UTF8Encoding(false));
            Console.WriteLine("PASS: actual Windows DPAPI + signed privileged installed target produced disposable DS proof.");
        }
        finally
        {
            if (Directory.Exists(temp)) Directory.Delete(temp, true);
            if (Directory.Exists(productRoot)) Directory.Delete(productRoot, true);
            var parent = Path.GetDirectoryName(productRoot)!;
            if (createdParent && Directory.Exists(parent) && !Directory.EnumerateFileSystemEntries(parent).Any())
                Directory.Delete(parent);
        }
    }

    public static async Task VerifyAsync(string path)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        using var doc = JsonDocument.Parse(File.ReadAllText(path, new UTF8Encoding(false, true)));
        var root = doc.RootElement;
        if (root.GetProperty("schema").GetString() !=
            "bke.ds-agent-startup-handshake-result.v1")
            throw new InvalidDataException("Untrusted test result schema.");
        var kid = root.GetProperty("kid").GetString()!;
        var publicPem = root.GetProperty("public_key_pem").GetString()!;
        var envelope = root.GetProperty("envelope").GetString()!;
        var trusted = new Dictionary<string, AccountProductLeaseTrustedKey>(
            StringComparer.Ordinal) { [kid] = new(publicPem, "ACTIVE") };
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var registry = InstalledStandaloneStartupPolicyRegistry.ForCertification(
            [envelope], trusted, programFiles, DateTimeOffset.UtcNow);
        using var e = JsonDocument.Parse(envelope);
        using var p = JsonDocument.Parse(e.RootElement.GetProperty("payload").GetString()!);
        var payload = p.RootElement;
        var productId = payload.GetProperty("product_id").GetString()!;
        var version = payload.GetProperty("version").GetString()!;
        var mode = payload.GetProperty("activation_mode").GetString()!;
        var actual = await registry.ReadVerifiedAsync(productId, version, CancellationToken.None);
        if (actual is null || actual.ActivationMode != mode || mode != "LICENSE_KEY")
            throw new InvalidDataException("DS SQL-signed LICENSE_KEY mode did not reach Agent.");

        var peer = new StandaloneStartupProcessEvidence(42, 1,
            payload.GetProperty("image_path").GetString()!,
            payload.GetProperty("image_sha256").GetString()!,
            payload.GetProperty("allowed_user_sid").GetString()!,
            DateTimeOffset.UtcNow, true);
        var matching = await registry.ResolveVerifiedAsync(peer, CancellationToken.None);
        if (matching is null ||
            matching.InstallationId != payload.GetProperty("installation_id").GetString())
            throw new InvalidDataException("Installed machine scope mismatched DS signed policy.");
        var wrong = peer with { ImageSha256 = new string('f', 64) };
        if (await registry.ResolveVerifiedAsync(wrong, CancellationToken.None) is not null)
            throw new InvalidDataException("Agent accepted tampered image hash.");
        var wrongSid = peer with { UserSid = "S-1-5-21-123-456-789-1001" };
        if (await registry.ResolveVerifiedAsync(wrongSid, CancellationToken.None) is not null)
            throw new InvalidDataException("Agent accepted wrong user SID.");
        var corrupted = JsonSerializer.Serialize(new {
            schema = e.RootElement.GetProperty("schema").GetString(),
            kid,
            payload = e.RootElement.GetProperty("payload").GetString(),
            signature = Convert.ToBase64String(new byte[64])
        }, JsonOptions);
        try {
            InstalledStandaloneStartupPolicyRegistry.ForCertification(
                [corrupted], trusted, programFiles, DateTimeOffset.UtcNow);
            throw new InvalidDataException("Agent accepted a forged DS signature.");
        }
        catch (InvalidDataException err) when (err.Message != "Agent accepted a forged DS signature.") { }
        Console.WriteLine("PASS: .NET Agent verified real DS SQL-signed LICENSE_KEY policy and rejected forged signature, image, SID.");
    }
}
