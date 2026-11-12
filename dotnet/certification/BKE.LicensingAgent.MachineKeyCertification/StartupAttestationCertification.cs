using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using BKE.LicensingAgent.Provisioner;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

/// <summary>
/// Real Windows DPAPI LocalMachine and signed privileged target policy proof.
/// No DS calls, customer keys, or actual Program Files release publication.
/// </summary>
internal static class StartupAttestationCertification
{
    public static void Run()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Attestation native test requires Windows.");
        var count = 0;
        void Check(bool condition, string name)
        {
            if (!condition) throw new InvalidOperationException("FAIL: privileged startup attestation " + name);
            Console.WriteLine("PASS: privileged startup attestation " + name);
            count++;
        }
        void Deny(Action action, string name)
        {
            bool denied = false;
            try { action(); }
            catch (Exception e) when (
                e is InvalidDataException or IOException or FormatException or
                    Win32Exception or CryptographicException or UnauthorizedAccessException)
            { denied = true; }
            Check(denied, name);
        }
        var root = Path.Combine(Path.GetTempPath(),
            "bke-startup-install-attest-" + Guid.NewGuid().ToString("N"));
        var programFiles = Path.Combine(root, "Program Files");
        var productRoot = Path.Combine(programFiles, "BKE Digital Solutions", "Render Dock");
        var data = Path.Combine(root, "ProgramData", "BKE Digital Solutions", "Licensing Agent");
        var privileged = Path.Combine(data, "privileged");
        var keys = Path.Combine(privileged, "target-keys");
        var policies = Path.Combine(privileged, "target-policies");
        var exe = Path.Combine(productRoot, "RENDER DOCK.exe");
        var policy = Path.Combine(policies, "render-dock.json");
        var id = Guid.NewGuid().ToString("D");
        var sid = "S-1-5-21-111-222-333-1001";
        var signerKey = new Ed25519PrivateKeyParameters(RandomNumberGenerator.GetBytes(32), 0);

        string CanonicalPublic(Ed25519PublicKeyParameters pub)
        {
            var der = Convert.FromHexString("302A300506032B6570032100")
                .Concat(pub.GetEncoded()).ToArray();
            return "-----BEGIN PUBLIC KEY-----\n" +
                   Convert.ToBase64String(der) + "\n-----END PUBLIC KEY-----\n";
        }

        string SignedPolicy(string productId = "bke-render-dock")
        {
            var unsigned = new SortedDictionary<string, object?>(StringComparer.Ordinal) {
                ["schema"] = "bke.install-target-policy.v1",
                ["policy_id"] = "installer-fixture",
                ["revision"] = 1,
                ["product_id"] = productId,
                ["platform"] = "windows", ["architecture"] = "x64",
                ["install_root"] = productRoot, ["entry_point"] = "RENDER DOCK.exe",
                ["signing_key_id"] = "fixture-install-target",
                ["algorithm"] = "Ed25519"
            };
            var canonical = JsonSerializer.SerializeToUtf8Bytes(unsigned,
                new JsonSerializerOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
            var signer = new Ed25519Signer();
            signer.Init(true, signerKey);
            signer.BlockUpdate(canonical, 0, canonical.Length);
            var signed = new SortedDictionary<string, object?>(unsigned, StringComparer.Ordinal) {
                ["signature"] = Convert.ToBase64String(signer.GenerateSignature())
            };
            return JsonSerializer.Serialize(signed,
                new JsonSerializerOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
        }

        try
        {
            Directory.CreateDirectory(productRoot);
            Directory.CreateDirectory(keys);
            Directory.CreateDirectory(policies);
            File.WriteAllText(exe, "DISPOSABLE CERTIFICATION EXE FIXTURE - not a release.");
            File.WriteAllText(Path.Combine(keys, "fixture-install-target.pem"),
                CanonicalPublic(signerKey.GeneratePublicKey()), new UTF8Encoding(false));
            var signedPolicy = SignedPolicy();
            File.WriteAllText(policy, signedPolicy, new UTF8Encoding(false));

            var authority = StartupMachineAttestor.ForCertification(data, programFiles);
            var candidate = authority.EnrollmentCandidate();
            using var enrollment = JsonDocument.Parse(candidate);
            var enrolled = enrollment.RootElement;
            Check(enrolled.GetProperty("schema").GetString() ==
                "bke.agent-startup-attestation-enrollment-candidate.v1" &&
                enrolled.GetProperty("status").GetString() == "STAGED",
                "public-only staging candidate cannot self-enroll DS ACTIVE trust");
            Check(enrolled.EnumerateObject().Count() == 5 &&
                !candidate.Contains("PRIVATE KEY", StringComparison.Ordinal),
                "enrollment output excludes private signer material");
            var kid = enrolled.GetProperty("kid").GetString()!;
            var device = enrolled.GetProperty("device_id").GetString()!;
            var publicKeyPem = enrolled.GetProperty("public_key_pem").GetString()!;
            var second = StartupMachineAttestor.ForCertification(data, programFiles);
            Check(second.EnrollmentCandidate() == candidate,
                "machine DPAPI identity survives a new process/provider instance");

            var privatePath = Path.Combine(privileged, "startup-attestation", "identity.dpapi");
            var encrypted = File.ReadAllBytes(privatePath);
            Check(encrypted.Length > 32 &&
                Encoding.UTF8.GetString(encrypted).IndexOf("PRIVATE KEY", StringComparison.Ordinal) < 0 &&
                !Encoding.UTF8.GetString(encrypted).Contains(kid, StringComparison.Ordinal),
                "private signing seed and identity are encrypted at rest under machine DPAPI");

            var installed = authority.RequireSignedTarget(
                "bke-render-dock", "1.0.3", id, sid);
            Check(installed.ImagePath == exe &&
                installed.ImageSha256 == Convert.ToHexString(
                    SHA256.HashData(File.ReadAllBytes(exe))).ToLowerInvariant(),
                "signed privileged target resolved to kernel filesystem binary fingerprint");
            var proof = second.IssueInstalled("bke-render-dock", "1.0.3", id, sid);
            using var outer = JsonDocument.Parse(proof);
            var obj = outer.RootElement;
            Check(obj.EnumerateObject().Select(x => x.Name).SequenceEqual(
                ["schema", "kid", "payload", "signature"]) &&
                obj.GetProperty("schema").GetString() ==
                    "bke.agent-startup-install-attestation-envelope.v1" &&
                obj.GetProperty("kid").GetString() == kid,
                "DS canonical outer envelope order and registered key ID");
            var payloadText = obj.GetProperty("payload").GetString()!;
            using var inner = JsonDocument.Parse(payloadText);
            var body = inner.RootElement;
            Check(body.EnumerateObject().Select(x => x.Name).SequenceEqual([
                "schema", "product_id", "version", "installation_id",
                "image_path", "image_sha256", "allowed_user_sid", "device_id",
                "attestation_id", "issued_at", "expires_at"
            ]) && body.GetProperty("device_id").GetString() == device,
                "DS exact payload field order and protected stable device ID");
            Check(body.GetProperty("installation_id").GetString() == id &&
                body.GetProperty("image_sha256").GetString() == installed.ImageSha256 &&
                body.GetProperty("allowed_user_sid").GetString() == sid,
                "attestation binds exact installation, image hash and user SID");
            Check(DateTime.Parse(body.GetProperty("issued_at").GetString()!) <= DateTime.UtcNow &&
                (DateTime.Parse(body.GetProperty("expires_at").GetString()!) -
                 DateTime.Parse(body.GetProperty("issued_at").GetString()!)).TotalSeconds == 60,
                "fresh, exactly 60-second DS-compatible UTC attestation");
            var publicDer = Convert.FromBase64String(publicKeyPem.Replace(
                "-----BEGIN PUBLIC KEY-----", "").Replace(
                "-----END PUBLIC KEY-----", "").Trim());
            var verifier = new Ed25519Signer();
            verifier.Init(false, new Ed25519PublicKeyParameters(publicDer, 12));
            var signedBytes = Encoding.UTF8.GetBytes(
                "BKE-AGENT-STARTUP-INSTALL-ATTESTATION-V1\n" + payloadText);
            verifier.BlockUpdate(signedBytes, 0, signedBytes.Length);
            Check(verifier.VerifySignature(Convert.FromBase64String(
                obj.GetProperty("signature").GetString()!)),
                "real Ed25519 signature verifies from exported public-only DS registry key");
            var otherProof = authority.IssueInstalled("bke-render-dock", "1.0.3", id, sid);
            using var other = JsonDocument.Parse(otherProof);
            Check(other.RootElement.GetProperty("payload").GetString() != payloadText,
                "new attestation produces new UUID for DS durable replay ledger");

            Deny(() => authority.RequireSignedTarget(
                "foreign-product", "1.0.3", id, sid), "unknown product cannot borrow installed signing authority");
            Deny(() => authority.RequireSignedTarget(
                "bke-render-dock", "bogus", id, sid), "invalid release version denied");
            Deny(() => authority.RequireSignedTarget(
                "bke-render-dock", "1.0.3", id, "S-1-1-0"), "untrusted Everyone SID denied");

            File.WriteAllText(policy, signedPolicy.Replace("bke-render-dock", "foreign-product"),
                new UTF8Encoding(false));
            Deny(() => authority.RequireSignedTarget(
                "bke-render-dock", "1.0.3", id, sid),
                "tampered signed target policy denied before executable proof");
            File.WriteAllText(policy, signedPolicy, new UTF8Encoding(false));
            File.WriteAllText(exe, "CHANGED INSTALLED BYTES");
            var changed = authority.RequireSignedTarget("bke-render-dock", "1.0.3", id, sid);
            Check(changed.ImageSha256 != installed.ImageSha256,
                "post-install binary modification changes signed fingerprint");

            encrypted[encrypted.Length / 2] ^= 0x2d;
            File.WriteAllBytes(privatePath, encrypted);
            Deny(() => authority.EnrollmentCandidate(),
                "corrupted protected machine key cannot be silently replaced");
            Check(File.ReadAllBytes(privatePath).SequenceEqual(encrypted),
                "corrupted protected identity remains untouched for investigation");

            if (count != 18)
                throw new InvalidOperationException($"Incomplete Windows startup attestation: {count}/18");
            Console.WriteLine("BKE privileged startup machine attestation certification: PASS 18/18");
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }
}
