using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Infrastructure;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

/// <summary>
/// Uses an actual disposable Ed25519 signer, not a fake catalog boolean, to
/// certify the installed policy schema and real durable SQLite audit.
/// Hosted Windows pipe behavior is separately certified on windows-x64.
/// </summary>
internal static class InstalledStandaloneStartupAuthorityCertification
{
    public static async Task RunAsync()
    {
        var passed = 0;
        void Check(bool ok, string description)
        {
            if (!ok) throw new InvalidOperationException(
                "FAIL: installed standalone startup " + description);
            passed++;
            Console.WriteLine("PASS: installed standalone startup " + description);
        }
        var root = Path.Combine(Path.GetTempPath(),
            "bke-startup-policy-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var image = Path.GetFullPath(Path.Combine(root,
                "BKE Digital Solutions", "Render Dock", "RENDER DOCK.exe"));
            var digest = new string('a', 64);
            var sid = "S-1-5-21-2001";
            var now = DateTimeOffset.UtcNow;
            var privateKey = new Ed25519PrivateKeyParameters(
                RandomNumberGenerator.GetBytes(32), 0);
            var publicDer = Convert.FromHexString("302A300506032B6570032100")
                .Concat(privateKey.GeneratePublicKey().GetEncoded()).ToArray();
            var pem = "-----BEGIN PUBLIC KEY-----\n" +
                Convert.ToBase64String(publicDer) +
                "\n-----END PUBLIC KEY-----\n";
            var keys = new Dictionary<string, AccountProductLeaseTrustedKey>(
                StringComparer.Ordinal) {
                    ["fixture-issuer"] = new(pem, "ACTIVE")
                };

            string Payload(
                string mode = "LICENSE_KEY",
                string? product = null,
                string? version = null,
                string? signedImage = null,
                string? signedSha = null,
                string? signedSid = null,
                string? source = null,
                DateTimeOffset? notBefore = null,
                DateTimeOffset? expiresAt = null) => JsonSerializer.Serialize(new {
                    schema = InstalledStandaloneStartupPolicyRegistry.PayloadSchema,
                    issuer_source_sha = source ??
                        AccountProductLeaseInstalledTrust.ExactIssuerSourceSha,
                    product_id = product ?? "bke-render-dock",
                    version = version ?? "1.0.3",
                    installation_id = "00000000-0000-0000-0000-000000000001",
                    image_path = signedImage ?? image,
                    image_sha256 = signedSha ?? digest,
                    allowed_user_sid = signedSid ?? sid,
                    activation_mode = mode,
                    not_before = (notBefore ?? now.AddHours(-1)).ToString("O"),
                    expires_at = (expiresAt ?? now.AddHours(2)).ToString("O")
                });

            string Sign(string payload)
            {
                var message = Encoding.UTF8.GetBytes(
                    InstalledStandaloneStartupPolicyRegistry.Domain + payload);
                var signer = new Ed25519Signer();
                signer.Init(true, privateKey);
                signer.BlockUpdate(message, 0, message.Length);
                return JsonSerializer.Serialize(new {
                    schema = InstalledStandaloneStartupPolicyRegistry.EnvelopeSchema,
                    kid = "fixture-issuer",
                    payload,
                    signature = Convert.ToBase64String(signer.GenerateSignature())
                });
            }

            var good = Sign(Payload());
            var verified = InstalledStandaloneStartupPolicyRegistry.VerifyEnvelope(
                good, keys, root, now);
            Check(verified.ProductId == "bke-render-dock" &&
                verified.ActivationMode == "LICENSE_KEY" &&
                verified.ImageSha256 == digest &&
                verified.AllowedUserSid == sid,
                "DS-signed product mode/image/SID/installation verified");

            var registry = InstalledStandaloneStartupPolicyRegistry.ForCertification(
                [good], keys, root, now);
            var peer = new StandaloneStartupProcessEvidence(
                4501, DateTime.UtcNow.AddSeconds(-3).Ticks,
                image, digest, sid, DateTimeOffset.UtcNow,
                WindowsKernelObserved: true);
            var installed = await registry.ResolveVerifiedAsync(
                peer, CancellationToken.None);
            Check(installed?.ProductId == "bke-render-dock" &&
                installed.InstallationId == "00000000-0000-0000-0000-000000000001",
                "real Ed25519 proof resolves exact executable identity");

            var mode = await registry.ReadVerifiedAsync(
                "bke-render-dock", "1.0.3", CancellationToken.None);
            Check(mode?.ActivationMode == "LICENSE_KEY",
                "mode comes from signed DS policy, not local catalog or manifest");

            Check(await registry.ResolveVerifiedAsync(
                peer with { ImageSha256 = new string('b', 64) },
                CancellationToken.None) is null,
                "different executable hash cannot borrow signature");
            Check(await registry.ResolveVerifiedAsync(
                peer with { UserSid = "S-1-5-21-9000" },
                CancellationToken.None) is null,
                "different Windows user cannot borrow signature");
            Check(await registry.ReadVerifiedAsync(
                "foreign-product", "1.0.3",
                CancellationToken.None) is null,
                "foreign product cannot borrow activation mode");

            void Reject(string envelope, string description)
            {
                bool denied = false;
                try { _ = InstalledStandaloneStartupPolicyRegistry.VerifyEnvelope(
                    envelope, keys, root, now); }
                catch (Exception e) when (e is InvalidDataException or
                    JsonException or FormatException or CryptographicException)
                { denied = true; }
                Check(denied, description);
            }

            Reject(good.Replace("LICENSE_KEY", "ACCOUNT",
                StringComparison.Ordinal),
                "tampered activation mode without valid signature rejected");
            Reject(good.Replace("fixture-issuer", "unsigned-issuer",
                StringComparison.Ordinal), "unknown signer rejected");
            Reject(Sign(Payload(mode: "AUTO")),
                "signed unknown SQL activation mode rejected");
            Reject(Sign(Payload(source: new string('0', 40))),
                "signed policy with unapproved DS source rejected");
            Reject(Sign(Payload(signedImage: Path.Combine(root,
                "outside", "RENDER DOCK.exe"))),
                "signed executable outside BKE Program Files root rejected");
            Reject(Sign(Payload(signedSha: "INVALID")),
                "signed malformed executable fingerprint rejected");
            Reject(Sign(Payload(signedSid: "everyone")),
                "signed unbound user identity rejected");
            Reject(Sign(Payload(expiresAt: now.AddMinutes(-1))),
                "expired signed installed mode rejected");
            Reject(Sign(Payload(notBefore: now.AddMinutes(10))),
                "future signed installed mode rejected");
            Reject(Sign(Payload(expiresAt: now.AddDays(370))),
                "indefinitely long signed mode lifetime rejected");

            // Duplicate JSON properties are rejected even when signed.
            var duplicate = Payload().Replace(
                "\"activation_mode\":\"LICENSE_KEY\"",
                "\"activation_mode\":\"ACCOUNT\",\"activation_mode\":\"LICENSE_KEY\"",
                StringComparison.Ordinal);
            Reject(Sign(duplicate), "signed duplicate mode field rejected");
            Reject(good.Replace("\"kid\":", "\"kid\":\"fixture-issuer\",\"kid\":",
                StringComparison.Ordinal),
                "ambiguous envelope signer rejected");

            bool duplicateRejected = false;
            try {
                _ = InstalledStandaloneStartupPolicyRegistry.ForCertification(
                    [good, good], keys, root, now);
            }
            catch (InvalidDataException) { duplicateRejected = true; }
            Check(duplicateRejected, "duplicate installed policies cannot grant authority");

            // A policy which was valid when loaded must not remain valid after
            // expiration. Construct with an earlier verification clock.
            var past = now.AddHours(-3);
            var expiredAfterLoad =
                InstalledStandaloneStartupPolicyRegistry.ForCertification(
                    [Sign(Payload(notBefore: past.AddHours(-1),
                        expiresAt: now.AddHours(-1)))], keys, root, past);
            Check(await expiredAfterLoad.ReadVerifiedAsync(
                "bke-render-dock", "1.0.3",
                CancellationToken.None) is null,
                "expired loaded policy is revalidated on every startup");

            var auditDb = Path.Combine(root, "standalone-grants.db");
            var audit = InstalledStandaloneStartupGrantAudit.ForCertification(auditDb);
            Check(await audit.CommitGrantAsync(installed!, peer, "LICENSE_KEY",
                CancellationToken.None),
                "first signed commercial startup audit durably committed");
            Check(!await audit.CommitGrantAsync(installed!, peer, "LICENSE_KEY",
                CancellationToken.None),
                "same process replay rejected inside one service");
            var restarted = InstalledStandaloneStartupGrantAudit.ForCertification(auditDb);
            Check(!await restarted.CommitGrantAsync(installed!, peer, "ACCOUNT",
                CancellationToken.None),
                "replay rejected after Agent service restart");
            Check(await restarted.CommitGrantAsync(installed!, peer with {
                ProcessId = 4502 }, "LICENSE_KEY", CancellationToken.None),
                "new process creates a distinct durable admission row");
            Check(!await restarted.CommitGrantAsync(installed!, peer with {
                ProcessId = 4503 }, "FAKE", CancellationToken.None),
                "unrecognized credential cannot enter audit ledger");

            var impossible = InstalledStandaloneStartupGrantAudit.ForCertification(
                Path.Combine(root, "nonexistent-directory", "grants.db"));
            Check(!await impossible.CommitGrantAsync(installed!, peer with {
                ProcessId = 4510 }, "LICENSE_KEY", CancellationToken.None),
                "unwritable/missing audit directory fails closed");

            var host = File.ReadAllText(Path.Combine(
                "dotnet", "src", "BKE.LicensingAgent.Host", "Program.cs"));
            var pipe = File.ReadAllText(Path.Combine(
                "dotnet", "src", "BKE.LicensingAgent.Host",
                "StandaloneStartupPipeHostedService.cs"));
            var installer = File.ReadAllText(Path.Combine(
                "packaging", "windows", "bke-licensing-agent.iss"));
            Check(host.Contains("BKE_STANDALONE_STARTUP_GATE_ENABLED",
                    StringComparison.Ordinal) &&
                host.Contains("InstalledStandaloneStartupPolicyRegistry.LoadInstalled",
                    StringComparison.Ordinal) &&
                host.Contains("InstalledStandaloneStartupGrantAudit.CreateInstalled",
                    StringComparison.Ordinal) &&
                host.Contains("AddHostedService<StandaloneStartupPipeHostedService>",
                    StringComparison.Ordinal) &&
                host.Contains("AgentRuntimeEnvironmentLoader.ProductionEnvironment",
                    StringComparison.Ordinal),
                "Host production lock and opt-in signed trust composition");
            Check(pipe.Contains("WellKnownSidType.NetworkSid",
                    StringComparison.Ordinal) &&
                pipe.Contains("NamedPipeServerStreamAcl.Create",
                    StringComparison.Ordinal) &&
                pipe.Contains("WindowsNamedPipeStandaloneStartupPeerAttestor",
                    StringComparison.Ordinal) &&
                pipe.Contains("root.GetProperty(\"operation\")",
                    StringComparison.Ordinal),
                "Host IPC rejects default ACL and untrusted request authority");
            Check(installer.Contains("standalone-startup-policies",
                    StringComparison.Ordinal) &&
                installer.Contains("skipifsourcedoesntexist",
                    StringComparison.Ordinal),
                "privileged installer owns optional signed policy delivery");

            Console.WriteLine($"Installed standalone startup signature/audit: {passed} PASS");
            if (passed != 27)
                throw new InvalidOperationException(
                    $"Incomplete signed startup trust test matrix: {passed}/27");
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }
}
