using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using BKE.LicensingAgent.Infrastructure;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

internal static class StartupPolicyAcquisitionCertification
{
    private const string Kid = "disposable-ds-startup-policy-issuer";
    private const string SignedDomain = "BKE-STANDALONE-STARTUP-POLICY-V1\n";

    public static async Task RunAsync()
    {
        var now = DateTimeOffset.UtcNow;
        var root = Path.GetTempPath();
        var productPath = Path.GetFullPath(Path.Combine(root,
            "BKE Digital Solutions", "Render Dock", "RENDER DOCK.exe"));
        var expected = new InstalledStartupPolicyScope(
            "bke-render-dock", "1.0.3", Guid.NewGuid().ToString("D"),
            productPath, new string('a', 64), "S-1-5-21-111-222-333-1001");
        var key = new Ed25519PrivateKeyParameters(RandomNumberGenerator.GetBytes(32), 0);
        var other = new Ed25519PrivateKeyParameters(RandomNumberGenerator.GetBytes(32), 0);
        var spki = Convert.FromHexString("302A300506032B6570032100");
        var publicPem = "-----BEGIN PUBLIC KEY-----\n" +
            Convert.ToBase64String(spki.Concat(key.GeneratePublicKey().GetEncoded()).ToArray()) +
            "\n-----END PUBLIC KEY-----\n";
        var installedKeys = new Dictionary<string, AccountProductLeaseTrustedKey>(
            StringComparer.Ordinal) { [Kid] = new(publicPem, "ACTIVE") };
        var signers = new Dictionary<string, AccountProductLeaseTrustedKey>(
            StringComparer.Ordinal) { [Kid] = new(publicPem, "VERIFY_ONLY") };

        string Sign(string variant)
        {
            var nowUtc = now.ToUniversalTime();
            string data = JsonSerializer.Serialize(new {
                schema = "bke.standalone-startup-policy.v1",
                issuer_source_sha = AccountProductLeaseInstalledTrust.ExactIssuerSourceSha,
                product_id = variant == "wrong-product" ? "other-app" : expected.ProductId,
                version = variant == "wrong-version" ? "99.0.0" : expected.Version,
                installation_id = variant == "wrong-install" ? Guid.NewGuid().ToString("D")
                    : expected.InstallationId,
                image_path = expected.ImagePath,
                image_sha256 = variant == "wrong-image" ? new string('b',64)
                    : expected.ImageSha256,
                allowed_user_sid = variant == "wrong-sid"
                    ? "S-1-5-21-999-888-777-1001" : expected.AllowedUserSid,
                activation_mode = "LICENSE_KEY",
                not_before = nowUtc.AddSeconds(-2).ToString("O", CultureInfo.InvariantCulture),
                expires_at = nowUtc.AddMinutes(25).ToString("O", CultureInfo.InvariantCulture),
            });
            var signedBytes = Encoding.UTF8.GetBytes(SignedDomain + data);
            try {
                var signer = new Ed25519Signer();
                signer.Init(true, variant == "forged" ? other : key);
                signer.BlockUpdate(signedBytes, 0, signedBytes.Length);
                return JsonSerializer.Serialize(new {
                    schema = "bke.standalone-startup-envelope.v1",
                    kid = Kid,
                    payload = data,
                    signature = Convert.ToBase64String(signer.GenerateSignature()),
                });
            }
            finally { CryptographicOperations.ZeroMemory(signedBytes); }
        }

        string JsonReply(string envelope, string variant)
        {
            using var doc = JsonDocument.Parse(envelope);
            using var inner = JsonDocument.Parse(
                doc.RootElement.GetProperty("payload").GetString()!);
            return JsonSerializer.Serialize(new {
                status = "issued", signed_policy_envelope = envelope,
                kid = variant == "wrong-response-kid" ? "swapped" : Kid,
                activation_mode = variant == "wrong-response-mode"
                    ? "ACCOUNT" : "LICENSE_KEY",
                expires_at = inner.RootElement.GetProperty("expires_at").GetString(),
            });
        }

        int passed = 0;
        void Pass(string label) {
            passed++;
            Console.WriteLine("PASS startup policy HTTP: " + label);
        }
        var origin = new Uri("https://agent-preprod.example.invalid/");
        PreproductionStartupPolicyAcquisition.RequirePreproductionOrigin(origin);
        Pass("explicit nonproduction HTTPS origin");

        foreach (var value in new [] {
            "https://jl-bke.com/",
            "https://staging.jl-bke.com/",
            "http://remote-preprod.example.invalid/",
            "https://user:password@agent-preprod.example.invalid/",
            "https://agent-preprod.example.invalid/unsafe",
            "https://agent-preprod.example.invalid/?token=secret",
        }) {
            bool denied = false;
            try {
                PreproductionStartupPolicyAcquisition.RequirePreproductionOrigin(
                    new Uri(value));
            }
            catch (InvalidDataException) { denied = true; }
            if (!denied) throw new InvalidOperationException(
                "Startup policy origin denied case failed.");
            Pass("forbidden origin");
        }

        async Task Try(string variant, bool shouldPass)
        {
            var envelope = Sign(variant);
            var body = JsonReply(envelope, variant);
            var requestCount = 0;
            using var client = new HttpClient(new ReplyHandler(req => {
                requestCount++;
                if (req.Method != HttpMethod.Post ||
                    req.RequestUri != new Uri(origin,
                        PreproductionStartupPolicyAcquisition.RelativeRoute) ||
                    !req.Headers.TryGetValues(
                        "x-bke-startup-policy-protocol", out var values) ||
                    !values.SequenceEqual([PreproductionStartupPolicyAcquisition.Protocol]) ||
                    req.Headers.Authorization is not null)
                    throw new InvalidOperationException(
                        "Agent issued wrong startup policy transport.");
                var rawRequest = req.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
                using var json = JsonDocument.Parse(rawRequest);
                if (json.RootElement.EnumerateObject().Count() != 1 ||
                    json.RootElement.GetProperty("signed_install_attestation")
                        .GetString() != "signed-native-attestation-mock-data")
                    throw new InvalidOperationException(
                        "Agent request sent unsigned client-selected startup authority.");

                var status = variant == "http-forbidden" ? HttpStatusCode.Forbidden :
                    variant == "redirect" ? HttpStatusCode.Redirect :
                    HttpStatusCode.Created;
                var response = new HttpResponseMessage(status) {
                    Content = new StringContent(body,
                        Encoding.UTF8, "application/json"),
                };
                response.Headers.TryAddWithoutValidation(
                    "x-bke-startup-policy-protocol",
                    variant == "wrong-protocol" ? "bke.account-session.v1" :
                    PreproductionStartupPolicyAcquisition.Protocol);
                if (variant == "redirect")
                    response.Headers.Location = new Uri("https://evil.example.invalid/");
                return response;
            }));
            var accepted = false;
            try {
                string verified = await PreproductionStartupPolicyAcquisition.AcquireVerifiedAsync(
                    client, origin, "signed-native-attestation-mock-data",
                    expected, variant == "verify-only" ? signers : installedKeys,
                    root, now);
                accepted = verified == envelope;
            }
            catch (InvalidDataException) { }
            if (accepted != shouldPass || requestCount != 1)
                throw new InvalidOperationException(
                    "Startup policy expected HTTP/signature/scope decision failed: " + variant);
            Pass(variant);
        }

        await Try("good", true);
        await Try("verify-only", true);
        foreach (var variant in new [] {
            "forged", "wrong-product", "wrong-version", "wrong-install",
            "wrong-image", "wrong-sid", "wrong-response-kid",
            "wrong-response-mode", "wrong-protocol", "http-forbidden", "redirect",
        }) await Try(variant, false);

        // The Agent trusts only its installed keyset; a correct signature
        // from a different private signer must never become a trust anchor.
        var noKeys = new Dictionary<string, AccountProductLeaseTrustedKey>();
        bool refused = false;
        try {
            PreproductionStartupPolicyAcquisition.ValidateSignedResponse(
                JsonReply(Sign("good"), "good"), expected, noKeys, root, now);
        }
        catch (InvalidDataException) { refused = true; }
        if (!refused) throw new InvalidOperationException("Untrusted issuer accepted.");
        Pass("unknown issuer denied");

        var exactSource = File.ReadAllText(
            "dotnet/src/BKE.LicensingAgent.Infrastructure/PreproductionStartupPolicyAcquisition.cs");
        if (!exactSource.Contains(
                "b282c8d1664efd6a59df9672a549b313343fa508",
                StringComparison.Ordinal) ||
            !exactSource.Contains("InstalledStandaloneStartupPolicyRegistry.VerifyEnvelope",
                StringComparison.Ordinal))
            throw new InvalidOperationException(
                "Agent does not pin certified DS transport or canonical signed verifier.");
        Pass("pinned DS source and shared .NET signed verifier");

        Console.WriteLine($"PREPRODUCTION_AGENT_DS_STARTUP_POLICY_TRANSPORT_PASS {passed} checks; " +
            "source-only disposable synthetic HTTP/Ed25519; NOT installed Windows positive grant");
    }

    private sealed class ReplyHandler(Func<HttpRequestMessage, HttpResponseMessage> reply)
        : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(reply(request));
    }
}
