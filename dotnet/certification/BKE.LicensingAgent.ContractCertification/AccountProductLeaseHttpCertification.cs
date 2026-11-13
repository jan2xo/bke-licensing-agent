using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;
using BKE.LicensingAgent.Infrastructure;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

/// <summary>
/// Hermetic, real Ed25519 preproduction DS issue/Agent consumer fraction.
/// Executes inside the exact-head Agent CONTRACTS job, with no DS production,
/// Windows DPAPI bypass or installed launcher/product execution.
/// </summary>
internal static class AccountProductLeaseHttpCertification
{
    private const string Kid = "disposable-ds-issuer-1";
    private const string Product = "bke-render-dock";

    public static async Task RunAsync()
    {
        int passed = 0;
        static string B64(byte[] bytes) => Convert.ToBase64String(bytes)
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        static byte[] Bytes(string token) => Convert.FromBase64String(
            token.Replace('-', '+').Replace('_', '/')
                .PadRight((token.Length + 3) / 4 * 4, '='));
        static string Iso(DateTimeOffset value) => value.UtcDateTime.ToString(
            "yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);
        static string Uuid() => Guid.NewGuid().ToString("D");

        using var machine = new LeaseDisposableMachineKey();
        var issuer = new Ed25519PrivateKeyParameters(RandomNumberGenerator.GetBytes(32), 0);
        var other = new Ed25519PrivateKeyParameters(RandomNumberGenerator.GetBytes(32), 0);
        string issuerPem = LeaseDisposableMachineKey.Pem(issuer.GeneratePublicKey().GetEncoded());
        string token = "agent-access-bearer-" + Guid.NewGuid().ToString("N");
        string registration = Uuid();
        var binding = new AgentEd25519SessionBinding(
            "ci-agent-session", "ci-account", "ci-user", "ci-device");
        var authenticated = new ActiveAccountSessionState(
            token, "disposable-refresh-never-used", binding.SessionId,
            DateTimeOffset.UtcNow.AddMinutes(10), DateTimeOffset.UtcNow.AddDays(1),
            new AccountSessionAccount(binding.UserId, "ci@bke.test",
                binding.AccountId, "INDIVIDUAL", "Disposable"));
        AgentMachineKeyRegistrationReceipt receipt = new(
            registration, machine.Identity.KeyThumbprint,
            DateTimeOffset.UtcNow.AddHours(1), "EdDSA");

        var trusted = new Dictionary<string, AccountProductLeaseTrustedKey> {
            [Kid] = new(issuerPem, "ACTIVE")
        };

        string SignJws(string variant, string nowIssuerKid = Kid)
        {
            var start = DateTimeOffset.UtcNow;
            var header = new {
                alg = "EdDSA", kid = nowIssuerKid, typ = "bke.product-lease.v1+jws"
            };
            var payload = new {
                schema = "bke.product-lease.v1",
                issuer = "BKE Digital Solutions",
                audience = "bke-product",
                leaseId = Uuid(),
                accountId = binding.AccountId,
                userId = variant == "wrong-user" ? "foreign-user" : binding.UserId,
                productId = variant == "wrong-product" ? "foreign-product" : Product,
                agentSessionId = binding.SessionId,
                agentKeyThumbprint = machine.Identity.KeyThumbprint,
                keyProtection = "software",
                plan = "subscription",
                allowedActions = new[] { "OPEN" },
                issuedAt = Iso(start),
                refreshAfter = Iso(start.AddSeconds(90)),
                expiresAt = Iso(start.AddSeconds(180))
            };
            string content = B64(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(header))) +
                "." + B64(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload)));
            var signer = new Ed25519Signer();
            signer.Init(true, variant == "bad-signature" ? other : issuer);
            byte[] toSign = Encoding.ASCII.GetBytes(content);
            signer.BlockUpdate(toSign, 0, toSign.Length);
            return content + "." + B64(signer.GenerateSignature());
        }

        async Task Scenario(string variant, bool accepted)
        {
            string challengeId = Uuid();
            var expires = DateTimeOffset.UtcNow.AddSeconds(25);
            string nonce = B64(RandomNumberGenerator.GetBytes(32));
            string message = string.Join("\n",
                "bke.agent-key-proof.v1", variant == "enroll-challenge" ? "ENROLL" : "LEASE",
                challengeId, registration, binding.SessionId,
                binding.AccountId, binding.UserId, binding.DeviceId,
                Product, "OPEN", nonce);
            string encodedMessage = B64(Encoding.UTF8.GetBytes(message));
            int calls = 0;
            var handler = new LeaseFakeHandler(req => {
                calls++;
                if (variant == "redirect" && calls == 1)
                    return new HttpResponseMessage(HttpStatusCode.Redirect) {
                        Headers = { Location = new Uri("https://evil.example.test/") }
                    };
                if (req.Method != HttpMethod.Post ||
                    req.Headers.Authorization?.Scheme != "Bearer" ||
                    req.Headers.Authorization?.Parameter != token ||
                    req.Headers.TryGetValues("x-bke-account-session-version",
                        out var values) != true ||
                    values.SingleOrDefault() != "bke.account-session.v1" ||
                    req.Headers.Contains("Origin"))
                    throw new InvalidOperationException("Agent transport leaked or weakened credentials.");
                using var doc = JsonDocument.Parse(req.Content!
                    .ReadAsStringAsync().GetAwaiter().GetResult());
                var root = doc.RootElement;
                if (calls == 1 && req.RequestUri?.AbsolutePath ==
                    "/api/agent-sessions/leases/challenge")
                {
                    if (root.GetProperty("registration_id").GetString() != registration ||
                        root.GetProperty("product_id").GetString() != Product ||
                        root.GetProperty("action").GetString() != "OPEN")
                        throw new InvalidOperationException("Wrong Agent challenge request scope.");
                    return Reply(new {
                        status = "challenge", registration_id = registration,
                        challenge_id = challengeId, message_base64url = encodedMessage,
                        expires_at = Iso(expires)
                    }, variant == "wrong-protocol");
                }
                if (calls == 2 && req.RequestUri?.AbsolutePath ==
                    "/api/agent-sessions/leases/issue")
                {
                    if (root.GetProperty("challenge_id").GetString() != challengeId ||
                        root.GetProperty("message_base64url").GetString() != encodedMessage ||
                        root.GetProperty("product_id").GetString() != Product ||
                        root.GetProperty("action").GetString() != "OPEN" ||
                        root.GetProperty("platform").GetString() != "windows" ||
                        root.GetProperty("architecture").GetString() != "x64")
                        throw new InvalidOperationException("Wrong Agent issuance request scope.");
                    var verifier = new Ed25519Signer();
                    verifier.Init(false, machine.Public);
                    var bytes = Encoding.UTF8.GetBytes(message);
                    verifier.BlockUpdate(bytes, 0, bytes.Length);
                    var signature = Bytes(root.GetProperty("signature_base64url").GetString()!);
                    if (!verifier.VerifySignature(signature))
                        throw new InvalidOperationException("Agent PoP signature did not verify.");
                    string jws = SignJws(variant,
                        variant == "unknown-kid" ? "unknown-issuer-key" : Kid);
                    var parts = jws.Split('.');
                    using var payload = JsonDocument.Parse(Bytes(parts[1]));
                    string expiry = payload.RootElement.GetProperty("expiresAt").GetString()!;
                    string refresh = payload.RootElement.GetProperty("refreshAfter").GetString()!;
                    if (variant == "extra-key")
                        return Reply(new {
                            status = "issued", lease_jws = jws, kid = Kid,
                            expires_at = expiry, refresh_after = refresh,
                            public_key_pem = issuerPem
                        });
                    return Reply(new {
                        status = "issued", lease_jws = jws, kid = Kid,
                        expires_at = variant == "wrong-expiry"
                            ? Iso(DateTimeOffset.UtcNow.AddHours(2)) : expiry,
                        refresh_after = refresh
                    });
                }
                throw new InvalidOperationException("Unexpected Agent HTTP sequence.");
            });
            var set = new Dictionary<string, AccountProductLeaseTrustedKey>(trusted);
            if (variant == "verify-only")
                set[Kid] = new(issuerPem, "VERIFY_ONLY");
            using var remote = new AgentAccountProductLeaseRemote(
                machine, _ => binding,
                _ => variant == "missing-receipt" ? null :
                    variant == "wrong-receipt"
                        ? receipt with { KeyThumbprint =
                            (receipt.KeyThumbprint.StartsWith('x') ? "y" : "x") +
                            receipt.KeyThumbprint[1..] }
                        : receipt,
                set, "https://disposable-agent.test/", handler);
            try
            {
                var subject = variant == "expired-session"
                    ? authenticated with { AccessTokenExpiresAt =
                        DateTimeOffset.UtcNow.AddSeconds(-5) }
                    : authenticated;
                var result = await remote.RequestVerifiedAsync(subject,
                    Product, "OPEN", "windows", "x64", CancellationToken.None);
                if (!accepted || !result.Ok || result.Kid != Kid ||
                    result.Claims?.AccountId != binding.AccountId ||
                    result.Claims?.ProductId != Product || calls != 2)
                    throw new InvalidOperationException("Unsafe lease accepted: " + variant);
            }
            catch (Exception error) when (
                !accepted && error is InvalidDataException or HttpRequestException)
            {
                if (variant is "missing-receipt" or "wrong-receipt" or "expired-session"
                    && calls != 0)
                    throw new InvalidOperationException("Failed-local-auth leaked HTTP request.");
                if (variant == "enroll-challenge" && calls != 1)
                    throw new InvalidOperationException("ENROLL was mistakenly issued as LEASE.");
                passed++;
                Console.WriteLine("PASS: reject " + variant);
                return;
            }
            if (!accepted)
                throw new InvalidOperationException("FAIL: unexpectedly accepted " + variant);
            passed++;
            Console.WriteLine("PASS: real Ed25519 two-call verified Agent lease");
        }

        await Scenario("valid", true);
        foreach (var variant in new[] {
            "bad-signature", "wrong-user", "wrong-product",
            "unknown-kid", "verify-only", "wrong-expiry", "extra-key",
            "wrong-protocol", "redirect", "enroll-challenge",
            "missing-receipt", "wrong-receipt", "expired-session"
        }) await Scenario(variant, false);
        Console.WriteLine($"Account-product lease HTTP certification: {passed}/14 PASS");
    }

    private static HttpResponseMessage Reply(object body, bool wrongProtocol = false)
    {
        var reply = new HttpResponseMessage(HttpStatusCode.Created) {
            Content = new StringContent(JsonSerializer.Serialize(body),
                Encoding.UTF8, "application/json")
        };
        reply.Headers.TryAddWithoutValidation("x-bke-account-session-version",
            wrongProtocol ? "bke.account-session.v999" : "bke.account-session.v1");
        reply.Headers.CacheControl = new CacheControlHeaderValue { NoStore = true };
        return reply;
    }

    private sealed class LeaseFakeHandler(
        Func<HttpRequestMessage, HttpResponseMessage> answer) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(answer(request));
    }

    private sealed class LeaseDisposableMachineKey : IAgentMachineKeySigner, IDisposable
    {
        private readonly Ed25519PrivateKeyParameters _private =
            new(RandomNumberGenerator.GetBytes(32), 0);
        public Ed25519PublicKeyParameters Public => _private.GeneratePublicKey();
        public AgentEd25519PublicIdentity Identity { get; }
        public LeaseDisposableMachineKey()
        {
            byte[] raw = Public.GetEncoded();
            byte[] spki = Convert.FromHexString("302A300506032B6570032100")
                .Concat(raw).ToArray();
            string thumbprint = Convert.ToBase64String(SHA256.HashData(spki))
                .TrimEnd('=').Replace('+', '-').Replace('/', '_');
            Identity = new AgentEd25519PublicIdentity(Pem(raw), thumbprint, "software");
        }
        public static string Pem(byte[] raw)
        {
            byte[] spki = Convert.FromHexString("302A300506032B6570032100")
                .Concat(raw).ToArray();
            return "-----BEGIN PUBLIC KEY-----\n" +
                Convert.ToBase64String(spki) + "\n-----END PUBLIC KEY-----\n";
        }
        public AgentEd25519PublicIdentity GetOrCreateIdentity(
            AgentEd25519SessionBinding binding, bool createIfMissing = true) => Identity;
        public string SignChallenge(AgentEd25519SessionBinding binding,
            string registrationId, string challengeId, string messageBase64url,
            DateTimeOffset expiresAt, string? productId = null, string? action = null)
        {
            if (expiresAt <= DateTimeOffset.UtcNow ||
                expiresAt > DateTimeOffset.UtcNow.AddSeconds(35))
                throw new InvalidDataException("Invalid LEASE expiry.");
            byte[] message = Convert.FromBase64String(
                messageBase64url.Replace('-', '+').Replace('_', '/').PadRight(
                    ((messageBase64url.Length + 3) / 4) * 4, '='));
            string[] fields = new UTF8Encoding(false, true).GetString(message).Split('\n');
            if (fields.Length != 11 || fields[0] != "bke.agent-key-proof.v1" ||
                fields[1] != "LEASE" || fields[2] != challengeId ||
                fields[3] != registrationId || fields[4] != binding.SessionId ||
                fields[5] != binding.AccountId || fields[6] != binding.UserId ||
                fields[7] != binding.DeviceId || fields[8] != productId ||
                fields[9] != action || fields[10].Length != 43)
                throw new InvalidDataException("Untrusted LEASE challenge context.");
            var signer = new Ed25519Signer();
            signer.Init(true, _private);
            signer.BlockUpdate(message, 0, message.Length);
            return Convert.ToBase64String(signer.GenerateSignature())
                .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }
        public void Dispose() { }
    }
}
