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

internal static class AgentMachineKeyHttpCertification
{
    public static async Task RunAsync()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Windows DPAPI required.");
        var root = Path.Combine(Path.GetTempPath(), "bke-agent-key-http-" + Guid.NewGuid().ToString("N"));
        var store = new WindowsDpapiEd25519MachineKeyStore(root);
        string sessionId = "agent-session-integration";
        string accountId = "account-integration";
        string userId = "user-integration";
        string deviceId = MachineIdentityProvider.Calculate().DeviceId;
        string bearer = "disposable-agent-session-token-xxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        var session = new ActiveAccountSessionState(
            bearer, "disposable-refresh", sessionId,
            DateTimeOffset.UtcNow.AddMinutes(10),
            DateTimeOffset.UtcNow.AddDays(1),
            new AccountSessionAccount(userId, "test@bke.test", accountId, "INDIVIDUAL", "Disposable"));
        int passed = 0;
        void Pass(bool value, string name)
        {
            if (!value) throw new InvalidOperationException("FAIL: " + name);
            Console.WriteLine("PASS: " + name);
            passed++;
        }
        async Task RejectAsync(Func<Task> execute, string name)
        {
            bool rejected = false;
            try { await execute(); }
            catch (InvalidDataException) { rejected = true; }
            catch (HttpRequestException) { rejected = true; }
            Pass(rejected, name);
        }

        try
        {
            using (var service = new AgentMachineKeyEnrollmentRemote(
                store, "https://ds.bke.test", new ProofHandler(bearer,
                    sessionId, accountId, userId, deviceId)))
            {
                var receipt = await service.EnrollAsync(session, CancellationToken.None);
                Pass(receipt.RegistrationId != "", "Authenticated DS enrollment verified");
                Pass(receipt.KeyThumbprint == store.GetOrCreateIdentity(new AgentEd25519SessionBinding(
                    sessionId, accountId, userId, deviceId)).KeyThumbprint,
                    "Verified registration ties to actual protected local key");
                await service.RevokeAsync(session, receipt, CancellationToken.None);
                Pass(true, "Authenticated DS revocation acknowledged with matching key");
                await RejectAsync(() => service.RevokeAsync(session,
                    receipt with { KeyThumbprint = "wrong" }, CancellationToken.None),
                    "Wrong key thumbprint cannot revoke");
            }
            using (var service = new AgentMachineKeyEnrollmentRemote(
                store, "https://ds.bke.test", new ProofHandler(bearer,
                    sessionId, accountId, userId, deviceId) { WrongAccount = true }))
            {
                await RejectAsync(() => service.EnrollAsync(session, CancellationToken.None),
                    "Server challenge bound to foreign account is rejected before VERIFY");
            }
            using (var service = new AgentMachineKeyEnrollmentRemote(
                store, "https://ds.bke.test", new ProofHandler(bearer,
                    sessionId, accountId, userId, deviceId) { Redirect = true }))
            {
                await RejectAsync(() => service.EnrollAsync(session, CancellationToken.None),
                    "Redirect never carries bearer to another origin");
            }
            using (var service = new AgentMachineKeyEnrollmentRemote(
                store, "https://ds.bke.test", new ProofHandler(bearer,
                    sessionId, accountId, userId, deviceId) { WrongVersion = true }))
            {
                await RejectAsync(() => service.EnrollAsync(session, CancellationToken.None),
                    "Protocol-version drift fails closed");
            }
            using (var service = new AgentMachineKeyEnrollmentRemote(
                store, "https://ds.bke.test", new ProofHandler(bearer,
                    sessionId, accountId, userId, deviceId) { DuplicateMember = true }))
            {
                await RejectAsync(() => service.EnrollAsync(session, CancellationToken.None),
                    "Duplicate JSON authority fields fail closed");
            }
            await RejectAsync(async () =>
            {
                using var service = new AgentMachineKeyEnrollmentRemote(
                    store, "https://ds.bke.test", new ProofHandler(bearer,
                        sessionId, accountId, userId, deviceId));
                await service.EnrollAsync(session with {
                    AccessTokenExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-2),
                }, CancellationToken.None);
            }, "Expired Agent bearer cannot start enrollment");
            bool refused = false;
            try
            {
                using var invalid = new AgentMachineKeyEnrollmentRemote(store,
                    "http://public-ds.bke.test", new ProofHandler(bearer,
                        sessionId, accountId, userId, deviceId));
            }
            catch (InvalidOperationException) { refused = true; }
            Pass(refused, "Non-HTTPS public endpoint rejected");
            Console.WriteLine("BKE Agent real DS-shaped enrollment transport PASS (" + passed +
                " assertions, in-memory HTTP without production/network).");
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    private sealed class ProofHandler : HttpMessageHandler
    {
        private readonly string _bearer, _session, _account, _user, _device;
        private readonly string _challenge = Guid.NewGuid().ToString("D");
        private readonly string _registration = Guid.NewGuid().ToString("D");
        private readonly string _nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        private string? _message, _publicPem;
        public bool WrongAccount { get; init; }
        public bool Redirect { get; init; }
        public bool WrongVersion { get; init; }
        public bool DuplicateMember { get; init; }

        public ProofHandler(string bearer, string session, string account, string user, string device)
        {
            _bearer = bearer;
            _session = session;
            _account = account;
            _user = user;
            _device = device;
        }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.RequestUri?.Host != "ds.bke.test" ||
                request.Headers.Authorization?.Scheme != "Bearer" ||
                request.Headers.Authorization.Parameter != _bearer ||
                !request.Headers.TryGetValues("x-bke-account-session-version", out var versions) ||
                versions.SingleOrDefault() != "bke.account-session.v1")
                throw new InvalidDataException("Untrusted Agent enrollment HTTP headers.");

            if (Redirect)
                return new HttpResponseMessage(HttpStatusCode.TemporaryRedirect)
                {
                    Headers = { Location = new Uri("https://evil.bke.test/") },
                };

            string path = request.RequestUri.AbsolutePath;
            var json = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(cancellationToken));
            using (json)
            {
                if (path.EndsWith("/enroll", StringComparison.Ordinal))
                {
                    _publicPem = json.RootElement.GetProperty("public_key_pem").GetString()!;
                    _message = string.Join("\n",
                        "bke.agent-key-proof.v1", "ENROLL", _challenge, _registration,
                        _session, WrongAccount ? "other-account" : _account,
                        _user, _device, "-", "-", _nonce);
                    string encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(_message))
                        .TrimEnd('=').Replace('+', '-').Replace('/', '_');
                    if (DuplicateMember)
                        return Json(HttpStatusCode.Created,
                            "{\"status\":\"challenge\",\"status\":\"evil\"}");
                    return Json(HttpStatusCode.Created, JsonSerializer.Serialize(new
                    {
                        status = "challenge",
                        registration_id = _registration,
                        challenge_id = _challenge,
                        message_base64url = encoded,
                        expires_at = DateTimeOffset.UtcNow.AddSeconds(25).ToString("O"),
                    }));
                }
                if (path.EndsWith("/verify", StringComparison.Ordinal))
                {
                    if (_message is null || _publicPem is null ||
                        json.RootElement.GetProperty("challenge_id").GetString() != _challenge)
                        throw new InvalidDataException("No matching Agent challenge for signature.");
                    byte[] signedBytes = Convert.FromBase64String(
                        json.RootElement.GetProperty("message_base64url").GetString()!
                            .Replace('-', '+').Replace('_', '/').PadRight(
                                4 * ((json.RootElement.GetProperty("message_base64url").GetString()!.Length + 3) / 4), '='));
                    byte[] signature = Convert.FromBase64String(
                        json.RootElement.GetProperty("signature_base64url").GetString()!
                            .Replace('-', '+').Replace('_', '/').PadRight(
                                4 * ((json.RootElement.GetProperty("signature_base64url").GetString()!.Length + 3) / 4), '='));
                    string pemBody = _publicPem.Replace("-----BEGIN PUBLIC KEY-----", "")
                        .Replace("-----END PUBLIC KEY-----", "").Trim();
                    var der = Convert.FromBase64String(pemBody);
                    var verifier = new Ed25519Signer();
                    verifier.Init(false, new Ed25519PublicKeyParameters(der, 12));
                    verifier.BlockUpdate(signedBytes, 0, signedBytes.Length);
                    if (Encoding.UTF8.GetString(signedBytes) != _message ||
                        !verifier.VerifySignature(signature))
                        throw new InvalidDataException("Agent did not sign the exact DS challenge.");
                    return Json(HttpStatusCode.OK, JsonSerializer.Serialize(new
                    {
                        status = "enrolled",
                        registration_id = _registration,
                    }));
                }
                if (path.EndsWith("/revoke", StringComparison.Ordinal))
                {
                    if (json.RootElement.GetProperty("registration_id").GetString() != _registration)
                        throw new InvalidDataException("Revoke registration mismatch.");
                    return Json(HttpStatusCode.OK, "{\"status\":\"revoked\"}");
                }
            }
            throw new InvalidOperationException("Unexpected Agent key transport route.");
        }

        private HttpResponseMessage Json(HttpStatusCode status, string text)
        {
            var response = new HttpResponseMessage(status)
            {
                Content = new StringContent(text, Encoding.UTF8, "application/json"),
            };
            response.Headers.TryAddWithoutValidation(
                "x-bke-account-session-version",
                WrongVersion ? "bke.account-session.invalid" : "bke.account-session.v1");
            response.Headers.CacheControl = new CacheControlHeaderValue { NoStore = true };
            return response;
        }
    }
}
