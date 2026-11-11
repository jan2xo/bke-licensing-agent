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
    private static readonly string ProofDeviceCode =
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
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
            new AccountSessionAccount(userId, "test@bke.test", accountId, "INDIVIDUAL", "Disposable"),
            ProofDeviceCode);
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
                await RejectAsync(() => service.EnrollAsync(session with {
                    EnrollmentDeviceCode = null,
                }, CancellationToken.None),
                    "Stolen Agent bearer without original handoff code cannot enroll");
                await RejectAsync(() => service.EnrollAsync(session with {
                    EnrollmentDeviceCode = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
                        .TrimEnd('=').Replace('+', '-').Replace('/', '_'),
                }, CancellationToken.None),
                    "Wrong device authorization code is refused by DS-shaped peer");
            }
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
            await RunReceiptAsync(root, session, bearer, sessionId, accountId, userId, deviceId);
            Console.WriteLine("BKE Agent real DS-shaped enrollment transport PASS (" + passed +
                " assertions, in-memory HTTP without production/network).");
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    private static async Task RunReceiptAsync(
        string root, ActiveAccountSessionState session, string bearer,
        string sessionId, string accountId, string userId, string deviceId)
    {
        int passed = 0;
        void Check(bool accepted, string message)
        {
            if (!accepted) throw new InvalidOperationException("FAIL: " + message);
            Console.WriteLine("PASS: " + message);
            passed++;
        }
        var directory = Path.Combine(root, "durable-receipt");
        var local = new WindowsDpapiEd25519MachineKeyStore(directory);
        var binding = new AgentEd25519SessionBinding(
            sessionId, accountId, userId, deviceId);
        var handler = new ProofHandler(bearer, sessionId, accountId, userId, deviceId)
        {
            DropVerifyAcknowledgementOnce = true,
        };
        using var remote = new AgentMachineKeyEnrollmentRemote(
            local, "https://ds.bke.test", handler);
        var coordinator = new AgentMachineKeyRegistrationCoordinator(local, remote);
        bool ackLost = false;
        try { await coordinator.EnsureEnrolledAsync(session, CancellationToken.None); }
        catch (HttpRequestException) { ackLost = true; }
        Check(ackLost, "Simulated server activated key but final response was lost");
        Check(local.ReadReceipt(binding) is null,
            "Unconfirmed response never persists local registration receipt");
        var recovered = await coordinator.EnsureEnrolledAsync(session, CancellationToken.None);
        Check(recovered.RegistrationId.Length == 36 && recovered.ValidUntil is not null,
            "Lost acknowledgment recovered from authenticated ACTIVE server metadata");
        Check(handler.EnrollRequests == 1,
            "Recovery never creates another DS registration or overwrites key");
        var reloaded = new WindowsDpapiEd25519MachineKeyStore(directory);
        var second = new AgentMachineKeyRegistrationCoordinator(reloaded, remote);
        var afterRestart = await second.EnsureEnrolledAsync(session, CancellationToken.None);
        Check(afterRestart.RegistrationId == recovered.RegistrationId &&
              afterRestart.KeyThumbprint == recovered.KeyThumbprint,
            "Agent restart restores exact DPAPI-protected receipt");
        Check(handler.EnrollRequests == 1, "Restart never duplicates enrollment");

        bool wrong = false;
        try { _ = reloaded.ReadReceipt(binding with { AccountId = "foreign-account" }); }
        catch (InvalidDataException) { wrong = true; }
        Check(wrong, "Foreign account cannot read protected registration receipt");

        bool guarded = false;
        try { reloaded.RemoveLocalKey(); }
        catch (InvalidOperationException) { guarded = true; }
        Check(guarded, "Local private key reset forbidden while receipt exists");

        string receiptPath = Directory.GetFiles(directory, "*.receipt.dpapi",
            SearchOption.AllDirectories).Single();
        byte[] previous = File.ReadAllBytes(receiptPath);
        byte[] corrupt = (byte[])previous.Clone();
        corrupt[corrupt.Length / 2] ^= 0x7F;
        File.WriteAllBytes(receiptPath, corrupt);
        bool damaged = false;
        try { _ = reloaded.ReadReceipt(binding); }
        catch (InvalidDataException) { damaged = true; }
        catch (System.ComponentModel.Win32Exception) { damaged = true; }
        Check(damaged, "Corrupt encrypted receipt cannot be accepted or regenerated");
        File.WriteAllBytes(receiptPath, previous);
        Check(reloaded.ReadReceipt(binding)?.RegistrationId == recovered.RegistrationId,
            "Unmodified encrypted receipt remains readable after corruption rejection");

        handler.FailRevoke = true;
        var accountStore = new MemorySessionStore(session);
        var fakeAccountRemote = new MemoryAccountRemote();
        var sessions = new AccountSessionService(
            fakeAccountRemote, accountStore, keyLifecycle: second);
        var failed = await sessions.LogoutAsync(
            new AccountSessionLogoutRequest("receipt-revocation"),
            CancellationToken.None);
        Check(failed.Status == "FAILED" && failed.Error?.Code == "KEY_REVOCATION_PENDING",
            "Server revocation outage blocks local session erasure");
        Check(accountStore.State is ActiveAccountSessionState &&
              fakeAccountRemote.RevokeCalls == 0 &&
              reloaded.ReadReceipt(binding) is not null,
            "Failed cleanup preserves authenticated bearer and protected receipt for retry");

        handler.FailRevoke = false;
        var logout = await sessions.LogoutAsync(
            new AccountSessionLogoutRequest("receipt-retry"),
            CancellationToken.None);
        Check(logout.Status == "SIGNED_OUT" &&
              accountStore.State is null && fakeAccountRemote.RevokeCalls == 1,
            "Confirmed DS key revocation precedes final AccountSession logout");
        Check(Directory.GetFiles(directory, "*.dpapi",
            SearchOption.AllDirectories).Length == 0,
            "Confirmed terminal revocation clears both receipt and software private key");
        Check(handler.EnrollRequests == 1, "No silent key regeneration across logout lifecycle");
        Console.WriteLine("BKE Agent protected receipt/restart/revocation lifecycle PASS (" +
            passed + " assertions, disposable Windows DPAPI + HTTP handler).");
    }

    private sealed class MemorySessionStore : IAccountSessionSecretStore
    {
        public AccountSessionStoredState? State { get; private set; }
        public MemorySessionStore(AccountSessionStoredState state) => State = state;
        public Task<AccountSessionStoredState?> ReadAsync(CancellationToken ct)
        { ct.ThrowIfCancellationRequested(); return Task.FromResult(State); }
        public Task WriteAsync(AccountSessionStoredState state, CancellationToken ct)
        { ct.ThrowIfCancellationRequested(); State = state; return Task.CompletedTask; }
        public Task ClearAsync(CancellationToken ct)
        { ct.ThrowIfCancellationRequested(); State = null; return Task.CompletedTask; }
    }

    private sealed class MemoryAccountRemote : IAccountSessionRemote
    {
        public int RevokeCalls { get; private set; }
        public Task<RemoteAccountSessionStart> StartAsync(CancellationToken ct) =>
            throw new NotSupportedException();
        public Task<RemoteAccountSessionPoll> PollAsync(string code, CancellationToken ct) =>
            throw new NotSupportedException();
        public Task<RemoteAccountSessionPoll> ExchangeNativeAsync(string code, CancellationToken ct) =>
            throw new NotSupportedException();
        public Task<RemoteAccountSessionRefresh> RefreshAsync(string token, CancellationToken ct) =>
            throw new NotSupportedException();
        public Task AcknowledgeAsync(string token, CancellationToken ct) =>
            throw new NotSupportedException();
        public Task RevokeAsync(string? sessionId, string? refreshToken,
            string? deviceCode, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            RevokeCalls++;
            return Task.CompletedTask;
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
        private readonly DateTimeOffset _validUntil = DateTimeOffset.UtcNow.AddHours(12);
        private bool _active, _pending, _revoked;
        public bool DropVerifyAcknowledgementOnce { get; set; }
        public bool FailRevoke { get; set; }
        public int EnrollRequests { get; private set; }
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
                if (path.EndsWith("/status", StringComparison.Ordinal))
                {
                    string? lookup = json.RootElement.TryGetProperty("registration_id", out var field)
                        ? field.GetString() : null;
                    if (lookup is not null && lookup != _registration)
                        return Json(HttpStatusCode.OK, "{\"status\":\"none\"}");
                    if (!_pending && !_active && !(lookup is not null && _revoked))
                        return Json(HttpStatusCode.OK, "{\"status\":\"none\"}");
                    string pemBody = _publicPem!.Replace("-----BEGIN PUBLIC KEY-----", "")
                        .Replace("-----END PUBLIC KEY-----", "").Trim();
                    string thumbprint = Convert.ToBase64String(
                        SHA256.HashData(Convert.FromBase64String(pemBody)))
                        .TrimEnd('=').Replace('+', '-').Replace('/', '_');
                    return Json(HttpStatusCode.OK, JsonSerializer.Serialize(new
                    {
                        status = "registration",
                        registration_id = _registration,
                        registration_state = _revoked ? "revoked" : _active ? "active" : "pending",
                        key_thumbprint = thumbprint,
                        key_protection = "software",
                        valid_until = _validUntil.UtcDateTime.ToString("O"),
                    }));
                }
                if (path.EndsWith("/enroll", StringComparison.Ordinal))
                {
                    EnrollRequests++;
                    _pending = true;
                    if (json.RootElement.GetProperty("device_code").GetString() != ProofDeviceCode)
                        return Json(HttpStatusCode.Forbidden, "{\"error\":\"INVALID_PROOF\"}");
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
                        expires_at = DateTimeOffset.UtcNow.AddSeconds(25).UtcDateTime.ToString("O"),
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
                    _active = true;
                    _pending = false;
                    if (DropVerifyAcknowledgementOnce)
                    {
                        DropVerifyAcknowledgementOnce = false;
                        throw new HttpRequestException("Disposable lost final enrollment ACK.");
                    }
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
                    if (FailRevoke)
                        return Json(HttpStatusCode.ServiceUnavailable, "{\"error\":\"DISPOSABLE_OFFLINE\"}");
                    _revoked = true;
                    _active = false;
                    _pending = false;
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
