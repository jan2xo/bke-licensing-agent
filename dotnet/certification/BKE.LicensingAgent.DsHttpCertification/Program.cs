using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;
using BKE.LicensingAgent.Infrastructure;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

// This assembly is an isolated CI consumer. The production Agent constructor
// cannot inject this ephemeral signer or bypass Windows DPAPI. Only the named
// friend assembly can supply a test signing/binding provider.
if (args.Length != 1 || args[0] != "--live-disposable-ds")
    throw new InvalidOperationException("Explicit --live-disposable-ds is required.");
static string Env(string key) => Environment.GetEnvironmentVariable(key)
    is { Length: > 0 } value ? value : throw new InvalidOperationException("Missing disposable " + key);

var endpoint = Env("BKE_CROSS_REPO_URL");
if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var uri) ||
    uri.Scheme != "https" || uri.Host != "127.0.0.1" ||
    uri.UserInfo.Length != 0 || uri.AbsolutePath != "/")
    throw new InvalidOperationException("Disposable Agent client must use loopback HTTPS.");
string expectedHash = Env("BKE_CROSS_REPO_CERT_SHA256");
if (expectedHash.Length != 64 || expectedHash.Any(c => !Uri.IsHexDigit(c)))
    throw new InvalidOperationException("Disposable certificate SHA-256 is not pinned.");

string token = Env("BKE_CROSS_REPO_BEARER");
string sessionId = Env("BKE_CROSS_REPO_SESSION_ID");
string accountId = Env("BKE_CROSS_REPO_ACCOUNT_ID");
string userId = Env("BKE_CROSS_REPO_USER_ID");
string deviceId = Env("BKE_CROSS_REPO_DEVICE_ID");
string deviceCode = Env("BKE_CROSS_REPO_DEVICE_CODE");
var trusted = new AgentEd25519SessionBinding(sessionId, accountId, userId, deviceId);
var session = new ActiveAccountSessionState(
    token,
    "disposable-no-refresh",
    sessionId,
    DateTimeOffset.UtcNow.AddMinutes(12),
    DateTimeOffset.UtcNow.AddDays(1),
    new AccountSessionAccount(userId, "disposable@bke.test",
        accountId, "INDIVIDUAL", "Disposable Certification"),
    deviceCode);

using var key = new DisposableSigner();
using var tls = new HttpClientHandler
{
    AllowAutoRedirect = false,
    ServerCertificateCustomValidationCallback = (request, cert, _, _) =>
        request.RequestUri?.Scheme == Uri.UriSchemeHttps &&
        request.RequestUri.Host == "127.0.0.1" &&
        cert is not null &&
        string.Equals(cert.GetCertHashString(HashAlgorithmName.SHA256),
            expectedHash, StringComparison.OrdinalIgnoreCase),
};
using var remote = new AgentMachineKeyEnrollmentRemote(
    key,
    active =>
    {
        if (active.SessionId != sessionId ||
            active.Account.UserId != userId ||
            active.Account.AccountId != accountId)
            throw new InvalidDataException("Trusted disposable Agent account changed.");
        return trusted;
    },
    endpoint, tls);

var wrong = session with { AccessToken = "bad-agent-token-" + Guid.NewGuid().ToString("N") };
bool unauthorized = false;
try { _ = await remote.StatusAsync(wrong, null, CancellationToken.None); }
catch (HttpRequestException error) when (error.StatusCode == HttpStatusCode.Unauthorized)
{ unauthorized = true; }
Check(unauthorized, "Actual DS route rejects invalid Agent bearer");

var before = await remote.StatusAsync(session, null, CancellationToken.None);
Check(before.Status == "none", "Actual DS status route reports no initial key");

bool rejected = false;
try { _ = await remote.EnrollAsync(session with { EnrollmentDeviceCode = "A" + deviceCode[1..] }, CancellationToken.None); }
catch (HttpRequestException ex) when (ex.StatusCode == HttpStatusCode.Forbidden) { rejected = true; }
Check(rejected, "Key enrollment rejects nonmatching device proof");
var enrollment = await remote.EnrollAsync(session, CancellationToken.None);
Check(Guid.TryParseExact(enrollment.RegistrationId, "D", out _),
    "Actual DS route verifies Ed25519 enrollment and returns server registration");
Check(enrollment.KeyThumbprint == key.GetOrCreateIdentity(trusted).KeyThumbprint,
    "Actual DS registration matches ephemeral test SPKI public key");

var current = await remote.StatusAsync(session, enrollment.RegistrationId, CancellationToken.None);
Check(current.Status == "active" &&
      current.RegistrationId == enrollment.RegistrationId &&
      current.KeyThumbprint == enrollment.KeyThumbprint &&
      current.ValidUntil > DateTimeOffset.UtcNow,
    "Actual DS PostgreSQL registration is ACTIVE with matching identity");

await remote.RevokeAsync(session, enrollment, CancellationToken.None);
var revoked = await remote.StatusAsync(session, enrollment.RegistrationId, CancellationToken.None);
Check(revoked.Status == "revoked",
    "Actual DS transaction confirms irreversible terminal registration revoke");

var empty = await remote.StatusAsync(session, null, CancellationToken.None);
Check(empty.Status == "none", "Revoked DS registration is no longer active");
Console.WriteLine("BKE LIVE CROSS-REPO HTTPS + POSTGRESQL PASS (8 assertions; actual DS handlers; separate .NET Agent client).");

static void Check(bool accepted, string label)
{
    if (!accepted) throw new InvalidOperationException("FAIL: " + label);
    Console.WriteLine("PASS: " + label);
}

// EPHEMERAL TEST-ONLY SOFTWARE KEY. It is not Windows DPAPI, attestation,
// or a substitute for the separately certified production Windows signer.
internal sealed class DisposableSigner : IAgentMachineKeyChallengeSigning, IDisposable
{
    private readonly byte[] _seed = RandomNumberGenerator.GetBytes(32);
    private readonly Ed25519PrivateKeyParameters _privateKey;
    private readonly string _publicPem;
    private readonly string _thumbprint;

    public DisposableSigner()
    {
        _privateKey = new Ed25519PrivateKeyParameters(_seed, 0);
        byte[] spki = Convert.FromHexString("302A300506032B6570032100")
            .Concat(_privateKey.GeneratePublicKey().GetEncoded()).ToArray();
        _publicPem = "-----BEGIN PUBLIC KEY-----\n" +
            Convert.ToBase64String(spki) + "\n-----END PUBLIC KEY-----\n";
        _thumbprint = B64(SHA256.HashData(spki));
    }

    public AgentEd25519PublicIdentity GetOrCreateIdentity(
        AgentEd25519SessionBinding binding, bool createIfMissing = true) =>
        new(_publicPem, _thumbprint, "software");

    public string SignChallenge(
        AgentEd25519SessionBinding binding,
        string registrationId, string challengeId,
        string messageBase64url, DateTimeOffset expiresAt,
        string? productId = null, string? action = null)
    {
        if (expiresAt <= DateTimeOffset.UtcNow ||
            expiresAt > DateTimeOffset.UtcNow.AddSeconds(35) ||
            productId is not null || action is not null)
            throw new InvalidDataException("Disposable DS challenge scope/expiry invalid.");
        byte[] message = Convert.FromBase64String(
            messageBase64url.Replace('-', '+').Replace('_', '/').PadRight(
                ((messageBase64url.Length + 3) / 4) * 4, '='));
        try
        {
            if (B64(message) != messageBase64url ||
                message.Length > 4096)
                throw new InvalidDataException("Noncanonical DS challenge.");
            var pieces = new UTF8Encoding(false, true).GetString(message).Split('\n');
            if (pieces.Length != 11 ||
                pieces[0] != "bke.agent-key-proof.v1" ||
                pieces[1] != "ENROLL" ||
                pieces[2] != challengeId ||
                pieces[3] != registrationId ||
                pieces[4] != binding.SessionId ||
                pieces[5] != binding.AccountId ||
                pieces[6] != binding.UserId ||
                pieces[7] != binding.DeviceId ||
                pieces[8] != "-" || pieces[9] != "-" ||
                pieces[10].Length != 43)
                throw new InvalidDataException("DS challenge mismatched trusted disposable Agent context.");
            var signer = new Ed25519Signer();
            signer.Init(true, _privateKey);
            signer.BlockUpdate(message, 0, message.Length);
            return B64(signer.GenerateSignature());
        }
        finally { CryptographicOperations.ZeroMemory(message); }
    }

    private static string B64(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public void Dispose() => CryptographicOperations.ZeroMemory(_seed);
}
