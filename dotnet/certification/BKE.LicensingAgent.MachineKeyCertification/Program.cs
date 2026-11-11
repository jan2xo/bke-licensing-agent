using System.Security.Cryptography;
using System.Text;
using BKE.LicensingAgent.Infrastructure;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

if (!OperatingSystem.IsWindows())
    throw new PlatformNotSupportedException("Windows DPAPI runner is required for this certification.");

int passed = 0;
void Check(bool assertion, string name)
{
    if (!assertion) throw new InvalidOperationException("FAIL: " + name);
    Console.WriteLine("PASS: " + name);
    passed++;
}
void Reject(Action operation, string name)
{
    bool denied = false;
    try { operation(); }
    catch (InvalidDataException) { denied = true; }
    catch (FormatException) { denied = true; }
    catch (System.ComponentModel.Win32Exception) { denied = true; }
    Check(denied, name);
}
string B64(byte[] bytes) => Convert.ToBase64String(bytes)
    .TrimEnd('=').Replace('+', '-').Replace('/', '_');
byte[] Unb64(string value)
{
    string base64 = value.Replace('-', '+').Replace('_', '/');
    return Convert.FromBase64String(base64.PadRight((base64.Length + 3) / 4 * 4, '='));
}
string Message(string purpose, string challenge, string registration,
    AgentEd25519SessionBinding context, string product, string action, string nonce) =>
    string.Join("\n", "bke.agent-key-proof.v1", purpose, challenge, registration,
        context.SessionId, context.AccountId, context.UserId, context.DeviceId,
        product, action, nonce);
void Verify(string publicPem, string message, string signature)
{
    byte[] der = Convert.FromBase64String(publicPem
        .Replace("-----BEGIN PUBLIC KEY-----", "")
        .Replace("-----END PUBLIC KEY-----", "").Trim());
    Check(der.Length == 44 && Convert.ToHexString(der.AsSpan(0, 12)) ==
        "302A300506032B6570032100", "Canonical Ed25519 SPKI DER prefix");
    var verifier = new Ed25519Signer();
    verifier.Init(false, new Ed25519PublicKeyParameters(der, 12));
    var bytes = Encoding.UTF8.GetBytes(message);
    verifier.BlockUpdate(bytes, 0, bytes.Length);
    Check(verifier.VerifySignature(Unb64(signature)), "Actual Ed25519 signature over exact DS message bytes");
    CryptographicOperations.ZeroMemory(bytes);
}
string root = Path.Combine(Path.GetTempPath(), "bke-agent-machine-key-" + Guid.NewGuid().ToString("N"));
var context = new AgentEd25519SessionBinding(
    "agent-session-123", "account-123", "user-123", "device-123");
var wrong = context with { AccountId = "other-account" };
var challenge = Guid.NewGuid().ToString("D");
var registration = Guid.NewGuid().ToString("D");
var nonce = B64(RandomNumberGenerator.GetBytes(32));
var expires = DateTimeOffset.UtcNow.AddSeconds(25);
try
{
    var store = new WindowsDpapiEd25519MachineKeyStore(root);
    var identity = store.GetOrCreateIdentity(context);
    Check(identity.KeyProtection == "software", "Never claims TPM or nonexportable key protection");
    byte[] spki = Convert.FromBase64String(identity.PublicKeyPem
        .Replace("-----BEGIN PUBLIC KEY-----", "")
        .Replace("-----END PUBLIC KEY-----", "").Trim());
    Check(identity.KeyThumbprint == B64(SHA256.HashData(spki)),
        "Thumbprint is SHA256 of exact SPKI DER, base64url");
    Check(!Directory.GetFiles(root, "*", SearchOption.AllDirectories)
        .Any(path => path.EndsWith(".pem", StringComparison.OrdinalIgnoreCase)),
        "No plaintext private PEM material is written");
    var restarted = new WindowsDpapiEd25519MachineKeyStore(root);
    Check(restarted.GetOrCreateIdentity(context) == identity,
        "DPAPI key survives new store instance/restart");
    Reject(() => restarted.GetOrCreateIdentity(wrong),
        "Wrong-account key reuse fails closed");
    Reject(() => restarted.GetOrCreateIdentity(context with { SessionId = "other-session" }),
        "Wrong-session key reuse fails closed");
    Reject(() => restarted.GetOrCreateIdentity(context with { DeviceId = "other-device" }),
        "Wrong-device key reuse fails closed");
    string enrollment = Message("ENROLL", challenge, registration, context, "-", "-", nonce);
    string enrollmentSignature = restarted.SignChallenge(context, registration,
        challenge, B64(Encoding.UTF8.GetBytes(enrollment)), expires);
    Verify(identity.PublicKeyPem, enrollment, enrollmentSignature);
    string lease = Message("LEASE", challenge, registration, context, "render-dock", "USE", nonce);
    string leaseSignature = restarted.SignChallenge(context, registration,
        challenge, B64(Encoding.UTF8.GetBytes(lease)), expires, "render-dock", "USE");
    Verify(identity.PublicKeyPem, lease, leaseSignature);
    Reject(() => restarted.SignChallenge(context, registration, challenge,
        B64(Encoding.UTF8.GetBytes(enrollment)), expires, "render-dock", "USE"),
        "ENROLL cannot be elevated into USE");
    Reject(() => restarted.SignChallenge(context, registration, challenge,
        B64(Encoding.UTF8.GetBytes(lease)), expires, "render-dock", "OPEN"),
        "Wrong action scope fails closed");
    Reject(() => restarted.SignChallenge(context, registration, challenge,
        B64(Encoding.UTF8.GetBytes(lease)), expires, "other-product", "USE"),
        "Wrong product scope fails closed");
    Reject(() => restarted.SignChallenge(wrong, registration, challenge,
        B64(Encoding.UTF8.GetBytes(lease)), expires, "render-dock", "USE"),
        "Changed account in challenge fails closed");
    Reject(() => restarted.SignChallenge(context, Guid.NewGuid().ToString("D"), challenge,
        B64(Encoding.UTF8.GetBytes(lease)), expires, "render-dock", "USE"),
        "Wrong registration fails closed");
    Reject(() => restarted.SignChallenge(context, registration, Guid.NewGuid().ToString("D"),
        B64(Encoding.UTF8.GetBytes(lease)), expires, "render-dock", "USE"),
        "Wrong challenge ID fails closed");
    Reject(() => restarted.SignChallenge(context, registration, challenge,
        B64(Encoding.UTF8.GetBytes(Message("ADMIN", challenge, registration, context, "-", "-", nonce))),
        expires), "Unsupported purpose fails closed");
    Reject(() => restarted.SignChallenge(context, registration, challenge,
        B64(Encoding.UTF8.GetBytes(Message("ENROLL", challenge, registration, context, "-", "-", "wrong"))),
        expires), "Malformed challenge nonce fails closed");
    Reject(() => restarted.SignChallenge(context, registration, challenge,
        B64(Encoding.UTF8.GetBytes(enrollment + "\n")), expires),
        "Unexpected trailing bytes fail closed");
    Reject(() => restarted.SignChallenge(context, registration, challenge,
        B64(Encoding.UTF8.GetBytes(enrollment)), DateTimeOffset.UtcNow.AddSeconds(-1)),
        "Expired challenge fails closed");
    Reject(() => restarted.SignChallenge(context, registration, challenge,
        B64(Encoding.UTF8.GetBytes(enrollment)), DateTimeOffset.UtcNow.AddMinutes(5)),
        "Implausibly long challenge lifetime fails closed");
    Reject(() => restarted.SignChallenge(context, registration, challenge,
        "not_base64=", expires), "Noncanonical base64url fails closed");

    string protectedFile = Directory.GetFiles(root, "*.dpapi", SearchOption.AllDirectories).Single();
    byte[] protectedBytes = File.ReadAllBytes(protectedFile);
    Check(protectedBytes.AsSpan().IndexOf(Encoding.ASCII.GetBytes("BKE-AGENT-ED25519-DPAPI-1")) < 0,
        "Private-key envelope is encrypted at rest");
    protectedBytes[protectedBytes.Length / 2] ^= 0x7F;
    File.WriteAllBytes(protectedFile, protectedBytes);
    Reject(() => restarted.GetOrCreateIdentity(context),
        "Corrupted DPAPI key fails closed without silent regeneration");
    var snapshot = File.ReadAllBytes(protectedFile);
    Reject(() => restarted.GetOrCreateIdentity(context),
        "Second corrupted read still fails closed");
    Check(snapshot.AsSpan().SequenceEqual(File.ReadAllBytes(protectedFile)),
        "Corrupted protected key never overwritten");
    restarted.RemoveLocalKey();
    Check(!File.Exists(protectedFile), "Explicit local reset removes protected key");
    var afterReset = restarted.GetOrCreateIdentity(context);
    Check(afterReset.KeyThumbprint != identity.KeyThumbprint,
        "Explicit reset makes fresh key; server must independently revoke old registration");
}
finally
{
    if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
}
Console.WriteLine("BKE Agent Windows DPAPI Ed25519 source custody PASS (" + passed + " assertions).");
await AgentMachineKeyHttpCertification.RunAsync();
