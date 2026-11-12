using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using BKE.LicensingAgent.Infrastructure;

if (args.Length != 3)
    throw new ArgumentException("Usage: lease-fraction-certification <vectors.json> <producer.json> <manifest.json>");

const string VectorDigest = "1e4fefe9df64dd2b0313a7b127c850417659a092647e515411a6595900802d80";
var agentSha = Environment.GetEnvironmentVariable("BKE_AGENT_SHA")
    ?? throw new InvalidOperationException("Missing Agent exact SHA");
var librarySha = Environment.GetEnvironmentVariable("BKE_LIBRARY_SHA")
    ?? throw new InvalidOperationException("Missing library exact SHA");
if (!Regex.IsMatch(agentSha, "^[0-9a-f]{40}$") ||
    !Regex.IsMatch(librarySha, "^[0-9a-f]{40}$"))
    throw new InvalidOperationException("Invalid source SHA: certification is fail closed.");

var vectorBytes = File.ReadAllBytes(args[0]);
var actualDigest = Convert.ToHexString(SHA256.HashData(vectorBytes))
    .ToLowerInvariant();
if (actualDigest != VectorDigest)
    throw new InvalidDataException(
        $"Upstream golden-vector digest drifted: {actualDigest}");

using var fixture = JsonDocument.Parse(vectorBytes);
using var producer = JsonDocument.Parse(File.ReadAllBytes(args[1]));
var root = fixture.RootElement;
var signed = producer.RootElement;
if (root.GetProperty("schema").GetString() != "bke.lease-vectors.v1" ||
    root.GetProperty("libraryContract").GetString() != "bke.product-lease.v1" ||
    signed.GetProperty("schema").GetString() != "bke.lease-fraction-producer.v1")
    throw new InvalidDataException("Fraction proof schema mismatch.");

var expectedData = root.GetProperty("expected");
var now = DateTimeOffset.ParseExact(
    root.GetProperty("now").GetString()!,
    "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
    CultureInfo.InvariantCulture,
    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);

var context = new AccountProductLeaseExpected(
    expectedData.GetProperty("issuer").GetString()!,
    expectedData.GetProperty("audience").GetString()!,
    expectedData.GetProperty("accountId").GetString()!,
    expectedData.GetProperty("userId").GetString()!,
    expectedData.GetProperty("productId").GetString()!,
    expectedData.GetProperty("agentSessionId").GetString()!,
    expectedData.GetProperty("agentKeyThumbprint").GetString()!,
    expectedData.GetProperty("action").GetString()!,
    now);

var activeKid = root.GetProperty("activeKid").GetString()!;
var retiredKid = root.GetProperty("retiredKid").GetString()!;
var publicKey = root.GetProperty("publicKeyPem").GetString()!;
var trust = new Dictionary<string, AccountProductLeaseTrustedKey>(StringComparer.Ordinal)
{
    [activeKid] = new(publicKey, "ACTIVE"),
    [retiredKid] = new(publicKey, "REVOKED"),
};
var total = 0;
var accepts = 0;
var rejects = 0;
void Check(string label, string jws, AccountProductLeaseExpected expected,
    bool allow, string? expectedReason = null,
    IReadOnlyDictionary<string, AccountProductLeaseTrustedKey>? ring = null)
{
    var result = AccountProductLeaseJwsVerifier.Verify(jws, ring ?? trust, expected);
    total++;
    if (result.Ok != allow ||
        (!allow && result.Reason != expectedReason) ||
        (allow && (result.Reason is not null ||
                   result.Claims is null ||
                   result.Kid != activeKid)))
    {
        throw new InvalidDataException(
            $"FAIL {label}: expected {(allow ? "ACCEPT" : expectedReason)}, " +
            $"actual {(result.Ok ? "ACCEPT" : result.Reason)}");
    }
    if (allow) accepts++; else rejects++;
    Console.WriteLine($"PASS {label}: {(allow ? "ACCEPT" : expectedReason)}");
}

var vectorList = root.GetProperty("vectors").EnumerateArray().ToArray();
if (vectorList.Length != 14 ||
    vectorList.Select(x => x.GetProperty("name").GetString())
        .Distinct(StringComparer.Ordinal).Count() != 14)
    throw new InvalidDataException("The 14 mandatory upstream test cases are missing or duplicated.");

foreach (var vector in vectorList)
{
    var name = vector.GetProperty("name").GetString()!;
    var expectedAccept = vector.GetProperty("accept").GetBoolean();
    var reason = expectedAccept ? null : vector.GetProperty("reason").GetString();
    Check("golden/" + name, vector.GetProperty("jws").GetString()!,
        context, expectedAccept, reason);
}

var validJws = signed.GetProperty("validJws").GetString()!;
var useJws = signed.GetProperty("useJws").GetString()!;
var canonicalValid = vectorList
    .Single(x => x.GetProperty("name").GetString() == "valid")
    .GetProperty("jws").GetString()!;
if (validJws != canonicalValid)
    throw new InvalidDataException("Real TypeScript issuer output changed signed bytes.");

Check("real-ts-signer/open", validJws, context, true);
Check("real-ts-signer/use", useJws, context with { Action = "USE" }, true);
Check("real-ts-signer/wrong-action", useJws, context, false, "CLAIM_MISMATCH");
Check("real-ts-signer/wrong-user", validJws,
    context with { UserId = "wrong-user" }, false, "CLAIM_MISMATCH");
Check("real-ts-signer/exclusive-expiry", validJws,
    context with { Now = new DateTimeOffset(2026, 11, 14, 0, 0, 0, TimeSpan.Zero) },
    false, "EXPIRED");

var verificationOnly = new Dictionary<string, AccountProductLeaseTrustedKey>(trust)
{
    [activeKid] = new(publicKey, "VERIFY_ONLY"),
};
Check("real-ts-signer/rotated-verification-key", validJws, context,
    true, ring: verificationOnly);

var output = new
{
    schema = "bke.fraction-contract-proof.v1",
    intent = "real TypeScript account-product lease signer to independent Agent .NET verifier",
    level = "L1",
    producer = new { repo = "jan2xo/bke-libraries-typescript", sha = librarySha },
    consumer = new { repo = "jan2xo/bke-licensing-agent", sha = agentSha },
    contract = new { name = "bke.product-lease.v1", fixtureSha256 = VectorDigest },
    assertions = new { total, passed = total, failed = 0, skipped = 0 },
    expectedAccepts = accepts,
    expectedRejects = rejects,
    unexpectedAccepts = 0,
    result = "PASS",
    limitations = new[]
    {
        "Synthetic test-only signer; not a Digital Solutions entitlement issuance route",
        "No Agent TPM key possession or live session custody proven",
        "No authentic Render Dock binary or installed Windows proof",
    },
};
File.WriteAllText(args[2], JsonSerializer.Serialize(output,
    new JsonSerializerOptions { WriteIndented = true }) + Environment.NewLine);
Console.WriteLine(
    $"BKE FRACTION CONTRACT PASS | L1 | {total}/{total} | unexpected-accepts=0");
