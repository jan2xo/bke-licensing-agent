using System.Text;
using System.Text.Json;
using BKE.LicensingAgent.Bootstrap;
using NSec.Cryptography;

if (args.Length == 2 && args[0] == "--fixture")
{
    RunExternalFixture(args[1]);
    return;
}

var root = Path.Combine(Path.GetTempPath(), "bke-phase9-self-update-" + Guid.NewGuid().ToString("N"));
var trust = Path.Combine(root, "trust");
var data = Path.Combine(root, "data");
Directory.CreateDirectory(trust);
Directory.CreateDirectory(data);
Environment.SetEnvironmentVariable("BKE_AGENT_UPDATE_AUTHORITY_KEY_DIR", trust);
Environment.SetEnvironmentVariable("BKE_AGENT_DATA_DIR", data);

try
{
    var algorithm = SignatureAlgorithm.Ed25519;
    using var key = Key.Create(algorithm, new KeyCreationParameters
    {
        ExportPolicy = KeyExportPolicies.AllowPlaintextExport,
    });
    var publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
    const string keyId = "phase9-certification-v1";
    File.WriteAllText(
        Path.Combine(trust, keyId + ".json"),
        JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["schema"] = UpdatePolicyVerifier.KeySchema,
            ["key_id"] = keyId,
            ["algorithm"] = "Ed25519",
            ["public_key"] = Convert.ToBase64String(publicKey),
        }));

    var artifact = Encoding.ASCII.GetBytes("MZphase9-certified-installer");
    var artifactPath = Path.Combine(root, "BKE-Licensing-Agent-2.0.1-Windows-x64.exe");
    File.WriteAllBytes(artifactPath, artifact);
    var hash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(artifact)).ToLowerInvariant();

    var valid = CreateSignedPolicy(
        key,
        keyId,
        currentVersion: "2.0.0",
        latestVersion: "2.0.1",
        minimumSupportedVersion: "2.0.0",
        architecture: "x86_64",
        revision: 2,
        artifactSha256: hash,
        artifactSize: artifact.Length);

    using var validJson = JsonDocument.Parse(SerializePolicy(valid));
    var verified = UpdatePolicyVerifier.ParseAndVerify(validJson.RootElement, "2.0.0", "x86_64");
    Require(verified.UpdateAvailable, "valid signed policy did not advertise update");
    Require(!verified.Required, "valid signed policy unexpectedly required update");
    Require(
        UpdatePolicyVerifier.CatalogAssetUri(verified).AbsoluteUri ==
        "https://github.com/jan2xo/bke-software-catalog/releases/download/bke-licensing-agent-v2.0.1/BKE-Licensing-Agent-2.0.1-Windows-x64.exe",
        "catalog URL was not derived from signed release/artifact identity");
    UpdatePolicyVerifier.VerifyArtifact(artifactPath, verified);
    UpdatePolicyRevisionStore.Accept(verified);

    ExpectFailure(
        () =>
        {
            var tampered = SerializePolicy(valid).Replace(hash, new string('0', 64), StringComparison.Ordinal);
            using var document = JsonDocument.Parse(tampered);
            _ = UpdatePolicyVerifier.ParseAndVerify(document.RootElement, "2.0.0", "x86_64");
        },
        "tampered signed field was accepted");

    ExpectFailure(
        () =>
        {
            using var document = JsonDocument.Parse(SerializePolicy(valid).Replace(keyId, "unknown-phase9-key", StringComparison.Ordinal));
            _ = UpdatePolicyVerifier.ParseAndVerify(document.RootElement, "2.0.0", "x86_64");
        },
        "unknown update authority key was accepted");

    ExpectFailure(
        () =>
        {
            using var document = JsonDocument.Parse(SerializePolicy(valid));
            _ = UpdatePolicyVerifier.ParseAndVerify(document.RootElement, "2.0.0", "arm64");
        },
        "wrong architecture policy was accepted");

    ExpectFailure(
        () =>
        {
            var extra = SerializePolicy(valid).TrimEnd('}') + ",\"unexpected\":true}";
            using var document = JsonDocument.Parse(extra);
            _ = UpdatePolicyVerifier.ParseAndVerify(document.RootElement, "2.0.0", "x86_64");
        },
        "policy with an extra unsigned field was accepted");

    var stale = CreateSignedPolicy(
        key,
        keyId,
        currentVersion: "2.0.0",
        latestVersion: "2.0.1",
        minimumSupportedVersion: "2.0.0",
        architecture: "x86_64",
        revision: 1,
        artifactSha256: hash,
        artifactSize: artifact.Length);
    using (var staleJson = JsonDocument.Parse(SerializePolicy(stale)))
    {
        var staleVerified = UpdatePolicyVerifier.ParseAndVerify(staleJson.RootElement, "2.0.0", "x86_64");
        ExpectFailure(() => UpdatePolicyRevisionStore.Accept(staleVerified), "stale signed revision was accepted");
    }

    File.WriteAllBytes(artifactPath, Encoding.ASCII.GetBytes("MZtampered-installer"));
    ExpectFailure(
        () => UpdatePolicyVerifier.VerifyArtifact(artifactPath, verified),
        "tampered installer bytes were accepted");

    Console.WriteLine("BKE Licensing Agent Phase 9 signed self-update certification: PASS");
    Console.WriteLine("Checks: signature, exact fields, trusted key, architecture, revision, derived catalog identity, SHA-256, size");
}
finally
{
    try { Directory.Delete(root, recursive: true); } catch { }
}

static SignedUpdatePolicy CreateSignedPolicy(
    Key key,
    string keyId,
    string currentVersion,
    string latestVersion,
    string minimumSupportedVersion,
    string architecture,
    long revision,
    string artifactSha256,
    long artifactSize)
{
    var suffix = architecture == "x86_64" ? "x64" : "arm64";
    var unsigned = new SignedUpdatePolicy(
        UpdatePolicyVerifier.Schema,
        RuntimeBridgeContract.AgentProductId,
        currentVersion,
        latestVersion,
        minimumSupportedVersion,
        "stable",
        "windows",
        architecture,
        $"bke-licensing-agent-v{latestVersion}",
        $"BKE-Licensing-Agent-{latestVersion}-Windows-{suffix}.exe",
        artifactSha256,
        artifactSize,
        "application/vnd.microsoft.portable-executable",
        "2026-09-18T17:00:00Z",
        DateTimeOffset.UtcNow.AddMinutes(-1).ToString("O"),
        revision,
        keyId,
        "Ed25519",
        "");
    var signature = SignatureAlgorithm.Ed25519.Sign(key, UpdatePolicyVerifier.CanonicalPayload(unsigned));
    return unsigned with { Signature = Convert.ToBase64String(signature) };
}

static string SerializePolicy(SignedUpdatePolicy policy) =>
    JsonSerializer.Serialize(new Dictionary<string, object?>
    {
        ["schema"] = policy.Schema,
        ["product_id"] = policy.ProductId,
        ["current_version"] = policy.CurrentVersion,
        ["latest_version"] = policy.LatestVersion,
        ["minimum_supported_version"] = policy.MinimumSupportedVersion,
        ["channel"] = policy.Channel,
        ["platform"] = policy.Platform,
        ["architecture"] = policy.Architecture,
        ["release_id"] = policy.ReleaseId,
        ["artifact_id"] = policy.ArtifactId,
        ["artifact_sha256"] = policy.ArtifactSha256,
        ["artifact_size"] = policy.ArtifactSize,
        ["content_type"] = policy.ContentType,
        ["published_at"] = policy.PublishedAt,
        ["issued_at"] = policy.IssuedAt,
        ["revision"] = policy.Revision,
        ["signing_key_id"] = policy.SigningKeyId,
        ["algorithm"] = policy.Algorithm,
        ["signature"] = policy.Signature,
    });

static void RunExternalFixture(string fixturePath)
{
    using var source = JsonDocument.Parse(File.ReadAllText(fixturePath));
    var root = source.RootElement;
    if (root.GetProperty("schema").GetString() != "bke.phase9-cross-repository-fixture.v1")
        throw new InvalidDataException("unexpected cross-repository fixture schema");
    if (root.GetProperty("source").GetString() != "bke-digital-solutions-v2")
        throw new InvalidDataException("unexpected cross-repository fixture source");

    var temp = Path.Combine(Path.GetTempPath(), "bke-phase9-cross-repo-" + Guid.NewGuid().ToString("N"));
    var trust = Path.Combine(temp, "trust");
    var data = Path.Combine(temp, "data");
    Directory.CreateDirectory(trust);
    Directory.CreateDirectory(data);
    Environment.SetEnvironmentVariable("BKE_AGENT_UPDATE_AUTHORITY_KEY_DIR", trust);
    Environment.SetEnvironmentVariable("BKE_AGENT_DATA_DIR", data);

    try
    {
        var count = 0;
        foreach (var fixture in root.GetProperty("fixtures").EnumerateArray())
        {
            var architecture = fixture.GetProperty("architecture").GetString()
                ?? throw new InvalidDataException("fixture architecture is missing");
            var policyElement = fixture.GetProperty("policy");
            var currentVersion = policyElement.GetProperty("current_version").GetString()
                ?? throw new InvalidDataException("fixture current version is missing");
            var keyId = policyElement.GetProperty("signing_key_id").GetString()
                ?? throw new InvalidDataException("fixture signing key id is missing");
            var publicKey = fixture.GetProperty("public_key").GetString()
                ?? throw new InvalidDataException("fixture public key is missing");

            File.WriteAllText(
                Path.Combine(trust, keyId + ".json"),
                JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["schema"] = UpdatePolicyVerifier.KeySchema,
                    ["key_id"] = keyId,
                    ["algorithm"] = "Ed25519",
                    ["public_key"] = publicKey,
                }));

            var verified = UpdatePolicyVerifier.ParseAndVerify(
                policyElement,
                currentVersion,
                architecture);
            UpdatePolicyRevisionStore.Accept(verified);

            var expectedUrl = fixture.GetProperty("expected_catalog_url").GetString()
                ?? throw new InvalidDataException("fixture catalog URL is missing");
            if (UpdatePolicyVerifier.CatalogAssetUri(verified).AbsoluteUri != expectedUrl)
                throw new InvalidDataException("cross-repository catalog URL mismatch");

            var artifact = Convert.FromBase64String(
                fixture.GetProperty("artifact_base64").GetString()
                ?? throw new InvalidDataException("fixture artifact is missing"));
            var artifactPath = Path.Combine(temp, verified.ArtifactId);
            File.WriteAllBytes(artifactPath, artifact);
            UpdatePolicyVerifier.VerifyArtifact(artifactPath, verified);
            count++;
        }

        if (count != 2)
            throw new InvalidDataException($"expected x64 + ARM64 fixtures, got {count}");

        Console.WriteLine("BKE Licensing Agent Phase 9 cross-repository signature certification: PASS");
        Console.WriteLine("Authority: BKE Digital Solutions V2");
        Console.WriteLine("Architectures: x86_64, arm64");
    }
    finally
    {
        try { Directory.Delete(temp, recursive: true); } catch { }
    }
}

static void ExpectFailure(Action action, string message)
{
    try
    {
        action();
    }
    catch (Exception exception) when (
        exception is InvalidDataException or
        JsonException or
        FormatException)
    {
        return;
    }
    throw new InvalidOperationException(message);
}

static void Require(bool condition, string message)
{
    if (!condition) throw new InvalidOperationException(message);
}
