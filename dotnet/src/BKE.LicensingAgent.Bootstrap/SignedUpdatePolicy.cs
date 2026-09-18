using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.RegularExpressions;
using NSec.Cryptography;

namespace BKE.LicensingAgent.Bootstrap;

internal sealed record SignedUpdatePolicy(
    string Schema,
    string ProductId,
    string CurrentVersion,
    string LatestVersion,
    string MinimumSupportedVersion,
    string Channel,
    string Platform,
    string Architecture,
    string ReleaseId,
    string ArtifactId,
    string ArtifactSha256,
    long ArtifactSize,
    string ContentType,
    string PublishedAt,
    string IssuedAt,
    long Revision,
    string SigningKeyId,
    string Algorithm,
    string Signature)
{
    internal bool UpdateAvailable =>
        SemanticVersion.Parse(LatestVersion).CompareTo(SemanticVersion.Parse(CurrentVersion)) > 0;

    internal bool Required =>
        SemanticVersion.Parse(CurrentVersion).CompareTo(SemanticVersion.Parse(MinimumSupportedVersion)) < 0;
}

internal static class UpdatePolicyVerifier
{
    internal const string Schema = "bke.update-policy.v1";
    internal const string KeySchema = "bke.update-authority-key.v1";
    internal const long MaxArtifactBytes = 512L * 1024L * 1024L;

    private static readonly Regex SafeIdentifier = new(
        "^[A-Za-z0-9._-]{1,160}$",
        RegexOptions.CultureInvariant);

    private static readonly Regex LowerSha256 = new(
        "^[a-f0-9]{64}$",
        RegexOptions.CultureInvariant);

    private static readonly HashSet<string> PolicyFields = new(StringComparer.Ordinal)
    {
        "schema",
        "product_id",
        "current_version",
        "latest_version",
        "minimum_supported_version",
        "channel",
        "platform",
        "architecture",
        "release_id",
        "artifact_id",
        "artifact_sha256",
        "artifact_size",
        "content_type",
        "published_at",
        "issued_at",
        "revision",
        "signing_key_id",
        "algorithm",
        "signature",
    };

    private static readonly HashSet<string> KeyFields = new(StringComparer.Ordinal)
    {
        "schema",
        "key_id",
        "algorithm",
        "public_key",
    };

    private static readonly JsonSerializerOptions CanonicalJson = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        WriteIndented = false,
    };

    internal static SignedUpdatePolicy ParseAndVerify(
        JsonElement root,
        string expectedCurrentVersion,
        string expectedArchitecture)
    {
        RequireExactFields(root, PolicyFields, "Agent update policy");

        var policy = new SignedUpdatePolicy(
            RequiredString(root, "schema"),
            RequiredString(root, "product_id"),
            RequiredString(root, "current_version"),
            RequiredString(root, "latest_version"),
            RequiredString(root, "minimum_supported_version"),
            RequiredString(root, "channel"),
            RequiredString(root, "platform"),
            RequiredString(root, "architecture"),
            RequiredString(root, "release_id"),
            RequiredString(root, "artifact_id"),
            RequiredString(root, "artifact_sha256"),
            RequiredInt64(root, "artifact_size"),
            RequiredString(root, "content_type"),
            RequiredString(root, "published_at"),
            RequiredString(root, "issued_at"),
            RequiredInt64(root, "revision"),
            RequiredString(root, "signing_key_id"),
            RequiredString(root, "algorithm"),
            RequiredString(root, "signature"));

        ValidateContract(policy, expectedCurrentVersion, expectedArchitecture);
        VerifySignature(policy);
        return policy;
    }

    internal static Uri CatalogAssetUri(SignedUpdatePolicy policy)
    {
        var tag = Uri.EscapeDataString(policy.ReleaseId);
        var asset = Uri.EscapeDataString(policy.ArtifactId);
        return new Uri(
            $"https://github.com/{RuntimeBridgeContract.CatalogRepository}/releases/download/{tag}/{asset}",
            UriKind.Absolute);
    }

    internal static byte[] CanonicalPayload(SignedUpdatePolicy policy)
    {
        var document = new SortedDictionary<string, object?>(StringComparer.Ordinal)
        {
            ["algorithm"] = policy.Algorithm,
            ["architecture"] = policy.Architecture,
            ["artifact_id"] = policy.ArtifactId,
            ["artifact_sha256"] = policy.ArtifactSha256,
            ["artifact_size"] = policy.ArtifactSize,
            ["channel"] = policy.Channel,
            ["content_type"] = policy.ContentType,
            ["current_version"] = policy.CurrentVersion,
            ["issued_at"] = policy.IssuedAt,
            ["latest_version"] = policy.LatestVersion,
            ["minimum_supported_version"] = policy.MinimumSupportedVersion,
            ["platform"] = policy.Platform,
            ["product_id"] = policy.ProductId,
            ["published_at"] = policy.PublishedAt,
            ["release_id"] = policy.ReleaseId,
            ["revision"] = policy.Revision,
            ["schema"] = policy.Schema,
            ["signing_key_id"] = policy.SigningKeyId,
        };
        return JsonSerializer.SerializeToUtf8Bytes(document, CanonicalJson);
    }

    internal static void VerifyArtifact(string path, SignedUpdatePolicy policy)
    {
        var info = new FileInfo(path);
        if (!info.Exists) throw new InvalidDataException("downloaded Agent installer is missing");
        if (info.Length != policy.ArtifactSize)
            throw new InvalidDataException("downloaded Agent installer size does not match signed update policy");

        using var stream = File.OpenRead(path);
        var digest = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
        if (!CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(digest),
                Encoding.ASCII.GetBytes(policy.ArtifactSha256)))
            throw new InvalidDataException("downloaded Agent installer hash does not match signed update policy");
    }

    private static void ValidateContract(
        SignedUpdatePolicy policy,
        string expectedCurrentVersion,
        string expectedArchitecture)
    {
        if (policy.Schema != Schema) throw new InvalidDataException("Agent update policy schema mismatch");
        if (policy.ProductId != RuntimeBridgeContract.AgentProductId)
            throw new InvalidDataException("Agent update policy product identity mismatch");
        if (policy.CurrentVersion != expectedCurrentVersion)
            throw new InvalidDataException("Agent update policy current version mismatch");
        if (policy.Channel != "stable") throw new InvalidDataException("Agent update policy channel mismatch");
        if (policy.Platform != "windows") throw new InvalidDataException("Agent update policy platform mismatch");
        if (policy.Architecture != expectedArchitecture)
            throw new InvalidDataException("Agent update policy architecture mismatch");
        if (policy.Algorithm != "Ed25519")
            throw new InvalidDataException("Agent update policy algorithm is unsupported");
        if (!SafeIdentifier.IsMatch(policy.SigningKeyId))
            throw new InvalidDataException("Agent update policy signing key id is malformed");
        if (!LowerSha256.IsMatch(policy.ArtifactSha256))
            throw new InvalidDataException("Agent update policy artifact hash is malformed");
        if (policy.ArtifactSize < 2 || policy.ArtifactSize > MaxArtifactBytes)
            throw new InvalidDataException("Agent update policy artifact size is invalid");
        if (string.IsNullOrWhiteSpace(policy.ContentType) || policy.ContentType.Length > 200)
            throw new InvalidDataException("Agent update policy content type is malformed");
        if (policy.Revision < 1) throw new InvalidDataException("Agent update policy revision is invalid");

        var current = SemanticVersion.Parse(policy.CurrentVersion);
        var latest = SemanticVersion.Parse(policy.LatestVersion);
        var minimum = SemanticVersion.Parse(policy.MinimumSupportedVersion);
        if (minimum.CompareTo(latest) > 0)
            throw new InvalidDataException("Agent update policy minimum version exceeds latest version");
        if (current.CompareTo(latest) > 0)
            throw new InvalidDataException("Agent update policy attempts a version rollback");

        var suffix = expectedArchitecture switch
        {
            "x86_64" => "x64",
            "arm64" => "arm64",
            _ => throw new InvalidDataException("Agent update policy architecture is unsupported"),
        };
        var expectedRelease = $"bke-licensing-agent-v{policy.LatestVersion}";
        var expectedArtifact = $"BKE-Licensing-Agent-{policy.LatestVersion}-Windows-{suffix}.exe";
        if (!SafeIdentifier.IsMatch(policy.ReleaseId) || policy.ReleaseId != expectedRelease)
            throw new InvalidDataException("Agent update policy release identity mismatch");
        if (!SafeIdentifier.IsMatch(policy.ArtifactId) || policy.ArtifactId != expectedArtifact)
            throw new InvalidDataException("Agent update policy artifact identity mismatch");

        if (!DateTimeOffset.TryParse(policy.PublishedAt, out _))
            throw new InvalidDataException("Agent update policy published_at is malformed");
        if (!DateTimeOffset.TryParse(policy.IssuedAt, out var issuedAt))
            throw new InvalidDataException("Agent update policy issued_at is malformed");
        if (issuedAt > DateTimeOffset.UtcNow.AddMinutes(10))
            throw new InvalidDataException("Agent update policy issued_at is in the future");
    }

    private static void VerifySignature(SignedUpdatePolicy policy)
    {
        var keyPath = Path.Combine(
            RuntimeBridgeContract.UpdateAuthorityKeyDirectory,
            $"{policy.SigningKeyId}.json");
        if (!File.Exists(keyPath))
            throw new InvalidDataException("Agent update policy signing key is not trusted");

        using var keyDocument = JsonDocument.Parse(File.ReadAllText(keyPath));
        var root = keyDocument.RootElement;
        RequireExactFields(root, KeyFields, "Agent update authority key");
        if (RequiredString(root, "schema") != KeySchema)
            throw new InvalidDataException("Agent update authority key schema mismatch");
        if (RequiredString(root, "key_id") != policy.SigningKeyId)
            throw new InvalidDataException("Agent update authority key id mismatch");
        if (RequiredString(root, "algorithm") != "Ed25519")
            throw new InvalidDataException("Agent update authority key algorithm is unsupported");

        byte[] rawKey;
        byte[] signature;
        try
        {
            rawKey = Convert.FromBase64String(RequiredString(root, "public_key"));
            signature = Convert.FromBase64String(policy.Signature);
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException("Agent update signature material is malformed", exception);
        }

        if (rawKey.Length != 32 || signature.Length != 64)
            throw new InvalidDataException("Agent update signature material has an invalid length");

        var algorithm = SignatureAlgorithm.Ed25519;
        var publicKey = PublicKey.Import(algorithm, rawKey, KeyBlobFormat.RawPublicKey);
        if (!algorithm.Verify(publicKey, CanonicalPayload(policy), signature))
            throw new InvalidDataException("Agent update policy signature is invalid");
    }

    private static string RequiredString(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var value) ||
            value.ValueKind != JsonValueKind.String ||
            string.IsNullOrWhiteSpace(value.GetString()))
            throw new InvalidDataException($"Agent update policy is missing {name}");
        return value.GetString()!;
    }

    private static long RequiredInt64(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var value) ||
            value.ValueKind != JsonValueKind.Number ||
            !value.TryGetInt64(out var result))
            throw new InvalidDataException($"Agent update policy is missing {name}");
        return result;
    }

    private static void RequireExactFields(JsonElement root, HashSet<string> expected, string description)
    {
        if (root.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException($"{description} is not an object");
        var actual = root.EnumerateObject().Select(property => property.Name)
            .ToHashSet(StringComparer.Ordinal);
        if (!actual.SetEquals(expected))
            throw new InvalidDataException($"{description} fields do not match the signed contract");
    }
}

internal static class UpdatePolicyRevisionStore
{
    private static readonly object Gate = new();

    internal static void Accept(SignedUpdatePolicy policy)
    {
        lock (Gate)
        {
            var directory = Path.Combine(RuntimeBridgeContract.DataRoot, "self-update");
            Directory.CreateDirectory(directory);
            var path = Path.Combine(directory, "authority-revisions.json");
            Dictionary<string, long> revisions;
            if (File.Exists(path))
            {
                try
                {
                    revisions = JsonSerializer.Deserialize<Dictionary<string, long>>(File.ReadAllText(path))
                        ?? throw new InvalidDataException("Agent update authority revision state is empty");
                }
                catch (JsonException exception)
                {
                    throw new InvalidDataException("Agent update authority revision state is malformed", exception);
                }
            }
            else
            {
                revisions = new Dictionary<string, long>(StringComparer.Ordinal);
            }

            if (revisions.TryGetValue(policy.SigningKeyId, out var accepted) && policy.Revision < accepted)
                throw new InvalidDataException("Agent update policy revision is stale");

            if (!revisions.TryGetValue(policy.SigningKeyId, out accepted) || policy.Revision > accepted)
            {
                revisions[policy.SigningKeyId] = policy.Revision;
                var temporary = path + ".tmp";
                File.WriteAllText(
                    temporary,
                    JsonSerializer.Serialize(revisions),
                    new UTF8Encoding(false));
                File.Move(temporary, path, true);
            }
        }
    }
}
