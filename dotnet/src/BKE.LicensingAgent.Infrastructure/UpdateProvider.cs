using System.Net;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.RegularExpressions;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;
using Microsoft.Data.Sqlite;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.OpenSsl;

namespace BKE.LicensingAgent.Infrastructure;

public sealed class UpdateProvider : IUpdateService
{
    private const string UpdatePackageContentType = "application/vnd.bke.update-package+zip";
    private const string ProtocolVersion = "bke.licensing.v3";
    private static readonly Regex SafePathPattern = new("[^A-Za-z0-9_.-]", RegexOptions.CultureInvariant);
    private static readonly Regex ArtifactHashPattern = new("^[0-9a-fA-F]{64}$", RegexOptions.CultureInvariant);
    private static readonly Regex CoreVersionPattern = new("^(?:0|[1-9][0-9]*)(?:\\.[0-9]+){0,3}$", RegexOptions.CultureInvariant);
    private static readonly Regex ProductIdPattern = new("^[a-z0-9-]+$", RegexOptions.CultureInvariant);
    private static readonly Regex ManifestVersionPattern = new("^\\d+\\.\\d+\\.\\d+(?:[-+].*)?$", RegexOptions.CultureInvariant);
    private static readonly HashSet<string> PolicyKeys = new(StringComparer.Ordinal)
    {
        "schema", "product_id", "current_version", "latest_version", "minimum_supported_version",
        "channel", "platform", "architecture", "release_id", "artifact_id", "artifact_sha256",
        "artifact_size", "content_type", "published_at", "issued_at", "revision", "signing_key_id",
        "algorithm", "signature",
    };
    private static readonly JsonSerializerOptions CanonicalJsonOptions = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    private readonly string _dataDir;
    private readonly string _databasePath;
    private readonly string _stateRoot;
    private readonly Uri _platformBaseUri;
    private readonly HttpClient _http;

    public UpdateProvider()
    {
        _dataDir = Environment.GetEnvironmentVariable("BKE_AGENT_DATA_DIR")
            ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "share", "bke_licensing_agent");
        _databasePath = Path.Combine(_dataDir, "agent.db");
        _stateRoot = Path.Combine(_dataDir, "updates");

        var baseUrl = (Environment.GetEnvironmentVariable("BKE_PLATFORM_BASE_URL") ?? "https://jl-bke.com").TrimEnd('/');
        if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var baseUri))
        {
            throw new InvalidOperationException("BKE_PLATFORM_BASE_URL is invalid");
        }
        var allowLocalHttp =
            Environment.GetEnvironmentVariable("BKE_AGENT_VNEXT_ALLOW_INSECURE_LOCAL") == "1" &&
            baseUri.IsLoopback &&
            string.Equals(baseUri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase);
        if (!string.Equals(baseUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) && !allowLocalHttp)
        {
            throw new InvalidOperationException("Update authority must use HTTPS");
        }
        _platformBaseUri = baseUri;
        _http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false })
        {
            Timeout = TimeSpan.FromSeconds(20),
        };
    }

    public async Task<UpdateCheckResponse> CheckAsync(UpdateCheckRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!string.IsNullOrEmpty(request.RequestedVersion))
        {
            return Failed(
                "InvalidRequest",
                "requested_version is not supported by the Licensing Agent provider yet",
                false);
        }

        var discovery = await RefreshAsync(request.ProductId, request.CurrentVersion, cancellationToken);
        return FromDiscovery(discovery);
    }

    public Task<OpenUpdateCenterResponse> OpenCenterAsync(
        OpenUpdateCenterRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(new OpenUpdateCenterResponse(
            "agent_unavailable",
            "gen2_privileged_update_not_migrated",
            request.CorrelationId));
    }

    private async Task<Dictionary<string, object?>> RefreshAsync(
        string productId,
        string version,
        CancellationToken cancellationToken)
    {
        var attempted = DateTimeOffset.UtcNow;
        var (_, statusPath) = Paths(productId, version);
        var product = LoadProduct(productId, version);
        if (product is null)
        {
            return FailedRefresh(statusPath, productId, version, attempted, "invalid_product_context");
        }

        // The frozen Python UpdateDiscoveryRequest accepts stable/lts while shipping manifests
        // accept stable/beta/alpha. Because validated manifests cannot produce lts, beta/alpha
        // currently fail before transport in the Python oracle and must remain fail-closed here.
        if (!string.Equals(product.UpdateChannel, "stable", StringComparison.Ordinal))
        {
            return FailedRefresh(statusPath, productId, version, attempted, "unknown");
        }

        var lease = LoadUpdateLease(productId, version);
        if (lease is null)
        {
            return FailedRefresh(statusPath, productId, version, attempted, "policy_denied");
        }

        try
        {
            var response = await CheckRemoteAsync(product, lease, cancellationToken);
            if (response.Status == "up_to_date")
            {
                var result = new Dictionary<string, object?>(StringComparer.Ordinal)
                {
                    ["state"] = "up_to_date",
                    ["product_id"] = productId,
                    ["current_version"] = version,
                    ["verified_at"] = Iso(attempted),
                    ["last_attempt_at"] = Iso(attempted),
                };
                WriteJson(statusPath, result);
                return result;
            }

            if (response.Policy is null || string.IsNullOrWhiteSpace(response.DownloadUrl))
            {
                return FailedRefresh(statusPath, productId, version, attempted, "verification_failure");
            }

            var (policyPath, _) = Paths(productId, version);
            var policy = response.Policy.Value;
            var cached = ReadCachedPolicy(policyPath);
            var incomingRevision = RequiredInt(policy, "revision");
            int? lastRevision;
            if (cached is not null && cached.Value.Revision == incomingRevision)
            {
                if (!JsonEquivalent(policy, cached.Value.Policy))
                {
                    return FailedRefresh(statusPath, productId, version, attempted, "verification_failure");
                }
                lastRevision = incomingRevision - 1;
            }
            else
            {
                lastRevision = HighestRevision(product);
            }

            var verified = VerifyPolicy(policy, product, lastRevision);
            if (!string.Equals(verified.ContentType, UpdatePackageContentType, StringComparison.Ordinal))
            {
                return FailedRefresh(statusPath, productId, version, attempted, "verification_failure");
            }
            if (!OffersUpdate(version, verified.LatestVersion, verified.MinimumSupportedVersion))
            {
                return FailedRefresh(statusPath, productId, version, attempted, "verification_failure");
            }

            CacheVerifiedPolicy(policyPath, policy, attempted, product, verified.Revision);
            var document = new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["state"] = "update_available",
                ["product_id"] = productId,
                ["current_version"] = version,
                ["latest_version"] = verified.LatestVersion,
                ["release_id"] = verified.ReleaseId,
                ["revision"] = verified.Revision,
                ["verified_at"] = Iso(attempted),
                ["last_attempt_at"] = Iso(attempted),
            };
            WriteJson(statusPath, document);
            return document;
        }
        catch (UpdateBoundaryException exception)
        {
            return FailedRefresh(statusPath, productId, version, attempted, exception.InternalError);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return FailedRefresh(statusPath, productId, version, attempted, "unknown");
        }
    }

    private async Task<RemoteUpdateResponse> CheckRemoteAsync(
        ProductContext product,
        LeaseEnvelope lease,
        CancellationToken cancellationToken)
    {
        var payload = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["lease"] = new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["payload"] = lease.Payload,
                ["signature"] = lease.Signature,
                ["key_id"] = lease.KeyId,
                ["algorithm"] = lease.Algorithm,
            },
            ["product_id"] = product.ProductId,
            ["current_version"] = product.Version,
            ["platform"] = product.Platform,
            ["architecture"] = product.Architecture,
            ["channel"] = product.UpdateChannel,
        };

        var requestId = Guid.NewGuid().ToString();
        for (var attempt = 0; attempt < 3; attempt++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(_platformBaseUri, "/api/agent/updates/check"));
            request.Headers.Accept.ParseAdd("application/json");
            request.Headers.UserAgent.ParseAdd("bke-licensing-agent");
            request.Headers.Add("X-Request-ID", requestId);
            request.Headers.Add("x-bke-licensing-version", ProtocolVersion);
            request.Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

            HttpResponseMessage response;
            try
            {
                response = await _http.SendAsync(request, cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (TaskCanceledException exception)
            {
                if (attempt < 2)
                {
                    await BackoffAsync(attempt, cancellationToken);
                    continue;
                }
                throw new UpdateBoundaryException("transport_failure", exception);
            }
            catch (HttpRequestException exception) when (exception.InnerException is AuthenticationException)
            {
                throw new UpdateBoundaryException("verification_failure", exception);
            }
            catch (HttpRequestException exception)
            {
                if (attempt < 2)
                {
                    await BackoffAsync(attempt, cancellationToken);
                    continue;
                }
                throw new UpdateBoundaryException("transport_failure", exception);
            }

            using (response)
            {
                if (IsRetryableStatus(response.StatusCode) && attempt < 2)
                {
                    await BackoffAsync(attempt, cancellationToken);
                    continue;
                }

                var raw = await response.Content.ReadAsStringAsync(cancellationToken);
                if (!response.IsSuccessStatusCode)
                {
                    var remoteError = TryRemoteError(raw);
                    if (remoteError is "RELEASE_NOT_VERIFIED" or "INVALID_ARTIFACT_CONTRACT")
                    {
                        throw new UpdateBoundaryException("verification_failure");
                    }
                    if (remoteError is "INVALID_REQUEST" or "INVALID_CONTENT_TYPE")
                    {
                        throw new UpdateBoundaryException("protocol_failure");
                    }
                    if (response.StatusCode == HttpStatusCode.Forbidden)
                    {
                        throw new UpdateBoundaryException("policy_denied");
                    }
                    if (response.StatusCode == HttpStatusCode.TooManyRequests || (int)response.StatusCode >= 500)
                    {
                        throw new UpdateBoundaryException("provider_unavailable");
                    }
                    throw new UpdateBoundaryException("protocol_failure");
                }

                JsonDocument document;
                try
                {
                    document = JsonDocument.Parse(raw);
                }
                catch (JsonException exception)
                {
                    throw new UpdateBoundaryException("malformed_response", exception);
                }

                using (document)
                {
                    var root = document.RootElement;
                    if (root.ValueKind != JsonValueKind.Object)
                    {
                        throw new UpdateBoundaryException("malformed_response");
                    }
                    var allowed = new HashSet<string>(StringComparer.Ordinal) { "status", "policy", "download_url" };
                    if (root.EnumerateObject().Any(property => !allowed.Contains(property.Name)))
                    {
                        throw new UpdateBoundaryException("malformed_response");
                    }

                    var status = ResponseString(root, "status");
                    if (status == "up_to_date")
                    {
                        if ((root.TryGetProperty("policy", out var noPolicy) && noPolicy.ValueKind != JsonValueKind.Null) ||
                            (root.TryGetProperty("download_url", out var noUrl) && noUrl.ValueKind != JsonValueKind.Null))
                        {
                            throw new UpdateBoundaryException("malformed_response");
                        }
                        return new RemoteUpdateResponse(status, null, null);
                    }
                    if (status != "update_available" ||
                        !root.TryGetProperty("policy", out var policy) || policy.ValueKind != JsonValueKind.Object ||
                        !root.TryGetProperty("download_url", out var downloadUrlElement) ||
                        downloadUrlElement.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(downloadUrlElement.GetString()))
                    {
                        throw new UpdateBoundaryException("malformed_response");
                    }

                    if (PolicyString(policy, "product_id") != product.ProductId ||
                        PolicyString(policy, "current_version") != product.Version ||
                        PolicyString(policy, "platform") != product.Platform ||
                        PolicyString(policy, "architecture") != product.Architecture ||
                        PolicyString(policy, "channel") != product.UpdateChannel)
                    {
                        throw new UpdateBoundaryException("verification_failure");
                    }
                    return new RemoteUpdateResponse(status, policy.Clone(), downloadUrlElement.GetString());
                }
            }
        }

        throw new UpdateBoundaryException("unknown");
    }

    private ProductContext? LoadProduct(string productId, string version)
    {
        if (!File.Exists(_databasePath))
        {
            return null;
        }
        try
        {
            using var connection = OpenDatabase(SqliteOpenMode.ReadOnly);
            using var command = connection.CreateCommand();
            command.CommandText = """
                SELECT product_id, version, manifest_path, product_root, entry_point_path
                FROM discovered_products
                WHERE product_id=$product_id AND version=$version
                ORDER BY discovered_at DESC
                LIMIT 1
                """;
            command.Parameters.AddWithValue("$product_id", productId);
            command.Parameters.AddWithValue("$version", version);
            using var reader = command.ExecuteReader();
            if (!reader.Read())
            {
                return null;
            }

            var manifestPath = reader.GetString(2);
            var productRoot = reader.GetString(3);
            var entryPointPath = reader.GetString(4);
            using var document = JsonDocument.Parse(File.ReadAllText(manifestPath));
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !root.TryGetProperty("schemaVersion", out var schema) || schema.ValueKind != JsonValueKind.Number || schema.GetInt32() != 1)
            {
                return null;
            }
            var allowed = new HashSet<string>(StringComparer.Ordinal)
            {
                "schemaVersion", "productId", "displayName", "publisher", "version", "entryPoint", "icon",
                "updateChannel", "minimumAgentVersion", "platform", "architecture"
            };
            if (root.EnumerateObject().Any(property => !allowed.Contains(property.Name)))
            {
                return null;
            }

            var manifestProductId = ManifestString(root, "productId");
            var displayName = ManifestString(root, "displayName");
            var manifestVersion = ManifestString(root, "version");
            var entryPoint = ManifestString(root, "entryPoint");
            var platform = ManifestString(root, "platform");
            var architecture = ManifestString(root, "architecture");
            var channel = ManifestString(root, "updateChannel");
            var minimumAgentVersion = ManifestString(root, "minimumAgentVersion");
            if (manifestProductId != productId || manifestVersion != version || displayName.Length == 0 ||
                !ProductIdPattern.IsMatch(manifestProductId) ||
                !ManifestVersionPattern.IsMatch(manifestVersion) ||
                !ManifestVersionPattern.IsMatch(minimumAgentVersion) ||
                platform is not ("windows" or "macos" or "linux") ||
                architecture is not ("x86" or "x64" or "arm64") ||
                channel is not ("stable" or "beta" or "alpha") ||
                !ValidRelativePath(entryPoint))
            {
                return null;
            }
            if (root.TryGetProperty("publisher", out var publisher) &&
                (publisher.ValueKind != JsonValueKind.String || string.IsNullOrEmpty(publisher.GetString())))
            {
                return null;
            }
            if (root.TryGetProperty("icon", out var icon) &&
                (icon.ValueKind != JsonValueKind.String || string.IsNullOrEmpty(icon.GetString()) || !ValidRelativePath(icon.GetString()!)))
            {
                return null;
            }

            var expectedEntry = Path.GetFullPath(Path.Combine(productRoot, entryPoint));
            var recordedEntry = Path.GetFullPath(entryPointPath);
            var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
            if (!string.Equals(expectedEntry, recordedEntry, comparison))
            {
                return null;
            }
            return new ProductContext(productId, version, platform, architecture, channel);
        }
        catch
        {
            return null;
        }
    }

    private LeaseEnvelope? LoadUpdateLease(string productId, string version)
    {
        if (!File.Exists(_databasePath))
        {
            return null;
        }
        using var connection = OpenDatabase(SqliteOpenMode.ReadOnly);
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT signed_payload, signed_signature, key_id, signed_algorithm
            FROM verified_licenses
            WHERE product_id=$product_id AND product_version=$version AND status='verified'
              AND signed_payload IS NOT NULL AND signed_signature IS NOT NULL AND signed_algorithm IS NOT NULL
            ORDER BY updated_at DESC
            LIMIT 1
            """;
        command.Parameters.AddWithValue("$product_id", productId);
        command.Parameters.AddWithValue("$version", version);
        using var reader = command.ExecuteReader();
        return reader.Read()
            ? new LeaseEnvelope(reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3))
            : null;
    }

    private VerifiedPolicy VerifyPolicy(JsonElement policy, ProductContext product, int? lastRevision)
    {
        var keys = policy.EnumerateObject().Select(property => property.Name).ToHashSet(StringComparer.Ordinal);
        if (!keys.SetEquals(PolicyKeys) ||
            PolicyString(policy, "schema") != "bke.update-policy.v1" ||
            PolicyString(policy, "algorithm") != "Ed25519" ||
            PolicyString(policy, "product_id") != product.ProductId ||
            PolicyString(policy, "current_version") != product.Version ||
            PolicyString(policy, "platform") != product.Platform ||
            PolicyString(policy, "architecture") != product.Architecture ||
            PolicyString(policy, "channel") != product.UpdateChannel)
        {
            throw new UpdateBoundaryException("verification_failure");
        }

        var currentVersion = PolicyString(policy, "current_version");
        var latestVersion = PolicyString(policy, "latest_version");
        var minimumVersion = PolicyString(policy, "minimum_supported_version");
        if (!TryCoreVersion(currentVersion, out _) || !TryCoreVersion(latestVersion, out var latest) ||
            !TryCoreVersion(minimumVersion, out var minimum) || CompareVersion(minimum, latest) > 0)
        {
            throw new UpdateBoundaryException("verification_failure");
        }
        var artifactHash = PolicyString(policy, "artifact_sha256");
        if (!ArtifactHashPattern.IsMatch(artifactHash))
        {
            throw new UpdateBoundaryException("verification_failure");
        }
        var artifactSize = PolicyLong(policy, "artifact_size");
        if (artifactSize < 0)
        {
            throw new UpdateBoundaryException("verification_failure");
        }
        var revision = RequiredInt(policy, "revision");
        if (revision < 0 || (lastRevision is not null && revision <= lastRevision.Value))
        {
            throw new UpdateBoundaryException("verification_failure");
        }

        var publicKey = LoadTrustedKey(PolicyString(policy, "signing_key_id"));
        if (publicKey is null)
        {
            throw new UpdateBoundaryException("verification_failure");
        }
        byte[] signature;
        try
        {
            signature = Convert.FromBase64String(PolicyString(policy, "signature"));
        }
        catch (FormatException exception)
        {
            throw new UpdateBoundaryException("verification_failure", exception);
        }
        var canonical = CanonicalPolicyBytes(policy);
        var verifier = new Ed25519Signer();
        verifier.Init(false, publicKey);
        verifier.BlockUpdate(canonical, 0, canonical.Length);
        if (!verifier.VerifySignature(signature))
        {
            throw new UpdateBoundaryException("verification_failure");
        }

        return new VerifiedPolicy(
            latestVersion,
            minimumVersion,
            PolicyString(policy, "release_id"),
            PolicyString(policy, "content_type"),
            revision);
    }

    private Ed25519PublicKeyParameters? LoadTrustedKey(string keyId)
    {
        var directory = Path.Combine(_dataDir, "trusted-keys");
        if (!Directory.Exists(directory))
        {
            return null;
        }
        var path = Directory.EnumerateFiles(directory, "*.pem", SearchOption.TopDirectoryOnly)
            .OrderBy(candidate => candidate, StringComparer.Ordinal)
            .FirstOrDefault(candidate => string.Equals(Path.GetFileNameWithoutExtension(candidate), keyId, StringComparison.Ordinal));
        if (path is null)
        {
            return null;
        }
        try
        {
            using var reader = new StringReader(File.ReadAllText(path));
            return new PemReader(reader).ReadObject() as Ed25519PublicKeyParameters;
        }
        catch
        {
            return null;
        }
    }

    private static byte[] CanonicalPolicyBytes(JsonElement policy)
    {
        var unsigned = policy.EnumerateObject()
            .Where(property => property.Name != "signature")
            .OrderBy(property => property.Name, StringComparer.Ordinal)
            .ToArray();
        var builder = new StringBuilder("{");
        for (var index = 0; index < unsigned.Length; index++)
        {
            if (index > 0) builder.Append(',');
            builder.Append(JsonString(unsigned[index].Name)).Append(':').Append(CanonicalJson(unsigned[index].Value));
        }
        return Encoding.UTF8.GetBytes(builder.Append('}').ToString());
    }

    private static string CanonicalJson(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.Object => "{" + string.Join(",", value.EnumerateObject()
            .OrderBy(property => property.Name, StringComparer.Ordinal)
            .Select(property => JsonString(property.Name) + ":" + CanonicalJson(property.Value))) + "}",
        JsonValueKind.Array => "[" + string.Join(",", value.EnumerateArray().Select(CanonicalJson)) + "]",
        JsonValueKind.String => JsonString(value.GetString()!),
        JsonValueKind.Number => value.GetRawText(),
        JsonValueKind.True => "true",
        JsonValueKind.False => "false",
        JsonValueKind.Null => "null",
        _ => throw new InvalidDataException("Unsupported JSON token"),
    };

    private static string JsonString(string value) => JsonSerializer.Serialize(value, CanonicalJsonOptions);

    private CachedPolicy? ReadCachedPolicy(string path)
    {
        if (!File.Exists(path)) return null;
        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(path));
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !root.EnumerateObject().Select(property => property.Name).ToHashSet(StringComparer.Ordinal)
                    .SetEquals(new[] { "policy", "verified_at" }) ||
                !root.TryGetProperty("policy", out var policy) || policy.ValueKind != JsonValueKind.Object)
            {
                throw new UpdateBoundaryException("verification_failure");
            }
            return new CachedPolicy(policy.Clone(), RequiredInt(policy, "revision"));
        }
        catch (UpdateBoundaryException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw new UpdateBoundaryException("verification_failure", exception);
        }
    }

    private void CacheVerifiedPolicy(
        string path,
        JsonElement policy,
        DateTimeOffset verifiedAt,
        ProductContext product,
        int revision)
    {
        AcceptRevision(product, revision);
        var raw = "{\"policy\":" + policy.GetRawText() + ",\"verified_at\":" + JsonSerializer.Serialize(Iso(verifiedAt)) + "}";
        WriteRaw(path, raw);
    }

    private int? HighestRevision(ProductContext product)
    {
        var path = RevisionPath(product);
        if (!File.Exists(path)) return null;
        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(path));
            if (document.RootElement.ValueKind != JsonValueKind.Object ||
                !document.RootElement.TryGetProperty("revision", out var revision))
            {
                throw new UpdateBoundaryException("verification_failure");
            }
            if (revision.ValueKind != JsonValueKind.Number || !revision.TryGetInt32(out var value))
            {
                return null;
            }
            return value;
        }
        catch (UpdateBoundaryException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw new UpdateBoundaryException("verification_failure", exception);
        }
    }

    private void AcceptRevision(ProductContext product, int revision)
    {
        var current = HighestRevision(product);
        if (current is not null && revision < current.Value)
        {
            throw new UpdateBoundaryException("verification_failure");
        }
        WriteJson(RevisionPath(product), new Dictionary<string, object?> { ["revision"] = revision });
    }

    private string RevisionPath(ProductContext product)
    {
        var scope = Safe($"{product.ProductId}-{product.Platform}-{product.Architecture}-{product.UpdateChannel}", 180);
        return Path.Combine(_stateRoot, "core", "policy-revisions", $"{scope}.json");
    }

    private (string Policy, string Status) Paths(string productId, string version)
    {
        var root = Path.Combine(_stateRoot, Safe(productId, 128), Safe(version, 128));
        return (Path.Combine(root, "policy.json"), Path.Combine(root, "status.json"));
    }

    private Dictionary<string, object?> FailedRefresh(
        string statusPath,
        string productId,
        string version,
        DateTimeOffset attempted,
        string error)
    {
        var document = ReadObject(statusPath) ?? new Dictionary<string, object?>(StringComparer.Ordinal);
        document["state"] = "refresh_failed";
        document["product_id"] = productId;
        document["current_version"] = version;
        document["last_attempt_at"] = Iso(attempted);
        document["error"] = error;
        WriteJson(statusPath, document);
        return document;
    }

    private static UpdateCheckResponse FromDiscovery(IReadOnlyDictionary<string, object?> document)
    {
        var state = document.TryGetValue("state", out var stateValue) ? stateValue as string : null;
        if (state == "up_to_date") return Success("UpToDate", null);
        if (state is "update_available" or "stale_update")
        {
            var version = document.TryGetValue("latest_version", out var latest) ? latest as string : null;
            return string.IsNullOrWhiteSpace(version)
                ? Failed("MalformedResponse", "The provider produced an update without an available version.", false)
                : Success("UpdateAvailable", version);
        }
        if (state == "suppressed_update")
        {
            var version = document.TryGetValue("latest_version", out var latest) ? latest as string : null;
            return Success("Deferred", string.IsNullOrWhiteSpace(version) ? null : version);
        }
        if (state == "refresh_failed")
        {
            var error = document.TryGetValue("error", out var internalError) ? internalError as string : "unknown";
            return error switch
            {
                "invalid_product_context" => Failed("InvalidRequest", "The product or current version is not known to the local provider.", false),
                "policy_denied" => Failed("PolicyDenied", "The trusted provider did not authorize update discovery for this product context.", false),
                "provider_unavailable" => Failed("ProviderUnavailable", "The trusted update authority is temporarily unavailable.", true),
                "transport_failure" => Failed("TransportFailure", "The provider could not reach the trusted update authority.", true),
                "protocol_failure" => Failed("ProtocolFailure", "The provider and trusted update authority could not complete their protocol.", false),
                "malformed_response" => Failed("MalformedResponse", "The trusted update authority returned an invalid response.", false),
                "verification_failure" => Failed("VerificationFailure", "The provider could not verify the trusted update response.", false),
                _ => Failed("Unknown", "The update check failed for an unknown provider reason.", false),
            };
        }
        return Failed("Unknown", "The provider returned an unsupported update state.", false);
    }

    private static UpdateCheckResponse Success(string status, string? version) => new(
        LocalAgentContract.UpdateCapabilityId,
        LocalAgentContract.UpdateContractVersion,
        status,
        version,
        null);

    private static UpdateCheckResponse Failed(string code, string message, bool retryable) => new(
        LocalAgentContract.UpdateCapabilityId,
        LocalAgentContract.UpdateContractVersion,
        "Failed",
        null,
        new UpdateCapabilityError(code, message, retryable));

    private SqliteConnection OpenDatabase(SqliteOpenMode mode)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = _databasePath,
            Mode = mode,
            Cache = SqliteCacheMode.Private,
        }.ToString());
        connection.Open();
        return connection;
    }

    private static string ResponseString(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.String || string.IsNullOrEmpty(value.GetString()))
            throw new UpdateBoundaryException("malformed_response");
        return value.GetString()!;
    }

    private static string ManifestString(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.String || string.IsNullOrEmpty(value.GetString()))
            throw new InvalidDataException($"Invalid manifest field {name}");
        return value.GetString()!;
    }

    private static string PolicyString(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.String || value.GetString() is null)
            throw new UpdateBoundaryException("verification_failure");
        return value.GetString()!;
    }

    private static int RequiredInt(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.Number || !value.TryGetInt32(out var result))
            throw new UpdateBoundaryException("verification_failure");
        return result;
    }

    private static long PolicyLong(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.Number || !value.TryGetInt64(out var result))
            throw new UpdateBoundaryException("verification_failure");
        return result;
    }

    private static string? TryRemoteError(string raw)
    {
        try
        {
            using var document = JsonDocument.Parse(raw);
            return document.RootElement.ValueKind == JsonValueKind.Object &&
                document.RootElement.TryGetProperty("error", out var error) && error.ValueKind == JsonValueKind.String
                ? error.GetString()
                : null;
        }
        catch
        {
            return null;
        }
    }

    private static bool IsRetryableStatus(HttpStatusCode statusCode) =>
        statusCode is HttpStatusCode.RequestTimeout or HttpStatusCode.TooManyRequests ||
        (int)statusCode == 425 ||
        statusCode is HttpStatusCode.InternalServerError or HttpStatusCode.BadGateway or
        HttpStatusCode.ServiceUnavailable or HttpStatusCode.GatewayTimeout;

    private static Task BackoffAsync(int attempt, CancellationToken cancellationToken) =>
        Task.Delay(TimeSpan.FromMilliseconds(250 * (1 << attempt)), cancellationToken);

    private static bool ValidRelativePath(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.StartsWith('/') || value.StartsWith('\\') ||
            (value.Length >= 2 && value[1] == ':'))
        {
            return false;
        }
        return !value.Replace('\\', '/').Split('/').Contains("..", StringComparer.Ordinal);
    }

    private static bool TryCoreVersion(string value, out int[] parts)
    {
        parts = Array.Empty<int>();
        if (!CoreVersionPattern.IsMatch(value)) return false;
        try
        {
            var parsed = value.Split('.').Select(int.Parse).ToList();
            while (parsed.Count < 4) parsed.Add(0);
            parts = parsed.Take(4).ToArray();
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static int CompareVersion(IReadOnlyList<int> left, IReadOnlyList<int> right)
    {
        for (var index = 0; index < 4; index++)
        {
            var comparison = left[index].CompareTo(right[index]);
            if (comparison != 0) return comparison;
        }
        return 0;
    }

    private static bool OffersUpdate(string installed, string latest, string minimum)
    {
        if (!TryCoreVersion(installed, out var current) || !TryCoreVersion(latest, out var target) ||
            !TryCoreVersion(minimum, out var minimumVersion))
        {
            return false;
        }
        return CompareVersion(current, minimumVersion) < 0 || CompareVersion(current, target) < 0;
    }

    private static bool JsonEquivalent(JsonElement left, JsonElement right) =>
        string.Equals(CanonicalJson(left), CanonicalJson(right), StringComparison.Ordinal);

    private static string Safe(string value, int maximumLength)
    {
        var safe = SafePathPattern.Replace(value, "-");
        return safe.Length <= maximumLength ? safe : safe[..maximumLength];
    }

    private static string Iso(DateTimeOffset value) =>
        value.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'");

    private static Dictionary<string, object?>? ReadObject(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            using var document = JsonDocument.Parse(File.ReadAllText(path));
            if (document.RootElement.ValueKind != JsonValueKind.Object) return null;
            var result = new Dictionary<string, object?>(StringComparer.Ordinal);
            foreach (var property in document.RootElement.EnumerateObject())
            {
                result[property.Name] = property.Value.ValueKind switch
                {
                    JsonValueKind.String => property.Value.GetString(),
                    JsonValueKind.Number when property.Value.TryGetInt64(out var number) => number,
                    JsonValueKind.True => true,
                    JsonValueKind.False => false,
                    JsonValueKind.Null => null,
                    _ => property.Value.Clone(),
                };
            }
            return result;
        }
        catch
        {
            return null;
        }
    }

    private static void WriteJson(string path, object value) => WriteRaw(path, JsonSerializer.Serialize(value));

    private static void WriteRaw(string path, string raw)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temporary = path + ".tmp";
        File.WriteAllText(temporary, raw, new UTF8Encoding(false));
        if (!OperatingSystem.IsWindows())
        {
            try
            {
                File.SetUnixFileMode(temporary, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
            catch (PlatformNotSupportedException)
            {
            }
        }
        File.Move(temporary, path, true);
    }

    private sealed record ProductContext(
        string ProductId,
        string Version,
        string Platform,
        string Architecture,
        string UpdateChannel);
    private sealed record LeaseEnvelope(string Payload, string Signature, string KeyId, string Algorithm);
    private sealed record RemoteUpdateResponse(string Status, JsonElement? Policy, string? DownloadUrl);
    private sealed record VerifiedPolicy(
        string LatestVersion,
        string MinimumSupportedVersion,
        string ReleaseId,
        string ContentType,
        int Revision);
    private readonly record struct CachedPolicy(JsonElement Policy, int Revision);

    private sealed class UpdateBoundaryException : Exception
    {
        internal UpdateBoundaryException(string internalError, Exception? innerException = null)
            : base(internalError, innerException)
        {
            InternalError = internalError;
        }

        internal string InternalError { get; }
    }
}
