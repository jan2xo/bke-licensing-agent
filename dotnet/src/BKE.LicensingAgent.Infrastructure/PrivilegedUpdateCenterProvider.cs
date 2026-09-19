using System.Diagnostics;
using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.RegularExpressions;
using BKE.LicensingAgent.Contracts;
using Microsoft.Data.Sqlite;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.OpenSsl;

namespace BKE.LicensingAgent.Infrastructure;

public sealed class PrivilegedUpdateCenterProvider : IStandaloneSoftwareProvisioner
{
    private const string ProtocolVersion = "bke.licensing.v3";
    private const string UpdatePackageContentType = "application/vnd.bke.update-package+zip";
    private const long MaximumStandalonePackageBytes = 4L * 1024 * 1024 * 1024;
    private const int MaximumReleaseMetadataBytes = 64 * 1024;
    private static readonly Uri GitHubApiBaseUri = new("https://api.github.com/", UriKind.Absolute);
    private static readonly HashSet<string> ApprovedGitHubAssetHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "github.com",
        "release-assets.githubusercontent.com",
        "objects.githubusercontent.com",
        "github-releases.githubusercontent.com",
    };
    private static readonly Regex SafePathPattern = new("[^A-Za-z0-9_.-]", RegexOptions.CultureInvariant);
    private static readonly Regex CoreVersionPattern = new("^(?:0|[1-9][0-9]*)(?:\\.[0-9]+){0,3}$", RegexOptions.CultureInvariant);
    private static readonly Regex HashPattern = new("^[0-9a-fA-F]{64}$", RegexOptions.CultureInvariant);
    private static readonly Regex ProductIdPattern = new("^[a-z0-9-]+$", RegexOptions.CultureInvariant);
    private static readonly Regex ManifestVersionPattern = new("^\\d+\\.\\d+\\.\\d+(?:[-+].*)?$", RegexOptions.CultureInvariant);
    private static readonly HashSet<string> PolicyKeys = new(StringComparer.Ordinal)
    {
        "schema", "product_id", "current_version", "latest_version", "minimum_supported_version",
        "channel", "platform", "architecture", "release_id", "artifact_id", "artifact_sha256",
        "artifact_size", "content_type", "published_at", "issued_at", "revision", "signing_key_id",
        "algorithm", "signature",
    };
    private static readonly HashSet<string> TargetPolicyKeys = new(StringComparer.Ordinal)
    {
        "schema", "policy_id", "revision", "product_id", "platform", "architecture",
        "install_root", "entry_point", "signing_key_id", "algorithm", "signature",
    };
    private static readonly HashSet<string> PrivilegedConfigKeys = new(StringComparer.Ordinal)
    {
        "runtime_root", "helper_executable", "signing_key_id", "signing_private_key",
        "target_keys_dir", "target_policies_dir", "approved_install_roots", "expected_channel",
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
    private readonly bool _certificationMode;

    public PrivilegedUpdateCenterProvider()
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
        _certificationMode =
            Environment.GetEnvironmentVariable("BKE_AGENT_VNEXT_ALLOW_INSECURE_LOCAL") == "1" &&
            baseUri.IsLoopback;
        if (!string.Equals(baseUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) &&
            !(_certificationMode && string.Equals(baseUri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException("Update authority must use HTTPS");
        }
        _platformBaseUri = baseUri;
        _http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false })
        {
            Timeout = TimeSpan.FromSeconds(30),
        };
    }

    public async Task<StandaloneProvisioningResult> ProvisionAsync(
        StandaloneProvisionAuthorization authorization,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!OperatingSystem.IsWindows())
        {
            return new StandaloneProvisioningResult(
                "PRIVILEGED_HANDOFF_FAILED",
                "unsupported_platform",
                false);
        }

        var identity = MachineIdentityProvider.Calculate();
        var platform = MachineIdentityProvider.ProtocolPlatform(identity.Platform);
        var protocolArchitecture = MachineIdentityProvider.ProtocolArchitecture(identity.Architecture);
        if (platform != "windows")
        {
            return new StandaloneProvisioningResult(
                "PRIVILEGED_HANDOFF_FAILED",
                "unsupported_platform",
                false);
        }

        PrivilegedConfig config;
        TargetPolicy target;
        try
        {
            config = LoadPrivilegedConfig();
            target = ResolveTargetPolicyForProvision(
                authorization.ProductId,
                platform,
                protocolArchitecture,
                config);

            if (Directory.Exists(target.InstallRoot) || File.Exists(target.InstallRoot))
            {
                return new StandaloneProvisioningResult(
                    "TARGET_ALREADY_EXISTS",
                    "target_already_exists",
                    false);
            }
        }
        catch
        {
            return new StandaloneProvisioningResult(
                "TARGET_POLICY_UNAVAILABLE",
                "target_policy_unavailable",
                false);
        }

        GitHubReleasePackage package;
        try
        {
            package = await ResolveGitHubReleasePackageAsync(
                authorization,
                protocolArchitecture,
                target,
                cancellationToken);
        }
        catch (GitHubReleasePackageException exception)
        {
            return new StandaloneProvisioningResult(
                exception.Code,
                exception.Reason,
                exception.Retryable);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return new StandaloneProvisioningResult(
                "RELEASE_METADATA_INVALID",
                "release_metadata_invalid",
                false);
        }

        string artifact;
        try
        {
            var downloadRoot = Path.Combine(
                config.RuntimeRoot,
                "downloads",
                "provision");
            var destination = Path.Combine(
                downloadRoot,
                Safe($"{authorization.ProductId}-{authorization.Version}-{package.FileName}", 220));
            artifact = await AcquireGitHubAssetAsync(
                package.DownloadUrl,
                destination,
                package.Size,
                package.Sha256,
                cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return new StandaloneProvisioningResult(
                "RELEASE_DOWNLOAD_FAILED",
                "release_download_failed",
                true);
        }

        try
        {
            var transactionId = Safe(
                $"{authorization.ProductId}-{authorization.Version}-{Guid.NewGuid():N}",
                180);
            var prepared = PreparePrivilegedProvisionInvocation(
                authorization,
                package,
                target,
                config,
                artifact,
                transactionId);
            Launch(prepared.Command);
            WriteTransaction(
                config.RuntimeRoot,
                transactionId,
                "PROVISION_STAGED",
                config.HelperExecutable);

            return new StandaloneProvisioningResult(
                "STARTED",
                "provision_started",
                false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return new StandaloneProvisioningResult(
                "PRIVILEGED_HANDOFF_FAILED",
                "privileged_handoff_failed",
                true);
        }
    }

    public async Task<OpenUpdateCenterResponse> OpenAsync(
        OpenUpdateCenterRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var status = UnsuppressedStatus(request.ProductId, request.Version);
        var state = status.TryGetValue("state", out var stateValue) ? stateValue as string : "never_checked";
        if (state is not ("update_available" or "stale_update"))
        {
            return new OpenUpdateCenterResponse("no_update", state ?? "never_checked", request.CorrelationId);
        }

        try
        {
            var product = LoadProduct(request.ProductId, request.Version)
                ?? throw new InvalidDataException("product unavailable");
            var lease = LoadUpdateLease(request.ProductId, request.Version)
                ?? throw new InvalidDataException("entitlement unavailable");
            if (!string.Equals(product.UpdateChannel, "stable", StringComparison.Ordinal))
            {
                throw new InvalidDataException("unsupported update channel");
            }

            var remote = await CheckRemoteAsync(product, lease, cancellationToken);
            if (remote.Status != "update_available" || remote.Policy is null || string.IsNullOrWhiteSpace(remote.DownloadUrl))
            {
                throw new InvalidDataException("authority no longer offers update");
            }

            var verified = VerifyPolicy(remote.Policy.Value, product, HighestRevision(product));
            if (!string.Equals(verified.ContentType, UpdatePackageContentType, StringComparison.Ordinal) ||
                !OffersUpdate(product.Version, verified.LatestVersion, verified.MinimumSupportedVersion))
            {
                throw new InvalidDataException("signed policy no longer authorizes update");
            }

            var config = LoadPrivilegedConfig();
            if (!string.Equals(config.ExpectedChannel, product.UpdateChannel, StringComparison.Ordinal))
            {
                throw new InvalidDataException("privileged runtime channel mismatch");
            }
            var target = ResolveTargetPolicy(product, config);
            var downloadPath = Path.Combine(config.RuntimeRoot, "downloads", $"{verified.ArtifactId}.bin");
            var artifact = await AcquireArtifactAsync(
                remote.DownloadUrl!, downloadPath, verified.ArtifactSize, verified.ArtifactSha256, cancellationToken);
            var transactionId = Safe($"{product.ProductId}-{verified.ReleaseId}-{verified.Revision}", 160);
            var prepared = PreparePrivilegedInvocation(product, remote.Policy.Value, verified, target, config, artifact, transactionId);
            Launch(prepared.Command);
            WriteTransaction(config.RuntimeRoot, transactionId, "STAGED", config.HelperExecutable);
            return new OpenUpdateCenterResponse("update_started", "staged", request.CorrelationId);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return new OpenUpdateCenterResponse(
                "update_failed",
                "privileged_update_verification_or_handoff_failed",
                request.CorrelationId);
        }
    }

    private Dictionary<string, object?> UnsuppressedStatus(string productId, string version)
    {
        var root = Path.Combine(_stateRoot, Safe(productId, 128), Safe(version, 128));
        var policyPath = Path.Combine(root, "policy.json");
        var statusPath = Path.Combine(root, "status.json");
        var document = ReadObject(statusPath);
        if (document is null)
        {
            return new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["state"] = "never_checked", ["product_id"] = productId, ["current_version"] = version,
            };
        }

        var result = new Dictionary<string, object?>(document, StringComparer.Ordinal);
        if (document.TryGetValue("latest_version", out var latestValue) && latestValue is string && File.Exists(policyPath))
        {
            var product = LoadProduct(productId, version);
            if (product is null)
            {
                return VerificationFailed(productId, version);
            }
            try
            {
                using var cachedDocument = JsonDocument.Parse(File.ReadAllText(policyPath));
                var rootElement = cachedDocument.RootElement;
                if (rootElement.ValueKind != JsonValueKind.Object ||
                    !rootElement.EnumerateObject().Select(item => item.Name).ToHashSet(StringComparer.Ordinal)
                        .SetEquals(new[] { "policy", "verified_at" }) ||
                    !rootElement.TryGetProperty("policy", out var policy) || policy.ValueKind != JsonValueKind.Object)
                {
                    throw new InvalidDataException("invalid cached policy");
                }
                var current = HighestRevision(product);
                var verified = VerifyPolicy(policy, product, current is null ? null : current.Value - 1);
                AcceptRevision(product, verified.Revision);
                if (!OffersUpdate(product.Version, verified.LatestVersion, verified.MinimumSupportedVersion))
                {
                    throw new InvalidDataException("cached policy no longer offers update");
                }
                var verifiedAt = ParseDateTime(document, "verified_at");
                result["state"] = DateTimeOffset.UtcNow - verifiedAt > TimeSpan.FromHours(24)
                    ? "stale_update"
                    : "update_available";
            }
            catch
            {
                return VerificationFailed(productId, version);
            }
        }
        return result;
    }

    private static Dictionary<string, object?> VerificationFailed(string productId, string version) =>
        new(StringComparer.Ordinal)
        {
            ["state"] = "verification_failed", ["product_id"] = productId, ["current_version"] = version,
        };

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
            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (IsRetryable(response.StatusCode) && attempt < 2)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(250 * (1 << attempt)), cancellationToken);
                continue;
            }
            if (!response.IsSuccessStatusCode)
            {
                throw new InvalidDataException("authority rejected update request");
            }
            var raw = await response.Content.ReadAsStringAsync(cancellationToken);
            using var document = JsonDocument.Parse(raw);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                root.EnumerateObject().Any(item => item.Name is not ("status" or "policy" or "download_url")))
            {
                throw new InvalidDataException("malformed authority response");
            }
            var status = RequiredString(root, "status");
            if (status == "up_to_date")
            {
                if ((root.TryGetProperty("policy", out var p) && p.ValueKind != JsonValueKind.Null) ||
                    (root.TryGetProperty("download_url", out var d) && d.ValueKind != JsonValueKind.Null))
                {
                    throw new InvalidDataException("malformed authority response");
                }
                return new RemoteUpdateResponse(status, null, null);
            }
            if (status != "update_available" ||
                !root.TryGetProperty("policy", out var policy) || policy.ValueKind != JsonValueKind.Object ||
                !root.TryGetProperty("download_url", out var url) || url.ValueKind != JsonValueKind.String ||
                string.IsNullOrWhiteSpace(url.GetString()))
            {
                throw new InvalidDataException("malformed authority response");
            }
            if (RequiredString(policy, "product_id") != product.ProductId ||
                RequiredString(policy, "current_version") != product.Version ||
                RequiredString(policy, "platform") != product.Platform ||
                RequiredString(policy, "architecture") != product.Architecture ||
                RequiredString(policy, "channel") != product.UpdateChannel)
            {
                throw new InvalidDataException("authority context mismatch");
            }
            return new RemoteUpdateResponse(status, policy.Clone(), url.GetString());
        }
        throw new InvalidDataException("update request did not complete");
    }

    private async Task<GitHubReleasePackage> ResolveGitHubReleasePackageAsync(
        StandaloneProvisionAuthorization authorization,
        string protocolArchitecture,
        TargetPolicy target,
        CancellationToken cancellationToken)
    {
        if (!Regex.IsMatch(
                authorization.Repository,
                "^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$",
                RegexOptions.CultureInvariant))
        {
            throw new GitHubReleasePackageException(
                "RELEASE_METADATA_INVALID",
                "release_metadata_invalid",
                false);
        }

        if (authorization.Tag != "v" + authorization.Version)
        {
            throw new GitHubReleasePackageException(
                "RELEASE_METADATA_INVALID",
                "release_metadata_invalid",
                false);
        }

        var segments = authorization.Repository.Split('/', 2);
        var releaseUri = new Uri(
            GitHubApiBaseUri,
            $"repos/{Uri.EscapeDataString(segments[0])}/{Uri.EscapeDataString(segments[1])}/releases/tags/{Uri.EscapeDataString(authorization.Tag)}");

        using var request = new HttpRequestMessage(HttpMethod.Get, releaseUri);
        request.Headers.Accept.ParseAdd("application/vnd.github+json");
        request.Headers.UserAgent.ParseAdd("bke-licensing-agent");
        request.Headers.TryAddWithoutValidation(
            "X-GitHub-Api-Version",
            "2022-11-28");

        using var response = await _http.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);

        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            throw new GitHubReleasePackageException(
                "RELEASE_PACKAGE_UNAVAILABLE",
                "release_package_unavailable",
                true);
        }
        if (!response.IsSuccessStatusCode)
        {
            throw new GitHubReleasePackageException(
                "RELEASE_DOWNLOAD_FAILED",
                "release_download_failed",
                IsRetryable(response.StatusCode));
        }

        await using var stream =
            await response.Content.ReadAsStreamAsync(cancellationToken);
        using var document = await JsonDocument.ParseAsync(
            stream,
            cancellationToken: cancellationToken);
        var root = document.RootElement;

        if (root.ValueKind != JsonValueKind.Object ||
            RequiredString(root, "tag_name") != authorization.Tag ||
            !root.TryGetProperty("draft", out var draft) ||
            draft.ValueKind is not (JsonValueKind.True or JsonValueKind.False) ||
            draft.GetBoolean() ||
            !root.TryGetProperty("prerelease", out var prerelease) ||
            prerelease.ValueKind is not (JsonValueKind.True or JsonValueKind.False) ||
            prerelease.GetBoolean() ||
            !root.TryGetProperty("assets", out var assets) ||
            assets.ValueKind != JsonValueKind.Array)
        {
            throw new GitHubReleasePackageException(
                "RELEASE_METADATA_INVALID",
                "release_metadata_invalid",
                false);
        }

        var metadataSuffix =
            $"-Windows-{protocolArchitecture}.update.json";
        var metadataAssets = assets.EnumerateArray()
            .Where(asset =>
                asset.ValueKind == JsonValueKind.Object &&
                asset.TryGetProperty("name", out var name) &&
                name.ValueKind == JsonValueKind.String &&
                name.GetString()!.EndsWith(
                    metadataSuffix,
                    StringComparison.OrdinalIgnoreCase))
            .Select(ParseGitHubAsset)
            .ToArray();

        if (metadataAssets.Length != 1 ||
            metadataAssets[0].Size <= 0 ||
            metadataAssets[0].Size > MaximumReleaseMetadataBytes)
        {
            throw new GitHubReleasePackageException(
                "RELEASE_PACKAGE_UNAVAILABLE",
                "release_package_unavailable",
                false);
        }

        var metadataBytes = await DownloadGitHubAssetBytesAsync(
            metadataAssets[0].DownloadUrl,
            MaximumReleaseMetadataBytes,
            cancellationToken);

        using var metadataDocument = JsonDocument.Parse(metadataBytes);
        var metadata = ParseStandalonePackageMetadata(
            metadataDocument.RootElement,
            authorization,
            protocolArchitecture,
            target);

        var packageAssets = assets.EnumerateArray()
            .Where(asset =>
                asset.ValueKind == JsonValueKind.Object &&
                asset.TryGetProperty("name", out var name) &&
                name.ValueKind == JsonValueKind.String &&
                string.Equals(
                    name.GetString(),
                    metadata.FileName,
                    StringComparison.Ordinal))
            .Select(ParseGitHubAsset)
            .ToArray();

        if (packageAssets.Length != 1 ||
            packageAssets[0].Size != metadata.Size)
        {
            throw new GitHubReleasePackageException(
                "RELEASE_PACKAGE_UNAVAILABLE",
                "release_package_unavailable",
                false);
        }

        return metadata with
        {
            DownloadUrl = packageAssets[0].DownloadUrl,
        };
    }

    private static GitHubReleaseAsset ParseGitHubAsset(JsonElement asset)
    {
        var name = RequiredString(asset, "name");
        var size = RequiredLong(asset, "size");
        var url = RequiredString(asset, "browser_download_url");

        if (string.IsNullOrWhiteSpace(name) ||
            name.Length > 512 ||
            size < 0 ||
            !Uri.TryCreate(url, UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttps ||
            !string.Equals(
                uri.Host,
                "github.com",
                StringComparison.OrdinalIgnoreCase))
        {
            throw new GitHubReleasePackageException(
                "RELEASE_METADATA_INVALID",
                "release_metadata_invalid",
                false);
        }

        return new GitHubReleaseAsset(name, size, url);
    }

    private static GitHubReleasePackage ParseStandalonePackageMetadata(
        JsonElement root,
        StandaloneProvisionAuthorization authorization,
        string protocolArchitecture,
        TargetPolicy target)
    {
        var expected = new HashSet<string>(StringComparer.Ordinal)
        {
            "schema",
            "productId",
            "version",
            "platform",
            "architecture",
            "entryPoint",
            "filename",
            "contentType",
            "bytes",
            "sha256",
        };

        if (root.ValueKind != JsonValueKind.Object ||
            !root.EnumerateObject()
                .Select(property => property.Name)
                .ToHashSet(StringComparer.Ordinal)
                .SetEquals(expected) ||
            RequiredString(root, "schema") != "bke.update-package.v1" ||
            RequiredString(root, "productId") != authorization.ProductId ||
            RequiredString(root, "version") != authorization.Version ||
            RequiredString(root, "platform") != "windows" ||
            RequiredString(root, "architecture") != protocolArchitecture ||
            RequiredString(root, "contentType") != UpdatePackageContentType)
        {
            throw new GitHubReleasePackageException(
                "RELEASE_METADATA_INVALID",
                "release_metadata_invalid",
                false);
        }

        var entryPoint = NormalizeWindowsRelative(
            RequiredString(root, "entryPoint"));
        if (!string.Equals(
                entryPoint,
                target.EntryPoint,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new GitHubReleasePackageException(
                "RELEASE_METADATA_INVALID",
                "release_metadata_invalid",
                false);
        }

        var fileName = RequiredString(root, "filename");
        if (fileName.Length > 512 ||
            Path.GetFileName(fileName) != fileName ||
            !fileName.EndsWith(
                ".update.zip",
                StringComparison.OrdinalIgnoreCase))
        {
            throw new GitHubReleasePackageException(
                "RELEASE_METADATA_INVALID",
                "release_metadata_invalid",
                false);
        }

        var size = RequiredLong(root, "bytes");
        var sha256 = RequiredString(root, "sha256").ToLowerInvariant();
        if (size <= 0 ||
            size > MaximumStandalonePackageBytes ||
            !HashPattern.IsMatch(sha256))
        {
            throw new GitHubReleasePackageException(
                "RELEASE_METADATA_INVALID",
                "release_metadata_invalid",
                false);
        }

        return new GitHubReleasePackage(
            fileName,
            size,
            sha256,
            entryPoint,
            string.Empty);
    }

    private async Task<byte[]> DownloadGitHubAssetBytesAsync(
        string url,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        using var response = await SendGitHubAssetAsync(
            new Uri(url, UriKind.Absolute),
            cancellationToken);

        if (response.Content.Headers.ContentLength is long announced &&
            announced > maximumBytes)
        {
            throw new GitHubReleasePackageException(
                "RELEASE_METADATA_INVALID",
                "release_metadata_invalid",
                false);
        }

        await using var input =
            await response.Content.ReadAsStreamAsync(cancellationToken);
        using var output = new MemoryStream();
        var buffer = new byte[16 * 1024];

        while (true)
        {
            var remaining = maximumBytes - (int)output.Length + 1;
            if (remaining <= 0)
            {
                throw new GitHubReleasePackageException(
                    "RELEASE_METADATA_INVALID",
                    "release_metadata_invalid",
                    false);
            }

            var read = await input.ReadAsync(
                buffer.AsMemory(
                    0,
                    Math.Min(buffer.Length, remaining)),
                cancellationToken);
            if (read == 0)
            {
                break;
            }

            output.Write(buffer, 0, read);
            if (output.Length > maximumBytes)
            {
                throw new GitHubReleasePackageException(
                    "RELEASE_METADATA_INVALID",
                    "release_metadata_invalid",
                    false);
            }
        }

        return output.ToArray();
    }

    private async Task<string> AcquireGitHubAssetAsync(
        string url,
        string destination,
        long expectedSize,
        string expectedSha256,
        CancellationToken cancellationToken)
    {
        if (expectedSize <= 0 ||
            expectedSize > MaximumStandalonePackageBytes ||
            !HashPattern.IsMatch(expectedSha256))
        {
            throw new InvalidDataException("invalid GitHub artifact bounds");
        }

        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        var temporary =
            destination + ".tmp-" + Guid.NewGuid().ToString("N");

        try
        {
            using var response = await SendGitHubAssetAsync(
                new Uri(url, UriKind.Absolute),
                cancellationToken);

            if (response.Content.Headers.ContentLength is long announced &&
                announced > expectedSize)
            {
                throw new InvalidDataException(
                    "GitHub artifact exceeds bounded size");
            }

            await using var input =
                await response.Content.ReadAsStreamAsync(cancellationToken);
            await using var output = File.Create(temporary);
            using var hash =
                IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buffer = new byte[1024 * 1024];
            long count = 0;

            while (true)
            {
                var remaining = expectedSize - count + 1;
                if (remaining <= 0)
                {
                    throw new InvalidDataException(
                        "GitHub artifact exceeds bounded size");
                }

                var read = await input.ReadAsync(
                    buffer.AsMemory(
                        0,
                        (int)Math.Min(buffer.Length, remaining)),
                    cancellationToken);
                if (read == 0)
                {
                    break;
                }

                count += read;
                if (count > expectedSize)
                {
                    throw new InvalidDataException(
                        "GitHub artifact exceeds bounded size");
                }

                hash.AppendData(buffer, 0, read);
                await output.WriteAsync(
                    buffer.AsMemory(0, read),
                    cancellationToken);
            }

            var digest =
                Convert.ToHexString(hash.GetHashAndReset())
                    .ToLowerInvariant();
            if (count != expectedSize ||
                !string.Equals(
                    digest,
                    expectedSha256,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "GitHub artifact integrity mismatch");
            }

            File.Move(temporary, destination, true);
            return destination;
        }
        catch
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }

            throw;
        }
    }

    private async Task<HttpResponseMessage> SendGitHubAssetAsync(
        Uri initialUri,
        CancellationToken cancellationToken)
    {
        var current = initialUri;

        for (var redirect = 0; redirect <= 5; redirect++)
        {
            ValidateGitHubAssetUri(current);

            using var request = new HttpRequestMessage(
                HttpMethod.Get,
                current);
            request.Headers.Accept.ParseAdd(
                "application/octet-stream");
            request.Headers.UserAgent.ParseAdd(
                "bke-licensing-agent");

            var response = await _http.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken);

            if ((int)response.StatusCode is >= 300 and <= 399)
            {
                var location = response.Headers.Location;
                response.Dispose();

                if (location is null)
                {
                    throw new HttpRequestException(
                        "GitHub release asset redirect is missing a location.");
                }

                current = location.IsAbsoluteUri
                    ? location
                    : new Uri(current, location);
                continue;
            }

            if (!response.IsSuccessStatusCode)
            {
                var status = response.StatusCode;
                response.Dispose();
                throw new HttpRequestException(
                    $"GitHub release asset returned {(int)status}.",
                    null,
                    status);
            }

            return response;
        }

        throw new HttpRequestException(
            "GitHub release asset exceeded the redirect limit.");
    }

    private static void ValidateGitHubAssetUri(Uri uri)
    {
        if (!uri.IsAbsoluteUri ||
            uri.Scheme != Uri.UriSchemeHttps ||
            !ApprovedGitHubAssetHosts.Contains(uri.Host) ||
            !string.IsNullOrEmpty(uri.Fragment))
        {
            throw new InvalidDataException(
                "GitHub release asset URI is not approved.");
        }
    }

    private async Task<string> AcquireArtifactAsync(
        string url,
        string destination,
        long expectedSize,
        string expectedSha256,
        CancellationToken cancellationToken)
    {
        if (expectedSize < 0 || !HashPattern.IsMatch(expectedSha256))
        {
            throw new InvalidDataException("invalid artifact bounds");
        }
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            throw new InvalidDataException("invalid artifact URL");
        }
        var approved = string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
            (_certificationMode && uri.IsLoopback && string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase));
        if (!approved)
        {
            throw new InvalidDataException("artifact transport requires HTTPS");
        }
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        var temporary = destination + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            response.EnsureSuccessStatusCode();
            if (response.Content.Headers.ContentLength is long announced && announced > expectedSize)
            {
                throw new InvalidDataException("artifact exceeds bounded size");
            }
            await using var input = await response.Content.ReadAsStreamAsync(cancellationToken);
            await using var output = File.Create(temporary);
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buffer = new byte[1024 * 1024];
            long count = 0;
            while (true)
            {
                var remaining = expectedSize - count + 1;
                if (remaining <= 0) throw new InvalidDataException("artifact exceeds bounded size");
                var read = await input.ReadAsync(buffer.AsMemory(0, (int)Math.Min(buffer.Length, remaining)), cancellationToken);
                if (read == 0) break;
                count += read;
                if (count > expectedSize) throw new InvalidDataException("artifact exceeds bounded size");
                hash.AppendData(buffer, 0, read);
                await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
            }
            if (count != expectedSize ||
                !string.Equals(Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant(), expectedSha256.ToLowerInvariant(), StringComparison.Ordinal))
            {
                throw new InvalidDataException("artifact integrity mismatch");
            }
            File.Move(temporary, destination, true);
            return destination;
        }
        catch
        {
            if (File.Exists(temporary)) File.Delete(temporary);
            throw;
        }
    }

    private PreparedInvocation PreparePrivilegedInvocation(
        ProductContext product,
        JsonElement updatePolicy,
        VerifiedPolicy verified,
        TargetPolicy target,
        PrivilegedConfig config,
        string artifact,
        string transactionId)
    {
        var runtimeRoot = Path.GetFullPath(config.RuntimeRoot);
        Directory.CreateDirectory(runtimeRoot);
        if (!File.Exists(config.HelperExecutable)) throw new InvalidDataException("privileged helper unavailable");
        if (!string.Equals(target.ProductId, product.ProductId, StringComparison.Ordinal) ||
            !string.Equals(target.Platform, product.Platform, StringComparison.Ordinal) ||
            !string.Equals(target.Architecture, product.Architecture, StringComparison.Ordinal))
        {
            throw new InvalidDataException("target authority mismatch");
        }

        var stageRoot = Path.Combine(runtimeRoot, "stage", transactionId);
        ExtractUpdatePackage(artifact, stageRoot, target.EntryPoint);
        var backupRoot = Path.Combine(runtimeRoot, "backup", transactionId);
        Directory.CreateDirectory(Path.GetDirectoryName(backupRoot)!);
        var transactionRoot = Path.Combine(runtimeRoot, "transactions");
        Directory.CreateDirectory(transactionRoot);

        var digitalKeys = LoadRawPublicKeys(Path.Combine(_dataDir, "trusted-keys"));
        if (digitalKeys.Count == 0 || config.TargetKeys.Count == 0)
        {
            throw new InvalidDataException("privileged trust unavailable");
        }
        var agentPublic = config.SigningPrivateKey.GeneratePublicKey().GetEncoded();
        var trust = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["schema"] = "bke.updater-trust.v1",
            ["agent_keys"] = new Dictionary<string, string> { [config.SigningKeyId] = Convert.ToBase64String(agentPublic) },
            ["digital_keys"] = digitalKeys.ToDictionary(pair => pair.Key, pair => Convert.ToBase64String(pair.Value.GetEncoded()), StringComparer.Ordinal),
            ["target_keys"] = config.TargetKeys.ToDictionary(pair => pair.Key, pair => Convert.ToBase64String(pair.Value.GetEncoded()), StringComparer.Ordinal),
            ["approved_install_roots"] = config.ApprovedInstallRoots,
            ["expected_channel"] = config.ExpectedChannel,
        };
        WriteJson(Path.Combine(runtimeRoot, "trust.json"), trust);

        var updatePath = Path.Combine(runtimeRoot, "update-policy.json");
        File.WriteAllText(updatePath, updatePolicy.GetRawText(), new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        var targetPath = Path.Combine(runtimeRoot, "target-policy.json");
        File.WriteAllText(targetPath, target.Raw.GetRawText(), new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        var runtimeArtifact = Path.Combine(runtimeRoot, "artifact.bin");
        File.Copy(artifact, runtimeArtifact, true);

        var now = DateTimeOffset.UtcNow;
        var unsigned = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["schema"] = "bke.privileged-update-request.v1",
            ["request_id"] = "agent-" + Guid.NewGuid().ToString("N"),
            ["product_id"] = product.ProductId,
            ["current_version"] = product.Version,
            ["target_version"] = verified.LatestVersion,
            ["platform"] = product.Platform,
            ["architecture"] = product.Architecture,
            ["install_root"] = target.InstallRoot,
            ["entry_point"] = target.EntryPoint,
            ["artifact_sha256"] = verified.ArtifactSha256,
            ["artifact_size"] = verified.ArtifactSize,
            ["update_policy_sha256"] = DocumentSha256(updatePolicy),
            ["target_policy_sha256"] = DocumentSha256(target.Raw),
            ["issued_at"] = Iso(now),
            ["expires_at"] = Iso(now.AddSeconds(120)),
            ["signing_key_id"] = config.SigningKeyId,
            ["algorithm"] = "Ed25519",
        };
        var canonical = CanonicalObjectBytes(unsigned);
        var signer = new Ed25519Signer();
        signer.Init(true, config.SigningPrivateKey);
        signer.BlockUpdate(canonical, 0, canonical.Length);
        var requestDocument = new Dictionary<string, object?>(unsigned, StringComparer.Ordinal)
        {
            ["signature"] = Convert.ToBase64String(signer.GenerateSignature()),
        };
        var requestPath = Path.Combine(runtimeRoot, "request.json");
        WriteJson(requestPath, requestDocument);

        var command = new List<string>
        {
            Path.GetFullPath(config.HelperExecutable),
            "--privileged-update",
            "--runtime-root", runtimeRoot,
            "--request", requestPath,
            "--update-policy", updatePath,
            "--target-policy", targetPath,
            "--artifact", runtimeArtifact,
            "--staged-root", stageRoot,
            "--backup-root", backupRoot,
            "--transaction-root", transactionRoot,
            "--transaction-id", transactionId,
        };
        return new PreparedInvocation(command);
    }

    private void ExtractUpdatePackage(string artifact, string stageRoot, string entryPoint)
    {
        if (Directory.Exists(stageRoot))
        {
            if ((File.GetAttributes(stageRoot) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("privileged stage root must not be a symlink");
            Directory.Delete(stageRoot, true);
        }
        Directory.CreateDirectory(stageRoot);
        var root = Path.GetFullPath(stageRoot) + Path.DirectorySeparatorChar;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        using var archive = ZipFile.OpenRead(artifact);
        foreach (var entry in archive.Entries)
        {
            var name = entry.FullName;
            if (string.IsNullOrEmpty(name) || name.Contains('\0') || name.Contains('\\') || name.StartsWith('/'))
                throw new InvalidDataException("unsafe updater package path");
            var trimmed = name.EndsWith('/') ? name[..^1] : name;
            if (string.IsNullOrEmpty(trimmed)) throw new InvalidDataException("unsafe updater package path");
            var parts = trimmed.Split('/');
            if (parts.Any(part => part is "" or "." or "..") || parts[0].Contains(':'))
                throw new InvalidDataException("unsafe updater package path");
            if (!seen.Add(string.Join('/', parts))) throw new InvalidDataException("duplicate updater package path");
            var unixType = (entry.ExternalAttributes >> 16) & 0xF000;
            if (unixType == 0xA000) throw new InvalidDataException("updater package symlinks are forbidden");
            if (unixType is not (0 or 0x8000 or 0x4000)) throw new InvalidDataException("unsupported updater package entry type");
            var destination = Path.GetFullPath(Path.Combine(stageRoot, Path.Combine(parts)));
            if (!destination.StartsWith(root, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                throw new InvalidDataException("unsafe updater package path");
            if (name.EndsWith('/'))
            {
                Directory.CreateDirectory(destination);
                continue;
            }
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            using var input = entry.Open();
            using var output = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            input.CopyTo(output);
        }
        var relative = entryPoint.Replace('\\', Path.DirectorySeparatorChar).Replace('/', Path.DirectorySeparatorChar);
        var executable = Path.GetFullPath(Path.Combine(stageRoot, relative));
        if (!executable.StartsWith(root, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal) || !File.Exists(executable))
            throw new InvalidDataException("updater package is missing signed entry point");
    }

    private void Launch(IReadOnlyList<string> command)
    {
        var capturePath = Environment.GetEnvironmentVariable("BKE_AGENT_VNEXT_PRIVILEGED_CAPTURE_PATH");
        if (_certificationMode && !string.IsNullOrWhiteSpace(capturePath))
        {
            File.WriteAllText(capturePath, JsonSerializer.Serialize(command), new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            return;
        }
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Windows elevation is only available on Windows");
        }
        var start = new ProcessStartInfo
        {
            FileName = command[0],
            UseShellExecute = true,
            Verb = "runas",
        };
        foreach (var argument in command.Skip(1)) start.ArgumentList.Add(argument);
        _ = Process.Start(start) ?? throw new InvalidOperationException("privileged helper did not start");
    }

    private void WriteTransaction(string runtimeRoot, string transactionId, string state, string helper)
    {
        var folder = Path.Combine(_stateRoot, "core", transactionId);
        Directory.CreateDirectory(folder);
        WriteJson(Path.Combine(folder, "state.json"), new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["transaction_id"] = transactionId,
            ["state"] = state,
            ["privileged"] = true,
            ["helper"] = helper,
            ["ready_marker"] = null,
        });
    }

    private PrivilegedConfig LoadPrivilegedConfig()
    {
        var configPath = Environment.GetEnvironmentVariable("BKE_PRIVILEGED_CONFIG")
            ?? Path.Combine(_dataDir, "privileged-update.json");
        using var document = JsonDocument.Parse(File.ReadAllText(configPath));
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object ||
            !root.EnumerateObject().Select(item => item.Name).ToHashSet(StringComparer.Ordinal).SetEquals(PrivilegedConfigKeys))
        {
            throw new InvalidDataException("invalid privileged runtime configuration");
        }
        var approved = root.GetProperty("approved_install_roots");
        if (approved.ValueKind != JsonValueKind.Array) throw new InvalidDataException("approved roots are required");
        var roots = approved.EnumerateArray().Select(item => item.GetString())
            .Where(item => !string.IsNullOrWhiteSpace(item)).Cast<string>().ToArray();
        if (roots.Length == 0 || roots.Length != approved.GetArrayLength()) throw new InvalidDataException("approved roots are required");
        var targetKeys = LoadRawPublicKeys(RequiredString(root, "target_keys_dir"));
        if (targetKeys.Count == 0) throw new InvalidDataException("trusted BKE target keys unavailable");
        var privateKey = LoadPrivateKey(RequiredString(root, "signing_private_key"));
        return new PrivilegedConfig(
            RequiredString(root, "runtime_root"),
            RequiredString(root, "helper_executable"),
            RequiredString(root, "signing_key_id"),
            privateKey,
            targetKeys,
            RequiredString(root, "target_policies_dir"),
            roots,
            RequiredString(root, "expected_channel"));
    }

    private TargetPolicy ResolveTargetPolicy(ProductContext product, PrivilegedConfig config)
    {
        TargetPolicy? selected = null;
        foreach (var path in Directory.Exists(config.TargetPoliciesDir)
                     ? Directory.EnumerateFiles(config.TargetPoliciesDir, "*.json").OrderBy(item => item, StringComparer.Ordinal).ToArray()
                     : Array.Empty<string>())
        {
            try
            {
                using var document = JsonDocument.Parse(File.ReadAllText(path));
                var candidate = VerifyTargetPolicy(document.RootElement, config);
                if (candidate.ProductId == product.ProductId && candidate.Platform == product.Platform &&
                    candidate.Architecture == product.Architecture &&
                    (selected is null || candidate.Revision > selected.Revision))
                {
                    selected = candidate with { Raw = candidate.Raw.Clone() };
                }
            }
            catch
            {
                // Invalid target-policy files are ignored exactly like the frozen oracle.
            }
        }
        return selected ?? throw new InvalidDataException("no verified BKE install-target policy");
    }

    private TargetPolicy ResolveTargetPolicyForProvision(
        string productId,
        string platform,
        string protocolArchitecture,
        PrivilegedConfig config)
    {
        TargetPolicy? selected = null;

        foreach (var path in Directory.Exists(config.TargetPoliciesDir)
                     ? Directory.EnumerateFiles(config.TargetPoliciesDir, "*.json")
                         .OrderBy(item => item, StringComparer.Ordinal)
                         .ToArray()
                     : Array.Empty<string>())
        {
            try
            {
                using var document = JsonDocument.Parse(File.ReadAllText(path));
                var candidate = VerifyTargetPolicy(document.RootElement, config);
                if (candidate.ProductId == productId &&
                    candidate.Platform == platform &&
                    ArchitecturesEquivalent(
                        candidate.Architecture,
                        protocolArchitecture) &&
                    (selected is null || candidate.Revision > selected.Revision))
                {
                    selected = candidate with { Raw = candidate.Raw.Clone() };
                }
            }
            catch
            {
                // Fail closed by ignoring any target policy that cannot be independently verified.
            }
        }

        return selected
            ?? throw new InvalidDataException(
                "no verified BKE install-target policy");
    }

    private static bool ArchitecturesEquivalent(
        string targetArchitecture,
        string protocolArchitecture)
    {
        static string Normalize(string value) =>
            value.Trim().ToLowerInvariant() switch
            {
                "amd64" or "x86_64" or "x64" => "x64",
                "arm64" or "aarch64" => "arm64",
                "x86" or "i386" or "i686" => "x86",
                _ => value.Trim().ToLowerInvariant(),
            };

        return string.Equals(
            Normalize(targetArchitecture),
            Normalize(protocolArchitecture),
            StringComparison.Ordinal);
    }

    private TargetPolicy VerifyTargetPolicy(JsonElement policy, PrivilegedConfig config)
    {
        if (policy.ValueKind != JsonValueKind.Object ||
            !policy.EnumerateObject().Select(item => item.Name).ToHashSet(StringComparer.Ordinal).SetEquals(TargetPolicyKeys) ||
            RequiredString(policy, "schema") != "bke.install-target-policy.v1" ||
            RequiredString(policy, "algorithm") != "Ed25519" ||
            RequiredString(policy, "platform") != "windows")
        {
            throw new InvalidDataException("unsupported target policy contract");
        }
        var policyId = RequiredString(policy, "policy_id");
        if (!Regex.IsMatch(policyId, "^[A-Za-z0-9_.-]{8,128}$", RegexOptions.CultureInvariant))
            throw new InvalidDataException("invalid policy_id");
        var revision = RequiredInt(policy, "revision");
        if (revision < 1) throw new InvalidDataException("invalid target revision");
        var installRoot = NormalizeWindowsAbsolute(RequiredString(policy, "install_root"));
        if (!config.ApprovedInstallRoots.Select(NormalizeWindowsAbsolute).Any(root => WindowsUnder(root, installRoot)))
            throw new InvalidDataException("install root outside approved roots");
        var entryPoint = NormalizeWindowsRelative(RequiredString(policy, "entry_point"));
        var keyId = RequiredString(policy, "signing_key_id");
        if (!config.TargetKeys.TryGetValue(keyId, out var key)) throw new InvalidDataException("unknown BKE signing key");
        var signature = Convert.FromBase64String(RequiredString(policy, "signature"));
        var canonical = CanonicalWithoutSignature(policy);
        var verifier = new Ed25519Signer();
        verifier.Init(false, key);
        verifier.BlockUpdate(canonical, 0, canonical.Length);
        if (!verifier.VerifySignature(signature)) throw new CryptographicException("invalid target policy signature");
        return new TargetPolicy(
            policy.Clone(), revision, RequiredString(policy, "product_id"), "windows",
            RequiredString(policy, "architecture"), installRoot, entryPoint);
    }

    private VerifiedPolicy VerifyPolicy(JsonElement policy, ProductContext product, int? lastRevision)
    {
        if (policy.ValueKind != JsonValueKind.Object ||
            !policy.EnumerateObject().Select(item => item.Name).ToHashSet(StringComparer.Ordinal).SetEquals(PolicyKeys) ||
            RequiredString(policy, "schema") != "bke.update-policy.v1" ||
            RequiredString(policy, "algorithm") != "Ed25519" ||
            RequiredString(policy, "product_id") != product.ProductId ||
            RequiredString(policy, "current_version") != product.Version ||
            RequiredString(policy, "platform") != product.Platform ||
            RequiredString(policy, "architecture") != product.Architecture ||
            RequiredString(policy, "channel") != product.UpdateChannel)
        {
            throw new InvalidDataException("unsupported update policy");
        }
        var latest = RequiredString(policy, "latest_version");
        var minimum = RequiredString(policy, "minimum_supported_version");
        if (!TryVersion(product.Version, out _) || !TryVersion(latest, out var latestParts) ||
            !TryVersion(minimum, out var minimumParts) || CompareVersion(minimumParts, latestParts) > 0)
            throw new InvalidDataException("invalid semantic version");
        var revision = RequiredInt(policy, "revision");
        if (revision < 0 || (lastRevision is not null && revision <= lastRevision.Value))
            throw new InvalidDataException("stale policy");
        var size = RequiredLong(policy, "artifact_size");
        var hash = RequiredString(policy, "artifact_sha256");
        if (size < 0 || !HashPattern.IsMatch(hash)) throw new InvalidDataException("invalid artifact contract");
        var keyId = RequiredString(policy, "signing_key_id");
        var key = LoadTrustedUpdateKey(keyId) ?? throw new InvalidDataException("unknown signing key");
        var signature = Convert.FromBase64String(RequiredString(policy, "signature"));
        var canonical = CanonicalWithoutSignature(policy);
        var verifier = new Ed25519Signer();
        verifier.Init(false, key);
        verifier.BlockUpdate(canonical, 0, canonical.Length);
        if (!verifier.VerifySignature(signature)) throw new CryptographicException("invalid policy signature");
        return new VerifiedPolicy(
            latest, minimum, RequiredString(policy, "release_id"), RequiredString(policy, "artifact_id"),
            hash.ToLowerInvariant(), size, RequiredString(policy, "content_type"), revision);
    }

    private ProductContext? LoadProduct(string productId, string version)
    {
        if (!File.Exists(_databasePath)) return null;
        try
        {
            using var connection = OpenDatabase(SqliteOpenMode.ReadOnly);
            using var command = connection.CreateCommand();
            command.CommandText = """
                SELECT manifest_path, product_root, entry_point_path
                FROM discovered_products
                WHERE product_id=$product_id AND version=$version
                ORDER BY discovered_at DESC LIMIT 1
                """;
            command.Parameters.AddWithValue("$product_id", productId);
            command.Parameters.AddWithValue("$version", version);
            using var reader = command.ExecuteReader();
            if (!reader.Read()) return null;
            var manifestPath = reader.GetString(0);
            var productRoot = reader.GetString(1);
            var entryPath = reader.GetString(2);
            using var manifestDocument = JsonDocument.Parse(File.ReadAllText(manifestPath));
            var root = manifestDocument.RootElement;
            var allowed = new HashSet<string>(StringComparer.Ordinal)
            {
                "schemaVersion", "productId", "displayName", "publisher", "version", "entryPoint", "icon",
                "updateChannel", "minimumAgentVersion", "platform", "architecture",
            };
            if (root.ValueKind != JsonValueKind.Object ||
                root.EnumerateObject().Any(item => !allowed.Contains(item.Name)) ||
                !root.TryGetProperty("schemaVersion", out var schema) || schema.ValueKind != JsonValueKind.Number || schema.GetInt32() != 1)
                return null;
            var manifestProductId = RequiredString(root, "productId");
            var manifestVersion = RequiredString(root, "version");
            var displayName = RequiredString(root, "displayName");
            var minimumAgentVersion = RequiredString(root, "minimumAgentVersion");
            var entryPoint = RequiredString(root, "entryPoint");
            var platform = RequiredString(root, "platform");
            var architecture = RequiredString(root, "architecture");
            var channel = RequiredString(root, "updateChannel");
            if (manifestProductId != productId || manifestVersion != version || displayName.Length == 0 ||
                !ProductIdPattern.IsMatch(manifestProductId) || !ManifestVersionPattern.IsMatch(manifestVersion) ||
                !ManifestVersionPattern.IsMatch(minimumAgentVersion) || !ValidRelativePath(entryPoint) ||
                platform is not ("windows" or "macos" or "linux") ||
                architecture is not ("x86" or "x64" or "arm64") ||
                channel is not ("stable" or "beta" or "alpha"))
                return null;
            if (root.TryGetProperty("publisher", out var publisher) &&
                (publisher.ValueKind != JsonValueKind.String || string.IsNullOrEmpty(publisher.GetString())))
                return null;
            if (root.TryGetProperty("icon", out var icon) &&
                (icon.ValueKind != JsonValueKind.String || string.IsNullOrEmpty(icon.GetString()) || !ValidRelativePath(icon.GetString()!)))
                return null;
            var expectedEntry = Path.GetFullPath(Path.Combine(productRoot, entryPoint));
            if (!string.Equals(expectedEntry, Path.GetFullPath(entryPath), OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                return null;
            return new ProductContext(productId, version, platform, architecture, channel, productRoot, entryPoint);
        }
        catch
        {
            return null;
        }
    }

    private LeaseEnvelope? LoadUpdateLease(string productId, string version)
    {
        if (!File.Exists(_databasePath)) return null;
        using var connection = OpenDatabase(SqliteOpenMode.ReadOnly);
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT signed_payload, signed_signature, key_id, signed_algorithm
            FROM verified_licenses
            WHERE product_id=$product_id AND product_version=$version AND status='verified'
              AND signed_payload IS NOT NULL AND signed_signature IS NOT NULL AND signed_algorithm IS NOT NULL
            ORDER BY updated_at DESC LIMIT 1
            """;
        command.Parameters.AddWithValue("$product_id", productId);
        command.Parameters.AddWithValue("$version", version);
        using var reader = command.ExecuteReader();
        return reader.Read() ? new LeaseEnvelope(reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3)) : null;
    }

    private int? HighestRevision(ProductContext product)
    {
        var path = RevisionPath(product);
        if (!File.Exists(path)) return null;
        using var document = JsonDocument.Parse(File.ReadAllText(path));
        return document.RootElement.TryGetProperty("revision", out var revision) && revision.TryGetInt32(out var value) ? value : null;
    }

    private void AcceptRevision(ProductContext product, int revision)
    {
        var current = HighestRevision(product);
        if (current is not null && revision < current.Value) throw new InvalidDataException("policy revision rollback");
        WriteJson(RevisionPath(product), new Dictionary<string, object?> { ["revision"] = revision });
    }

    private string RevisionPath(ProductContext product) =>
        Path.Combine(_stateRoot, "core", "policy-revisions", $"{Safe($"{product.ProductId}-{product.Platform}-{product.Architecture}-{product.UpdateChannel}", 180)}.json");

    private Ed25519PublicKeyParameters? LoadTrustedUpdateKey(string keyId)
    {
        var path = Path.Combine(_dataDir, "trusted-keys", keyId + ".pem");
        if (!File.Exists(path)) return null;
        try
        {
            using var reader = new StringReader(File.ReadAllText(path));
            return new PemReader(reader).ReadObject() as Ed25519PublicKeyParameters;
        }
        catch { return null; }
    }

    private static Dictionary<string, Ed25519PublicKeyParameters> LoadRawPublicKeys(string directory)
    {
        var result = new Dictionary<string, Ed25519PublicKeyParameters>(StringComparer.Ordinal);
        if (!Directory.Exists(directory)) return result;
        foreach (var path in Directory.EnumerateFiles(directory, "*.pem").OrderBy(item => item, StringComparer.Ordinal))
        {
            try
            {
                using var reader = new StringReader(File.ReadAllText(path));
                if (new PemReader(reader).ReadObject() is Ed25519PublicKeyParameters key)
                    result[Path.GetFileNameWithoutExtension(path)] = key;
            }
            catch { }
        }
        return result;
    }

    private static Ed25519PrivateKeyParameters LoadPrivateKey(string path)
    {
        using var reader = new StringReader(File.ReadAllText(path));
        var keyObject = new PemReader(reader).ReadObject();
        return keyObject switch
        {
            Ed25519PrivateKeyParameters privateKey => privateKey,
            AsymmetricCipherKeyPair pair when pair.Private is Ed25519PrivateKeyParameters privateKey => privateKey,
            _ => throw new InvalidDataException("Agent privileged signing key must be Ed25519"),
        };
    }

    private static string NormalizeWindowsAbsolute(string value)
    {
        var input = value.Replace('/', '\\');
        if (!Regex.IsMatch(input, "^[A-Za-z]:\\\\", RegexOptions.CultureInvariant))
            throw new InvalidDataException("invalid Windows path");
        var drive = char.ToUpperInvariant(input[0]) + ":";
        var stack = new List<string>();
        foreach (var part in input[3..].Split('\\', StringSplitOptions.RemoveEmptyEntries))
        {
            if (part == ".") continue;
            if (part == "..") { if (stack.Count == 0) throw new InvalidDataException("invalid Windows path"); stack.RemoveAt(stack.Count - 1); continue; }
            stack.Add(part);
        }
        return drive + "\\" + string.Join("\\", stack);
    }

    private static string NormalizeWindowsRelative(string value)
    {
        var input = value.Replace('/', '\\');
        if (string.IsNullOrWhiteSpace(input) || Regex.IsMatch(input, "^[A-Za-z]:", RegexOptions.CultureInvariant) || input.StartsWith('\\'))
            throw new InvalidDataException("invalid entry_point");
        var parts = input.Split('\\', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0 || parts.Any(part => part is "." or "..")) throw new InvalidDataException("invalid entry_point");
        return string.Join("\\", parts);
    }

    private static bool WindowsUnder(string root, string child)
    {
        var normalizedRoot = NormalizeWindowsAbsolute(root).TrimEnd('\\');
        var normalizedChild = NormalizeWindowsAbsolute(child);
        return normalizedChild.Equals(normalizedRoot, StringComparison.OrdinalIgnoreCase) ||
            normalizedChild.StartsWith(normalizedRoot + "\\", StringComparison.OrdinalIgnoreCase);
    }

    private static bool ValidRelativePath(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.StartsWith('/') || value.StartsWith('\\') ||
            (value.Length >= 2 && value[1] == ':')) return false;
        return !value.Replace('\\', '/').Split('/').Contains("..", StringComparer.Ordinal);
    }

    private static bool OffersUpdate(string current, string latest, string minimum)
    {
        if (!TryVersion(current, out var currentParts) || !TryVersion(latest, out var latestParts) || !TryVersion(minimum, out var minimumParts))
            return false;
        return CompareVersion(currentParts, minimumParts) < 0 || CompareVersion(currentParts, latestParts) < 0;
    }

    private static bool TryVersion(string value, out int[] parts)
    {
        parts = Array.Empty<int>();
        if (!CoreVersionPattern.IsMatch(value)) return false;
        try
        {
            parts = value.Split('.').Select(int.Parse).Concat(Enumerable.Repeat(0, 4)).Take(4).ToArray();
            return true;
        }
        catch { return false; }
    }

    private static int CompareVersion(int[] left, int[] right)
    {
        for (var index = 0; index < 4; index++)
        {
            var comparison = left[index].CompareTo(right[index]);
            if (comparison != 0) return comparison;
        }
        return 0;
    }

    private static bool IsRetryable(HttpStatusCode status) => status is
        HttpStatusCode.RequestTimeout or (HttpStatusCode)425 or (HttpStatusCode)429 or
        HttpStatusCode.InternalServerError or HttpStatusCode.BadGateway or
        HttpStatusCode.ServiceUnavailable or HttpStatusCode.GatewayTimeout;

    private SqliteConnection OpenDatabase(SqliteOpenMode mode)
    {
        var builder = new SqliteConnectionStringBuilder { DataSource = _databasePath, Mode = mode };
        var connection = new SqliteConnection(builder.ToString());
        connection.Open();
        connection.ExecuteNonQuery("PRAGMA busy_timeout=5000");
        return connection;
    }

    private static Dictionary<string, object?>? ReadObject(string path)
    {
        if (!File.Exists(path)) return null;
        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(path));
            if (document.RootElement.ValueKind != JsonValueKind.Object) return null;
            return document.RootElement.EnumerateObject().ToDictionary(
                property => property.Name,
                property => JsonValue(property.Value),
                StringComparer.Ordinal);
        }
        catch { return null; }
    }

    private static object? JsonValue(JsonElement element) => element.ValueKind switch
    {
        JsonValueKind.String => element.GetString(),
        JsonValueKind.Number when element.TryGetInt64(out var integer) => integer,
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        JsonValueKind.Null => null,
        _ => element.GetRawText(),
    };

    private static void WriteJson(string path, object value)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temporary = path + ".tmp";
        File.WriteAllText(temporary, JsonSerializer.Serialize(value), new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        File.Move(temporary, path, true);
    }

    private static byte[] CanonicalWithoutSignature(JsonElement document)
    {
        var unsigned = document.EnumerateObject().Where(item => item.Name != "signature")
            .OrderBy(item => item.Name, StringComparer.Ordinal).ToArray();
        var builder = new StringBuilder("{");
        for (var index = 0; index < unsigned.Length; index++)
        {
            if (index > 0) builder.Append(',');
            builder.Append(JsonString(unsigned[index].Name)).Append(':').Append(CanonicalJson(unsigned[index].Value));
        }
        return Encoding.UTF8.GetBytes(builder.Append('}').ToString());
    }

    private static byte[] CanonicalObjectBytes(object value)
    {
        using var document = JsonDocument.Parse(JsonSerializer.Serialize(value));
        return Encoding.UTF8.GetBytes(CanonicalJson(document.RootElement));
    }

    private static string CanonicalJson(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.Object => "{" + string.Join(",", value.EnumerateObject().OrderBy(item => item.Name, StringComparer.Ordinal)
            .Select(item => JsonString(item.Name) + ":" + CanonicalJson(item.Value))) + "}",
        JsonValueKind.Array => "[" + string.Join(",", value.EnumerateArray().Select(CanonicalJson)) + "]",
        JsonValueKind.String => JsonString(value.GetString()!),
        JsonValueKind.Number => value.GetRawText(),
        JsonValueKind.True => "true",
        JsonValueKind.False => "false",
        JsonValueKind.Null => "null",
        _ => throw new InvalidDataException("unsupported JSON token"),
    };

    private static string JsonString(string value) => JsonSerializer.Serialize(value, CanonicalJsonOptions);

    private static string DocumentSha256(JsonElement document) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(CanonicalJson(document)))).ToLowerInvariant();

    private static string RequiredString(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.String || string.IsNullOrEmpty(value.GetString()))
            throw new InvalidDataException($"missing or invalid {name}");
        return value.GetString()!;
    }

    private static int RequiredInt(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.Number || !value.TryGetInt32(out var result))
            throw new InvalidDataException($"missing or invalid {name}");
        return result;
    }

    private static long RequiredLong(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.Number || !value.TryGetInt64(out var result))
            throw new InvalidDataException($"missing or invalid {name}");
        return result;
    }

    private static DateTimeOffset ParseDateTime(IReadOnlyDictionary<string, object?> document, string name)
    {
        if (!document.TryGetValue(name, out var value) || value is not string raw || !DateTimeOffset.TryParse(raw, out var parsed))
            throw new InvalidDataException($"missing or invalid {name}");
        return parsed.ToUniversalTime();
    }

    private static string Safe(string value, int length)
    {
        var sanitized = SafePathPattern.Replace(value, "-");
        return sanitized.Length <= length ? sanitized : sanitized[..length];
    }

    private static string Iso(DateTimeOffset value) => value.ToUniversalTime().ToString("O").Replace("+00:00", "Z", StringComparison.Ordinal);

    private sealed record ProductContext(
        string ProductId, string Version, string Platform, string Architecture, string UpdateChannel,
        string ProductRoot, string EntryPoint);
    private sealed record LeaseEnvelope(string Payload, string Signature, string KeyId, string Algorithm);
    private sealed record RemoteUpdateResponse(string Status, JsonElement? Policy, string? DownloadUrl);
    private sealed record VerifiedPolicy(
        string LatestVersion, string MinimumSupportedVersion, string ReleaseId, string ArtifactId,
        string ArtifactSha256, long ArtifactSize, string ContentType, int Revision);
    private sealed record TargetPolicy(
        JsonElement Raw, int Revision, string ProductId, string Platform, string Architecture, string InstallRoot, string EntryPoint);
    private sealed record PrivilegedConfig(
        string RuntimeRoot, string HelperExecutable, string SigningKeyId, Ed25519PrivateKeyParameters SigningPrivateKey,
        IReadOnlyDictionary<string, Ed25519PublicKeyParameters> TargetKeys, string TargetPoliciesDir,
        string[] ApprovedInstallRoots, string ExpectedChannel);
    private sealed record PreparedInvocation(IReadOnlyList<string> Command);
}

internal static class SqliteConnectionUpdateCenterExtensions
{
    public static void ExecuteNonQuery(this SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }
}
