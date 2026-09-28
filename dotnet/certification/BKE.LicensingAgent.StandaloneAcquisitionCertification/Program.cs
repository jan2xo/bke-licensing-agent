using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Reflection;
using System.Text.Json;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Infrastructure;

const string ProductId = "bke-render-dock";
const string Version = "1.0.2";
const string Repository = "jan2xo/BKE_RENDER_DOCK";
const string Tag = "v1.0.2";
const string EntryPoint = "RENDER DOCK.exe";
const long ExpectedArtifactBytes = 54156325;
const string ExpectedArtifactSha256 = "88bc6131f6c66d7c6ee69a368e414d4c88bdf1f969e6b398e74c7cbaa299fa1a";

string? outputPath = null;
string? sourceSha = null;
for (var index = 0; index < args.Length; index++)
{
    if (args[index] == "--output" && index + 1 < args.Length)
    {
        outputPath = Path.GetFullPath(args[++index]);
    }
    else if (args[index] == "--source-sha" && index + 1 < args.Length)
    {
        sourceSha = args[++index].Trim().ToLowerInvariant();
    }
    else
    {
        throw new InvalidDataException($"Unknown or incomplete argument: {args[index]}");
    }
}

if (string.IsNullOrWhiteSpace(outputPath))
{
    throw new InvalidDataException("--output <path> is required");
}
if (string.IsNullOrWhiteSpace(sourceSha) ||
    sourceSha.Length != 40 ||
    sourceSha.Any(character => !Uri.IsHexDigit(character)))
{
    throw new InvalidDataException("--source-sha must be an exact 40-character SHA");
}

var evidence = new SortedDictionary<string, object?>(StringComparer.Ordinal)
{
    ["schema"] = "bke.standalone-acquisition-certification.v1",
    ["source_sha"] = sourceSha,
    ["product_id"] = ProductId,
    ["version"] = Version,
    ["repository"] = Repository,
    ["tag"] = Tag,
    ["status"] = "FAILED",
};

try
{
    Require(OperatingSystem.IsWindows(), "Windows is required");

    var identity = WindowsIdentity.GetCurrent();
    var identityName = identity.Name ?? string.Empty;
    Require(
        string.Equals(identityName, @"NT AUTHORITY\SYSTEM", StringComparison.OrdinalIgnoreCase),
        $"Certification must run as NT AUTHORITY\\SYSTEM, got '{identityName}'.");

    var dataRoot = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "BKE Digital Solutions",
        "Licensing Agent");
    var configPath = Path.Combine(dataRoot, "privileged-update.json");
    Require(File.Exists(configPath), "Installed Agent privileged-update.json is missing.");

    using var configDocument = JsonDocument.Parse(File.ReadAllText(configPath));
    var configRoot = configDocument.RootElement;
    var runtimeRoot = Path.GetFullPath(
        configRoot.GetProperty("runtime_root").GetString()
        ?? throw new InvalidDataException("runtime_root is missing"));
    var helperExecutable = Path.GetFullPath(
        configRoot.GetProperty("helper_executable").GetString()
        ?? throw new InvalidDataException("helper_executable is missing"));
    Require(File.Exists(helperExecutable), "Installed privileged helper is missing.");

    var installRoot = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
        "BKE Digital Solutions",
        "Render Dock");
    var entryPointPath = Path.Combine(installRoot, EntryPoint);
    Require(
        !Directory.Exists(installRoot) && !File.Exists(installRoot),
        "Certification refuses to overwrite an existing Render Dock installation.");

    Environment.SetEnvironmentVariable(
        "BKE_AGENT_DATA_DIR",
        dataRoot,
        EnvironmentVariableTarget.Process);
    Environment.SetEnvironmentVariable(
        "BKE_PLATFORM_BASE_URL",
        "https://certification.invalid",
        EnvironmentVariableTarget.Process);
    Environment.SetEnvironmentVariable(
        "BKE_AGENT_SERVICE_HOSTED",
        "1",
        EnvironmentVariableTarget.Process);

    var provider = new PrivilegedUpdateCenterProvider();
    using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(10));
    var result = await provider.ProvisionAsync(
        new StandaloneProvisionAuthorization(
            ProductId,
            Version,
            Repository,
            Tag),
        timeout.Token);

    if (result.Status != "STARTED" ||
        result.Reason != "provision_started" ||
        result.Retryable)
    {
        evidence["provision_status"] = result.Status;
        evidence["provision_reason"] = result.Reason;
        evidence["provision_retryable"] = result.Retryable;
        try
        {
            evidence["provider_acquisition_diagnostic"] =
                await DiagnoseProviderAcquisitionAsync(
                    provider,
                    runtimeRoot);
        }
        catch (Exception providerDiagnosticException)
        {
            var root = providerDiagnosticException.GetBaseException();
            evidence["provider_acquisition_diagnostic_error_type"] =
                root.GetType().FullName;
            evidence["provider_acquisition_diagnostic_error"] =
                root.Message;
            if (root is HttpRequestException httpException)
            {
                evidence["provider_acquisition_http_status"] =
                    httpException.StatusCode is null
                        ? null
                        : (int)httpException.StatusCode.Value;
            }
        }

        try
        {
            evidence["release_diagnostic"] =
                await DiagnoseImmutableReleaseAsync();
        }
        catch (Exception diagnosticException)
        {
            evidence["release_diagnostic_error_type"] =
                diagnosticException.GetType().FullName;
            evidence["release_diagnostic_error"] =
                diagnosticException.Message;
        }

        throw new InvalidOperationException(
            $"Provisioning did not start: status={result.Status}, reason={result.Reason}, retryable={result.Retryable}");
    }

    var genericArtifactDiagnostic =
        await CertifyGenericArtifactAcquisitionAsync(
            provider,
            runtimeRoot);
    evidence["generic_artifact_acquisition"] =
        genericArtifactDiagnostic;

    var inventory = new SqliteProductInventory(dataRoot);
    LocalInstalledProduct? installed = null;
    var deadline = DateTimeOffset.UtcNow.AddMinutes(2);
    while (DateTimeOffset.UtcNow < deadline)
    {
        var products = await inventory.ReadAsync(CancellationToken.None);
        products.TryGetValue(ProductId, out installed);
        if (installed is not null && File.Exists(entryPointPath))
        {
            break;
        }
        await Task.Delay(500);
    }

    Require(installed is not null, "Render Dock was not registered in Agent inventory.");
    Require(File.Exists(entryPointPath), "Render Dock entry point was not installed.");
    Require(installed!.Version == Version, "Installed Render Dock version drifted.");
    Require(
        installed.InstallProvenance == "BKE_MANAGED_PACKAGE",
        "Installed Render Dock provenance drifted.");
    Require(
        installed.UninstallStrategy == "MANAGED_DIRECTORY",
        "Installed Render Dock uninstall strategy drifted.");

    var manifestPath = Path.Combine(installRoot, "bke.manifest.json");
    Require(File.Exists(manifestPath), "Installed Render Dock manifest is missing.");
    using var manifestDocument = JsonDocument.Parse(File.ReadAllText(manifestPath));
    var manifest = manifestDocument.RootElement;
    Require(
        manifest.GetProperty("productId").GetString() == ProductId,
        "Installed Render Dock product identity drifted.");
    Require(
        manifest.GetProperty("version").GetString() == Version,
        "Installed Render Dock manifest version drifted.");
    Require(
        manifest.GetProperty("entryPoint").GetString() == EntryPoint,
        "Installed Render Dock entry point contract drifted.");
    Require(
        manifest.GetProperty("platform").GetString() == "windows",
        "Installed Render Dock platform drifted.");
    Require(
        manifest.GetProperty("architecture").GetString() == "x64",
        "Installed Render Dock architecture drifted.");

    var downloadRoot = Path.Combine(runtimeRoot, "downloads", "provision");
    Require(Directory.Exists(downloadRoot), "Provision download root is missing.");
    var downloadedArtifacts = Directory
        .EnumerateFiles(downloadRoot, "*.update.zip", SearchOption.TopDirectoryOnly)
        .ToArray();
    Require(
        downloadedArtifacts.Length == 1,
        $"Expected exactly one downloaded updater ZIP, found {downloadedArtifacts.Length}.");

    var downloadedArtifact = downloadedArtifacts[0];
    var artifactInfo = new FileInfo(downloadedArtifact);
    var artifactHash = Convert.ToHexString(
        SHA256.HashData(File.ReadAllBytes(downloadedArtifact)))
        .ToLowerInvariant();

    Require(
        artifactInfo.Length == ExpectedArtifactBytes,
        $"Downloaded x64 updater ZIP size drifted: {artifactInfo.Length}.");
    Require(
        artifactHash == ExpectedArtifactSha256,
        $"Downloaded x64 updater ZIP hash drifted: {artifactHash}.");

    evidence["status"] = "PASS";
    evidence["identity"] = identityName;
    evidence["process_architecture"] = RuntimeInformation.ProcessArchitecture.ToString();
    evidence["os_architecture"] = RuntimeInformation.OSArchitecture.ToString();
    evidence["provision_status"] = result.Status;
    evidence["provision_reason"] = result.Reason;
    evidence["runtime_root"] = runtimeRoot;
    evidence["helper_executable"] = helperExecutable;
    evidence["installed_entry_point"] = entryPointPath;
    evidence["installed_entry_point_sha256"] = Sha256File(entryPointPath);
    evidence["install_provenance"] = installed.InstallProvenance;
    evidence["uninstall_strategy"] = installed.UninstallStrategy;
    evidence["artifact_file"] = Path.GetFileName(downloadedArtifact);
    evidence["artifact_bytes"] = artifactInfo.Length;
    evidence["artifact_sha256"] = artifactHash;

    WriteEvidence(outputPath, evidence);
    Console.WriteLine("BKE standalone acquisition certification: PASS");
    return 0;
}
catch (Exception exception)
{
    evidence["error_type"] = exception.GetType().FullName;
    evidence["error"] = exception.Message;
    WriteEvidence(outputPath, evidence);
    Console.Error.WriteLine(exception);
    return 1;
}

static async Task<SortedDictionary<string, object?>> CertifyGenericArtifactAcquisitionAsync(
    PrivilegedUpdateCenterProvider provider,
    string runtimeRoot)
{
    const string packageUrl =
        "https://github.com/jan2xo/BKE_RENDER_DOCK/releases/download/v1.0.2/Render-Dock-1.0.2-Windows-x64.update.zip";
    var destination = Path.Combine(
        runtimeRoot,
        "downloads",
        "generic-artifact-cert",
        "Render-Dock-1.0.2-Windows-x64.update.zip");

    var method = typeof(PrivilegedUpdateCenterProvider)
        .GetMethods(BindingFlags.Instance | BindingFlags.NonPublic)
        .Single(candidate =>
            candidate.Name == "AcquireArtifactAsync" &&
            candidate.GetParameters().Length == 5);

    var taskObject = method.Invoke(
        provider,
        [
            packageUrl,
            destination,
            ExpectedArtifactBytes,
            ExpectedArtifactSha256,
            CancellationToken.None,
        ])
        ?? throw new InvalidOperationException(
            "AcquireArtifactAsync returned null.");

    if (taskObject is not Task task)
    {
        throw new InvalidDataException(
            "AcquireArtifactAsync did not return a Task.");
    }

    await task;
    var acquiredPath = (string)(
        taskObject.GetType()
            .GetProperty("Result", BindingFlags.Instance | BindingFlags.Public)!
            .GetValue(taskObject)
        ?? throw new InvalidDataException(
            "AcquireArtifactAsync Task returned null."));

    var info = new FileInfo(acquiredPath);
    var hash = Sha256File(acquiredPath);
    Require(
        info.Length == ExpectedArtifactBytes,
        "Generic artifact acquisition size drifted.");
    Require(
        hash == ExpectedArtifactSha256,
        "Generic artifact acquisition hash drifted.");

    return new SortedDictionary<string, object?>(
        StringComparer.Ordinal)
    {
        ["status"] = "PASS",
        ["bytes"] = info.Length,
        ["sha256"] = hash,
    };
}

static async Task<SortedDictionary<string, object?>> DiagnoseProviderAcquisitionAsync(
    PrivilegedUpdateCenterProvider provider,
    string runtimeRoot)
{
    const BindingFlags PrivateInstance =
        BindingFlags.Instance | BindingFlags.NonPublic;

    object Invoke(string methodName, params object?[] arguments)
    {
        var methods = typeof(PrivilegedUpdateCenterProvider)
            .GetMethods(PrivateInstance)
            .Where(method => method.Name == methodName)
            .ToArray();
        var method = methods.SingleOrDefault(candidate =>
            candidate.GetParameters().Length == arguments.Length)
            ?? throw new MissingMethodException(
                typeof(PrivilegedUpdateCenterProvider).FullName,
                methodName);
        return method.Invoke(provider, arguments)
            ?? throw new InvalidOperationException(
                $"Private provider method {methodName} returned null.");
    }

    static object RequiredProperty(object instance, string propertyName)
    {
        var property = instance.GetType().GetProperty(
            propertyName,
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
            ?? throw new MissingMemberException(
                instance.GetType().FullName,
                propertyName);
        return property.GetValue(instance)
            ?? throw new InvalidDataException(
                $"Provider diagnostic property {propertyName} was null.");
    }

    static async Task<object> AwaitResultAsync(object taskObject)
    {
        if (taskObject is not Task task)
        {
            throw new InvalidDataException(
                "Provider diagnostic invocation did not return a Task.");
        }
        await task;
        return taskObject.GetType()
            .GetProperty("Result", BindingFlags.Instance | BindingFlags.Public)!
            .GetValue(taskObject)
            ?? throw new InvalidDataException(
                "Provider diagnostic Task returned null.");
    }

    var config = Invoke("LoadPrivilegedConfig");
    var target = Invoke(
        "ResolveTargetPolicyForProvision",
        ProductId,
        "windows",
        "x64",
        config);

    var authorization = new StandaloneProvisionAuthorization(
        ProductId,
        Version,
        Repository,
        Tag);
    var package = await AwaitResultAsync(
        Invoke(
            "ResolveGitHubReleasePackageAsync",
            authorization,
            "x64",
            target,
            CancellationToken.None));

    var fileName = (string)RequiredProperty(package, "FileName");
    var size = (long)RequiredProperty(package, "Size");
    var sha256 = (string)RequiredProperty(package, "Sha256");
    var downloadUrl = (string)RequiredProperty(package, "DownloadUrl");

    var destination = Path.Combine(
        runtimeRoot,
        "downloads",
        "provider-diagnostic",
        fileName);

    var result = new SortedDictionary<string, object?>(
        StringComparer.Ordinal)
    {
        ["file_name"] = fileName,
        ["size"] = size,
        ["sha256"] = sha256,
        ["download_host"] = new Uri(downloadUrl).Host,
        ["destination"] = destination,
    };

    try
    {
        var acquisitionTask = Invoke(
            "AcquireGitHubAssetAsync",
            downloadUrl,
            destination,
            size,
            sha256,
            CancellationToken.None);
        await (Task)acquisitionTask;

        var acquiredPath = (string)(
            acquisitionTask.GetType()
                .GetProperty("Result", BindingFlags.Instance | BindingFlags.Public)!
                .GetValue(acquisitionTask)
            ?? throw new InvalidDataException(
                "Provider diagnostic acquisition returned null."));
        var info = new FileInfo(acquiredPath);
        result["status"] = "PASS";
        result["acquired_bytes"] = info.Length;
        result["acquired_sha256"] = Sha256File(acquiredPath);
    }
    catch (Exception exception)
    {
        var root = exception.GetBaseException();
        result["status"] = "FAILED";
        result["error_type"] = root.GetType().FullName;
        result["error"] = root.Message;
        if (root is HttpRequestException httpException)
        {
            result["http_status"] =
                httpException.StatusCode is null
                    ? null
                    : (int)httpException.StatusCode.Value;
        }
    }

    return result;
}

static async Task<SortedDictionary<string, object?>> DiagnoseImmutableReleaseAsync()
{
    const string metadataUrl =
        "https://github.com/jan2xo/BKE_RENDER_DOCK/releases/download/v1.0.2/Render-Dock-1.0.2-Windows-x64.update.json";

    var metadataTransfer = await DownloadBytesWithHopsAsync(
        new Uri(metadataUrl, UriKind.Absolute),
        64 * 1024,
        CancellationToken.None);

    using var metadataDocument =
        JsonDocument.Parse(metadataTransfer.Bytes);
    var metadata = metadataDocument.RootElement;
    var fileName = metadata.GetProperty("filename").GetString()
        ?? throw new InvalidDataException("Release metadata filename is missing.");
    var advertisedBytes = metadata.GetProperty("bytes").GetInt64();
    var advertisedSha256 = (
        metadata.GetProperty("sha256").GetString()
        ?? throw new InvalidDataException("Release metadata SHA-256 is missing."))
        .ToLowerInvariant();

    if (fileName != "Render-Dock-1.0.2-Windows-x64.update.zip")
    {
        throw new InvalidDataException(
            $"Release metadata selected unexpected file '{fileName}'.");
    }

    var packageUrl = new Uri(
        "https://github.com/jan2xo/BKE_RENDER_DOCK/releases/download/v1.0.2/" +
        fileName,
        UriKind.Absolute);
    var packageTransfer = await DownloadHashWithHopsAsync(
        packageUrl,
        CancellationToken.None);

    return new SortedDictionary<string, object?>(
        StringComparer.Ordinal)
    {
        ["metadata_hops"] = metadataTransfer.Hops,
        ["metadata_filename"] = fileName,
        ["metadata_advertised_bytes"] = advertisedBytes,
        ["metadata_advertised_sha256"] = advertisedSha256,
        ["release_api_asset_bytes"] = ExpectedArtifactBytes,
        ["release_api_asset_sha256"] = ExpectedArtifactSha256,
        ["package_hops"] = packageTransfer.Hops,
        ["package_actual_bytes"] = packageTransfer.Bytes,
        ["package_actual_sha256"] = packageTransfer.Sha256,
        ["metadata_matches_actual"] =
            advertisedBytes == packageTransfer.Bytes &&
            advertisedSha256 == packageTransfer.Sha256,
        ["release_api_matches_actual"] =
            ExpectedArtifactBytes == packageTransfer.Bytes &&
            ExpectedArtifactSha256 == packageTransfer.Sha256,
    };
}

static async Task<(byte[] Bytes, List<SortedDictionary<string, object?>> Hops)>
    DownloadBytesWithHopsAsync(
        Uri initialUri,
        int maximumBytes,
        CancellationToken cancellationToken)
{
    using var http = new HttpClient(
        new HttpClientHandler { AllowAutoRedirect = false })
    {
        Timeout = Timeout.InfiniteTimeSpan,
    };

    var hops = new List<SortedDictionary<string, object?>>();
    var current = initialUri;
    for (var redirect = 0; redirect <= 5; redirect++)
    {
        ValidateDiagnosticUri(current);
        using var request = new HttpRequestMessage(HttpMethod.Get, current);
        request.Headers.Accept.ParseAdd("application/octet-stream");
        request.Headers.UserAgent.ParseAdd("bke-licensing-agent-certification");

        using var response = await http.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);
        hops.Add(SafeHop(current, response));

        if ((int)response.StatusCode is >= 300 and <= 399)
        {
            var location = response.Headers.Location
                ?? throw new HttpRequestException(
                    "Diagnostic redirect is missing a location.");
            current = location.IsAbsoluteUri
                ? location
                : new Uri(current, location);
            continue;
        }

        response.EnsureSuccessStatusCode();
        await using var input =
            await response.Content.ReadAsStreamAsync(cancellationToken);
        using var output = new MemoryStream();
        var buffer = new byte[16 * 1024];
        while (true)
        {
            var remaining = maximumBytes - (int)output.Length + 1;
            if (remaining <= 0)
            {
                throw new InvalidDataException(
                    "Diagnostic metadata exceeded bounded size.");
            }

            var read = await input.ReadAsync(
                buffer.AsMemory(0, Math.Min(buffer.Length, remaining)),
                cancellationToken);
            if (read == 0)
            {
                return (output.ToArray(), hops);
            }

            output.Write(buffer, 0, read);
            if (output.Length > maximumBytes)
            {
                throw new InvalidDataException(
                    "Diagnostic metadata exceeded bounded size.");
            }
        }
    }

    throw new HttpRequestException(
        "Diagnostic metadata redirect limit exceeded.");
}

static async Task<(long Bytes, string Sha256, List<SortedDictionary<string, object?>> Hops)>
    DownloadHashWithHopsAsync(
        Uri initialUri,
        CancellationToken cancellationToken)
{
    using var http = new HttpClient(
        new HttpClientHandler { AllowAutoRedirect = false })
    {
        Timeout = Timeout.InfiniteTimeSpan,
    };

    var hops = new List<SortedDictionary<string, object?>>();
    var current = initialUri;
    for (var redirect = 0; redirect <= 5; redirect++)
    {
        ValidateDiagnosticUri(current);
        using var request = new HttpRequestMessage(HttpMethod.Get, current);
        request.Headers.Accept.ParseAdd("application/octet-stream");
        request.Headers.UserAgent.ParseAdd("bke-licensing-agent-certification");

        using var response = await http.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);
        hops.Add(SafeHop(current, response));

        if ((int)response.StatusCode is >= 300 and <= 399)
        {
            var location = response.Headers.Location
                ?? throw new HttpRequestException(
                    "Diagnostic package redirect is missing a location.");
            current = location.IsAbsoluteUri
                ? location
                : new Uri(current, location);
            continue;
        }

        response.EnsureSuccessStatusCode();
        await using var input =
            await response.Content.ReadAsStreamAsync(cancellationToken);
        using var hash =
            IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[1024 * 1024];
        long count = 0;

        while (true)
        {
            var read = await input.ReadAsync(buffer, cancellationToken);
            if (read == 0)
            {
                return (
                    count,
                    Convert.ToHexString(hash.GetHashAndReset())
                        .ToLowerInvariant(),
                    hops);
            }

            count += read;
            if (count > 4L * 1024 * 1024 * 1024)
            {
                throw new InvalidDataException(
                    "Diagnostic package exceeded bounded size.");
            }
            hash.AppendData(buffer, 0, read);
        }
    }

    throw new HttpRequestException(
        "Diagnostic package redirect limit exceeded.");
}

static SortedDictionary<string, object?> SafeHop(
    Uri uri,
    HttpResponseMessage response) =>
    new(StringComparer.Ordinal)
    {
        ["host"] = uri.Host,
        ["status"] = (int)response.StatusCode,
        ["content_length"] = response.Content.Headers.ContentLength,
    };

static void ValidateDiagnosticUri(Uri uri)
{
    var allowed = new HashSet<string>(
        StringComparer.OrdinalIgnoreCase)
    {
        "github.com",
        "release-assets.githubusercontent.com",
        "objects.githubusercontent.com",
        "github-releases.githubusercontent.com",
    };

    if (!uri.IsAbsoluteUri ||
        uri.Scheme != Uri.UriSchemeHttps ||
        !allowed.Contains(uri.Host) ||
        !string.IsNullOrEmpty(uri.Fragment))
    {
        throw new InvalidDataException(
            $"Diagnostic release host is not approved: {uri.Host}");
    }
}

static string Sha256File(string path) =>
    Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)))
        .ToLowerInvariant();

static void WriteEvidence(
    string path,
    SortedDictionary<string, object?> evidence)
{
    Directory.CreateDirectory(Path.GetDirectoryName(path)!);
    File.WriteAllText(
        path,
        JsonSerializer.Serialize(
            evidence,
            new JsonSerializerOptions { WriteIndented = true }) +
        Environment.NewLine);
}

static void Require(bool condition, string message)
{
    if (!condition)
    {
        throw new InvalidOperationException(message);
    }
}
