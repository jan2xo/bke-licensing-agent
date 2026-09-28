using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
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

    Require(
        result.Status == "STARTED" &&
        result.State == "provision_started" &&
        !result.Retryable,
        $"Provisioning did not start: status={result.Status}, state={result.State}, retryable={result.Retryable}");

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
    evidence["provision_state"] = result.State;
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
