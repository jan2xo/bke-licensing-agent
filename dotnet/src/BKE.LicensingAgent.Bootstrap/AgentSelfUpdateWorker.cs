using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace BKE.LicensingAgent.Bootstrap;

internal sealed class AgentSelfUpdateWorker(ILogger<AgentSelfUpdateWorker> logger) : BackgroundService
{
    private const long MaxInstallerBytes = 512L * 1024L * 1024L;
    private static readonly TimeSpan InitialDelay = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan CheckInterval = TimeSpan.FromHours(6);
    private static readonly TimeSpan RemindAfter = TimeSpan.FromHours(24);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!OperatingSystem.IsWindows() || Environment.GetEnvironmentVariable("BKE_AGENT_SELF_UPDATE_DISABLE") == "1") return;
        try { await Task.Delay(InitialDelay, stoppingToken); }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { return; }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var outcome = await PollOnceAsync(stoppingToken);
                if (outcome == "update_started") logger.LogInformation("Agent runtime update installer started");
                if (outcome == "later") logger.LogInformation("Agent runtime update deferred by active user");
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { return; }
            catch (Exception exception) { logger.LogWarning(exception, "Agent runtime update check failed"); }

            try { await Task.Delay(CheckInterval, stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { return; }
        }
    }

    private async Task<string> PollOnceAsync(CancellationToken cancellationToken)
    {
        var offer = await CheckAsync(cancellationToken);
        if (offer is null) return "up_to_date";
        if (!offer.Required && IsSuppressed(offer.LatestVersion)) return "suppressed";

        var prompt = Prompt(offer, cancellationToken);
        if (prompt == "later" && !offer.Required)
        {
            Suppress(offer.LatestVersion);
            return "later";
        }

        var installer = await DownloadAsync(offer, cancellationToken);
        LaunchInstaller(installer);
        return "update_started";
    }

    private async Task<UpdateOffer?> CheckAsync(CancellationToken cancellationToken)
    {
        var current = CurrentVersion();
        var currentVersion = SemanticVersion.Parse(current);
        var targetArchitecture = TargetArchitecture();
        var platformBase = (Environment.GetEnvironmentVariable("BKE_PLATFORM_BASE_URL") ?? "https://jl-bke.com").TrimEnd('/');
        if (!Uri.TryCreate(platformBase, UriKind.Absolute, out var origin) || origin.Scheme != Uri.UriSchemeHttps)
            throw new InvalidOperationException("BKE_PLATFORM_BASE_URL must be HTTPS");

        var target = new UriBuilder(new Uri(origin, "/api/licensing-agent/update"))
        {
            Query = $"version={Uri.EscapeDataString(current)}&platform=windows&architecture={Uri.EscapeDataString(targetArchitecture.QueryValue)}",
        }.Uri;
        using var handler = new HttpClientHandler { AllowAutoRedirect = false };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
        using var request = new HttpRequestMessage(HttpMethod.Get, target);
        request.Headers.Accept.ParseAdd("application/json");
        request.Headers.UserAgent.ParseAdd($"BKE-Licensing-Agent/{current}");
        using var response = await client.SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
        var root = document.RootElement;

        RequireString(root, "productId", RuntimeBridgeContract.AgentProductId);
        RequireString(root, "source", "bke-software-catalog");
        RequireString(root, "currentVersion", current);
        var latest = RequiredString(root, "latestVersion");
        var latestVersion = SemanticVersion.Parse(latest);
        if (!root.TryGetProperty("updateAvailable", out var availableValue) || availableValue.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
            throw new InvalidDataException("Agent update response is malformed");
        var available = availableValue.GetBoolean();
        if (!available)
        {
            if (latestVersion.CompareTo(currentVersion) > 0) throw new InvalidDataException("Agent update authority returned an inconsistent decision");
            return null;
        }
        if (latestVersion.CompareTo(currentVersion) <= 0) throw new InvalidDataException("Agent update authority returned an invalid newer-version decision");

        var download = ValidateCatalogUrl(RequiredString(root, "downloadUrl"));
        string? notes = null;
        if (root.TryGetProperty("releaseNotes", out var notesValue) && notesValue.ValueKind != JsonValueKind.Null)
        {
            if (notesValue.ValueKind != JsonValueKind.String) throw new InvalidDataException("Agent update release notes are malformed");
            notes = notesValue.GetString();
        }
        var required = root.TryGetProperty("required", out var requiredValue) && requiredValue.ValueKind == JsonValueKind.True;
        return new UpdateOffer(current, latest, download, notes, required);
    }

    private static string Prompt(UpdateOffer offer, CancellationToken cancellationToken)
    {
        var executable = Path.GetFullPath(RuntimeBridgeContract.LicenseCenterExecutable);
        if (!File.Exists(executable)) throw new FileNotFoundException("native License Center is not installed", executable);
        var arguments = new List<string>
        {
            "--agent-update-prompt", "--current-version", offer.CurrentVersion, "--latest-version", offer.LatestVersion,
        };
        if (!string.IsNullOrWhiteSpace(offer.ReleaseNotes))
        {
            arguments.Add("--release-notes");
            arguments.Add(offer.ReleaseNotes[..Math.Min(2000, offer.ReleaseNotes.Length)]);
        }
        return WindowsInteractiveProcess.Run(executable, arguments, cancellationToken) switch
        {
            0 => "update",
            2 => "later",
            _ => throw new InvalidOperationException("Agent update prompt failed"),
        };
    }

    private async Task<string> DownloadAsync(UpdateOffer offer, CancellationToken cancellationToken)
    {
        var directory = Path.Combine(RuntimeBridgeContract.DataRoot, "self-update", "downloads");
        Directory.CreateDirectory(directory);
        var targetArchitecture = TargetArchitecture();
        var destination = Path.Combine(directory, $"BKE-Licensing-Agent-{offer.LatestVersion}-Windows-{targetArchitecture.AssetSuffix}.exe");
        var temporary = destination + ".download";
        if (File.Exists(temporary)) File.Delete(temporary);

        using var handler = new HttpClientHandler { AllowAutoRedirect = true, MaxAutomaticRedirections = 5 };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromMinutes(2) };
        using var request = new HttpRequestMessage(HttpMethod.Get, offer.DownloadUrl);
        request.Headers.UserAgent.ParseAdd($"BKE-Licensing-Agent/{offer.CurrentVersion}");
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        response.EnsureSuccessStatusCode();
        if (response.RequestMessage?.RequestUri is not Uri finalUri || !ApprovedRedirect(finalUri))
            throw new InvalidDataException("GitHub release redirected outside approved asset hosts");
        if (response.Content.Headers.ContentLength is long announced && announced > MaxInstallerBytes)
            throw new InvalidDataException("Agent installer exceeds the download limit");

        try
        {
            await using var input = await response.Content.ReadAsStreamAsync(cancellationToken);
            await using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                var buffer = new byte[1024 * 1024];
                long total = 0;
                while (true)
                {
                    var read = await input.ReadAsync(buffer.AsMemory(), cancellationToken);
                    if (read == 0) break;
                    total += read;
                    if (total > MaxInstallerBytes) throw new InvalidDataException("Agent installer exceeds the download limit");
                    await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
                }
                if (total < 2) throw new InvalidDataException("downloaded Agent installer is empty");
            }
            await using (var payload = File.OpenRead(temporary))
            {
                if (payload.ReadByte() != 'M' || payload.ReadByte() != 'Z') throw new InvalidDataException("downloaded Agent installer is not a Windows executable");
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

    private static void LaunchInstaller(string installer)
    {
        var stateRoot = Path.Combine(RuntimeBridgeContract.DataRoot, "self-update");
        Directory.CreateDirectory(stateRoot);
        var start = new ProcessStartInfo
        {
            FileName = installer,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        start.ArgumentList.Add("/VERYSILENT");
        start.ArgumentList.Add("/SUPPRESSMSGBOXES");
        start.ArgumentList.Add("/NORESTART");
        start.ArgumentList.Add($"/LOG={Path.Combine(stateRoot, "installer.log")}");
        _ = Process.Start(start) ?? throw new InvalidOperationException("Agent update installer did not start");
    }

    private static bool IsSuppressed(string latestVersion)
    {
        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(StatePath()));
            var root = document.RootElement;
            return root.TryGetProperty("latest_version", out var latest) && latest.GetString() == latestVersion &&
                   root.TryGetProperty("remind_after", out var remind) && DateTimeOffset.TryParse(remind.GetString(), out var until) &&
                   DateTimeOffset.UtcNow < until;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            return false;
        }
    }

    private static void Suppress(string latestVersion)
    {
        var path = StatePath();
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temporary = path + ".tmp";
        var json = JsonSerializer.Serialize(new Dictionary<string, string>
        {
            ["latest_version"] = latestVersion,
            ["remind_after"] = DateTimeOffset.UtcNow.Add(RemindAfter).ToString("O"),
        });
        File.WriteAllText(temporary, json, new UTF8Encoding(false));
        File.Move(temporary, path, true);
    }

    private static string StatePath() => Path.Combine(RuntimeBridgeContract.DataRoot, "self-update", "state.json");

    private static string CurrentVersion()
    {
        var configured = Environment.GetEnvironmentVariable("BKE_AGENT_SELF_UPDATE_VERSION");
        if (!string.IsNullOrWhiteSpace(configured)) return configured.Trim();
        var version = Assembly.GetEntryAssembly()?.GetName().Version;
        return version is null ? "1.0.0" : $"{version.Major}.{version.Minor}.{Math.Max(version.Build, 0)}";
    }

    private static (string QueryValue, string AssetSuffix) TargetArchitecture() =>
        RuntimeInformation.ProcessArchitecture switch
        {
            Architecture.X64 => ("x86_64", "x64"),
            Architecture.Arm64 => ("arm64", "arm64"),
            _ => throw new PlatformNotSupportedException(
                $"BKE Licensing Agent self-update does not support {RuntimeInformation.ProcessArchitecture} on Windows"),
        };

    private static Uri ValidateCatalogUrl(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps ||
            !string.Equals(uri.Host, "github.com", StringComparison.OrdinalIgnoreCase) ||
            !uri.AbsolutePath.StartsWith($"/{RuntimeBridgeContract.CatalogRepository}/releases/download/", StringComparison.Ordinal) ||
            !uri.AbsolutePath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Agent update URL is outside the BKE software catalog");
        return uri;
    }

    private static bool ApprovedRedirect(Uri uri) => uri.Scheme == Uri.UriSchemeHttps &&
        (string.Equals(uri.Host, "github.com", StringComparison.OrdinalIgnoreCase) || uri.Host.EndsWith(".githubusercontent.com", StringComparison.OrdinalIgnoreCase));

    private static string RequiredString(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(value.GetString()))
            throw new InvalidDataException($"Agent update response is missing {name}");
        return value.GetString()!;
    }

    private static void RequireString(JsonElement root, string name, string expected)
    {
        if (!string.Equals(RequiredString(root, name), expected, StringComparison.Ordinal))
            throw new InvalidDataException($"Agent update response {name} mismatch");
    }

    private sealed record UpdateOffer(string CurrentVersion, string LatestVersion, Uri DownloadUrl, string? ReleaseNotes, bool Required);
}
