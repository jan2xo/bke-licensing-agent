using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace BKE.LicensingAgent.Infrastructure;

public sealed class AgentSelfUpdateService : BackgroundService
{
    private const string AgentProductId = "bke-licensing-agent";
    private const string CatalogRepository = "jan2xo/bke-software-catalog";
    private const long MaxInstallerBytes = 512L * 1024L * 1024L;
    private static readonly TimeSpan InitialDelay = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan CheckInterval = TimeSpan.FromHours(6);
    private static readonly TimeSpan RemindAfter = TimeSpan.FromHours(24);

    private readonly ILogger<AgentSelfUpdateService> _logger;
    private readonly string _dataDir;
    private readonly Uri _platformBaseUri;
    private readonly string _currentVersion;

    public AgentSelfUpdateService(ILogger<AgentSelfUpdateService> logger)
    {
        _logger = logger;
        _dataDir = Environment.GetEnvironmentVariable("BKE_AGENT_DATA_DIR")
            ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "BKE Digital Solutions", "Licensing Agent");
        var baseUrl = (Environment.GetEnvironmentVariable("BKE_PLATFORM_BASE_URL") ?? "https://jl-bke.com").TrimEnd('/');
        if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var baseUri) ||
            !string.Equals(baseUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("BKE_PLATFORM_BASE_URL must be an HTTPS origin for Agent self-update.");
        }
        _platformBaseUri = baseUri;
        _currentVersion = ResolveCurrentVersion();
        _ = SemanticVersion.Parse(_currentVersion);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!OperatingSystem.IsWindows() ||
            Environment.GetEnvironmentVariable("BKE_AGENT_SELF_UPDATE_DISABLE") == "1")
        {
            return;
        }

        try
        {
            await Task.Delay(InitialDelay, stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            return;
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var outcome = await PollOnceAsync(stoppingToken);
                if (outcome == "update_started")
                {
                    _logger.LogInformation("BKE Licensing Agent self-update installer started");
                }
                else if (outcome == "later")
                {
                    _logger.LogInformation("BKE Licensing Agent self-update deferred by the active user");
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception exception)
            {
                _logger.LogWarning(exception, "BKE Licensing Agent self-update check failed");
            }

            try
            {
                await Task.Delay(CheckInterval, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
        }
    }

    internal async Task<string> PollOnceAsync(CancellationToken cancellationToken)
    {
        var offer = await CheckAsync(cancellationToken);
        if (offer is null)
        {
            return "up_to_date";
        }
        if (!offer.Required && Suppressed(offer))
        {
            return "suppressed";
        }

        var prompt = Prompt(offer, cancellationToken);
        if (prompt == "later" && !offer.Required)
        {
            Suppress(offer);
            return "later";
        }

        var installer = await DownloadAsync(offer, cancellationToken);
        LaunchInstaller(installer);
        return "update_started";
    }

    private async Task<AgentUpdateOffer?> CheckAsync(CancellationToken cancellationToken)
    {
        var requestUri = new UriBuilder(new Uri(_platformBaseUri, "/api/licensing-agent/update"))
        {
            Query = $"version={Uri.EscapeDataString(_currentVersion)}&platform=windows&architecture=x86_64",
        }.Uri;

        using var handler = new HttpClientHandler { AllowAutoRedirect = false };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
        using var request = new HttpRequestMessage(HttpMethod.Get, requestUri);
        request.Headers.Accept.ParseAdd("application/json");
        request.Headers.UserAgent.ParseAdd($"BKE-Licensing-Agent/{_currentVersion}");
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseContentRead, cancellationToken);
        response.EnsureSuccessStatusCode();
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object ||
            String(root, "productId") != AgentProductId ||
            String(root, "source") != "bke-software-catalog" ||
            String(root, "currentVersion") != _currentVersion)
        {
            throw new InvalidDataException("Agent update response identity mismatch");
        }

        var latest = String(root, "latestVersion");
        if (!root.TryGetProperty("updateAvailable", out var availableElement) ||
            availableElement.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
        {
            throw new InvalidDataException("Agent update response is malformed");
        }
        var currentVersion = SemanticVersion.Parse(_currentVersion);
        var latestVersion = SemanticVersion.Parse(latest);
        var available = availableElement.GetBoolean();
        if (!available)
        {
            if (latestVersion.CompareTo(currentVersion) > 0)
            {
                throw new InvalidDataException("Agent update authority returned an inconsistent decision");
            }
            return null;
        }
        if (latestVersion.CompareTo(currentVersion) <= 0)
        {
            throw new InvalidDataException("Agent update authority returned an invalid newer-version decision");
        }

        var downloadUrl = String(root, "downloadUrl");
        var releaseNotes = root.TryGetProperty("releaseNotes", out var notesElement) &&
            notesElement.ValueKind != JsonValueKind.Null
                ? notesElement.ValueKind == JsonValueKind.String
                    ? notesElement.GetString()
                    : throw new InvalidDataException("Agent update release notes are malformed")
                : null;
        var required = root.TryGetProperty("required", out var requiredElement) && requiredElement.ValueKind == JsonValueKind.True;
        return new AgentUpdateOffer(_currentVersion, latest, ValidateCatalogUrl(downloadUrl), releaseNotes, required);
    }

    private bool Suppressed(AgentUpdateOffer offer)
    {
        var state = ReadState();
        if (!state.TryGetValue("latest_version", out var latest) || latest != offer.LatestVersion ||
            !state.TryGetValue("remind_after", out var remindAfter) ||
            !DateTimeOffset.TryParse(remindAfter, out var parsed))
        {
            return false;
        }
        return DateTimeOffset.UtcNow < parsed;
    }

    private void Suppress(AgentUpdateOffer offer)
    {
        var root = SelfUpdateRoot();
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, "state.json");
        var temporary = path + ".tmp";
        var document = JsonSerializer.Serialize(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["latest_version"] = offer.LatestVersion,
            ["remind_after"] = DateTimeOffset.UtcNow.Add(RemindAfter).ToString("O"),
        });
        File.WriteAllText(temporary, document, new UTF8Encoding(false));
        File.Move(temporary, path, true);
    }

    private Dictionary<string, string> ReadState()
    {
        var path = Path.Combine(SelfUpdateRoot(), "state.json");
        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(path));
            return document.RootElement.ValueKind == JsonValueKind.Object
                ? document.RootElement.EnumerateObject()
                    .Where(item => item.Value.ValueKind == JsonValueKind.String)
                    .ToDictionary(item => item.Name, item => item.Value.GetString()!, StringComparer.Ordinal)
                : new Dictionary<string, string>(StringComparer.Ordinal);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            return new Dictionary<string, string>(StringComparer.Ordinal);
        }
    }

    private string Prompt(AgentUpdateOffer offer, CancellationToken cancellationToken)
    {
        var executable = ResolveLicenseCenter();
        if (!File.Exists(executable))
        {
            throw new FileNotFoundException("native License Center is not installed", executable);
        }
        var arguments = new List<string>
        {
            "--agent-update-prompt",
            "--current-version", offer.CurrentVersion,
            "--latest-version", offer.LatestVersion,
        };
        if (!string.IsNullOrWhiteSpace(offer.ReleaseNotes))
        {
            arguments.Add("--release-notes");
            arguments.Add(offer.ReleaseNotes[..Math.Min(2000, offer.ReleaseNotes.Length)]);
        }
        var exitCode = RunWindowsInteractive(executable, arguments, cancellationToken);
        return exitCode switch
        {
            0 => "update",
            2 => "later",
            _ => throw new InvalidOperationException("Agent update prompt failed"),
        };
    }

    private async Task<string> DownloadAsync(AgentUpdateOffer offer, CancellationToken cancellationToken)
    {
        var source = ValidateCatalogUrl(offer.DownloadUrl);
        var root = Path.Combine(SelfUpdateRoot(), "downloads");
        Directory.CreateDirectory(root);
        var destination = Path.Combine(root, $"BKE-Licensing-Agent-{offer.LatestVersion}-Windows-x64.exe");
        var temporary = destination + ".download";
        if (File.Exists(temporary)) File.Delete(temporary);

        using var handler = new HttpClientHandler { AllowAutoRedirect = true, MaxAutomaticRedirections = 5 };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromMinutes(2) };
        using var request = new HttpRequestMessage(HttpMethod.Get, source);
        request.Headers.UserAgent.ParseAdd($"BKE-Licensing-Agent/{_currentVersion}");
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        response.EnsureSuccessStatusCode();
        if (response.RequestMessage?.RequestUri is not Uri finalUri || !ApprovedRedirect(finalUri))
        {
            throw new InvalidDataException("GitHub release redirected outside approved asset hosts");
        }
        if (response.Content.Headers.ContentLength is long announced && announced > MaxInstallerBytes)
        {
            throw new InvalidDataException("Agent installer exceeds the download limit");
        }

        try
        {
            await using var input = await response.Content.ReadAsStreamAsync(cancellationToken);
            await using var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            var buffer = new byte[1024 * 1024];
            long count = 0;
            while (true)
            {
                var read = await input.ReadAsync(buffer.AsMemory(), cancellationToken);
                if (read == 0) break;
                count += read;
                if (count > MaxInstallerBytes) throw new InvalidDataException("Agent installer exceeds the download limit");
                await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
            }
            await output.FlushAsync(cancellationToken);
            if (count < 2) throw new InvalidDataException("downloaded Agent installer is empty");
            output.Close();
            await using var payload = File.OpenRead(temporary);
            if (payload.ReadByte() != 'M' || payload.ReadByte() != 'Z')
            {
                throw new InvalidDataException("downloaded Agent installer is not a Windows executable");
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

    private void LaunchInstaller(string installer)
    {
        var logPath = Path.Combine(SelfUpdateRoot(), "installer.log");
        Directory.CreateDirectory(SelfUpdateRoot());
        var start = new ProcessStartInfo
        {
            FileName = installer,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        start.ArgumentList.Add("/VERYSILENT");
        start.ArgumentList.Add("/SUPPRESSMSGBOXES");
        start.ArgumentList.Add("/NORESTART");
        start.ArgumentList.Add($"/LOG={logPath}");
        _ = Process.Start(start) ?? throw new InvalidOperationException("Agent self-update installer did not start");
    }

    private string SelfUpdateRoot() => Path.Combine(_dataDir, "self-update");

    private static string ResolveCurrentVersion()
    {
        var configured = Environment.GetEnvironmentVariable("BKE_AGENT_SELF_UPDATE_VERSION");
        if (!string.IsNullOrWhiteSpace(configured)) return configured.Trim();
        var version = Assembly.GetEntryAssembly()?.GetName().Version ??
            typeof(AgentSelfUpdateService).Assembly.GetName().Version;
        return version is null ? "1.0.0" : $"{version.Major}.{version.Minor}.{Math.Max(version.Build, 0)}";
    }

    private static string ResolveLicenseCenter()
    {
        var agentDirectory = Path.GetFullPath(AppContext.BaseDirectory);
        var parent = Directory.GetParent(agentDirectory)?.FullName;
        var candidates = new List<string> { Path.Combine(agentDirectory, "bke-license-center.exe") };
        if (parent is not null)
        {
            candidates.Add(Path.Combine(parent, "license-center", "bke-license-center.exe"));
            candidates.Add(Path.Combine(parent, "bke-license-center", "bke-license-center.exe"));
        }
        return candidates.FirstOrDefault(File.Exists) ?? candidates[0];
    }

    private static Uri ValidateCatalogUrl(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
            !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(uri.Host, "github.com", StringComparison.OrdinalIgnoreCase) ||
            !uri.AbsolutePath.StartsWith($"/{CatalogRepository}/releases/download/", StringComparison.Ordinal) ||
            !uri.AbsolutePath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Agent update URL is outside the BKE software catalog");
        }
        return uri;
    }

    private static bool ApprovedRedirect(Uri uri) =>
        string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) &&
        (string.Equals(uri.Host, "github.com", StringComparison.OrdinalIgnoreCase) ||
         uri.Host.EndsWith(".githubusercontent.com", StringComparison.OrdinalIgnoreCase));

    private static string String(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.String ||
            string.IsNullOrWhiteSpace(value.GetString()))
        {
            throw new InvalidDataException($"Agent update response is missing {name}");
        }
        return value.GetString()!;
    }

    private static int RunWindowsInteractive(string executable, IReadOnlyList<string> arguments, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var sessionId = Native.WTSGetActiveConsoleSessionId();
        if (sessionId == uint.MaxValue) throw new Win32Exception("No active Windows console session is available");
        IntPtr token = IntPtr.Zero;
        IntPtr environment = IntPtr.Zero;
        var processInfo = new Native.PROCESS_INFORMATION();
        var environmentCreated = false;
        try
        {
            if (!Native.WTSQueryUserToken(sessionId, out token)) throw LastError("Could not obtain active user token");
            if (!Native.CreateEnvironmentBlock(out environment, token, false)) throw LastError("Could not build active user environment");
            environmentCreated = true;
            var startupInfo = new Native.STARTUPINFO
            {
                cb = Marshal.SizeOf<Native.STARTUPINFO>(),
                lpDesktop = "winsta0\\default",
            };
            var command = new StringBuilder(Quote(executable));
            foreach (var argument in arguments) command.Append(' ').Append(Quote(argument));
            const uint CreateUnicodeEnvironment = 0x00000400;
            if (!Native.CreateProcessAsUserW(token, executable, command, IntPtr.Zero, IntPtr.Zero, false,
                    CreateUnicodeEnvironment, environment, Path.GetDirectoryName(Path.GetFullPath(executable)),
                    ref startupInfo, out processInfo))
            {
                throw LastError("Could not launch Agent update prompt");
            }
            const uint Infinite = 0xffffffff;
            const uint WaitFailed = 0xffffffff;
            if (Native.WaitForSingleObject(processInfo.hProcess, Infinite) == WaitFailed) throw LastError("Could not wait for Agent update prompt");
            if (!Native.GetExitCodeProcess(processInfo.hProcess, out var exitCode)) throw LastError("Could not read Agent update prompt status");
            return checked((int)exitCode);
        }
        finally
        {
            if (processInfo.hThread != IntPtr.Zero) Native.CloseHandle(processInfo.hThread);
            if (processInfo.hProcess != IntPtr.Zero) Native.CloseHandle(processInfo.hProcess);
            if (environmentCreated && environment != IntPtr.Zero) Native.DestroyEnvironmentBlock(environment);
            if (token != IntPtr.Zero) Native.CloseHandle(token);
        }
    }

    private static Exception LastError(string message)
    {
        var error = Marshal.GetLastWin32Error();
        return new Win32Exception(error, $"{message} (Windows error {error})");
    }

    private static string Quote(string value)
    {
        if (value.Length > 0 && !value.Any(char.IsWhiteSpace) && !value.Contains('"')) return value;
        var builder = new StringBuilder("\"");
        var backslashes = 0;
        foreach (var character in value)
        {
            if (character == '\\') { backslashes++; continue; }
            if (character == '"')
            {
                builder.Append('\\', backslashes * 2 + 1).Append('"');
                backslashes = 0;
                continue;
            }
            builder.Append('\\', backslashes);
            backslashes = 0;
            builder.Append(character);
        }
        builder.Append('\\', backslashes * 2).Append('"');
        return builder.ToString();
    }

    private sealed record AgentUpdateOffer(string CurrentVersion, string LatestVersion, Uri DownloadUrl, string? ReleaseNotes, bool Required);

    private sealed record SemanticVersion(int Major, int Minor, int Patch, string? PreRelease) : IComparable<SemanticVersion>
    {
        private static readonly Regex Pattern = new(
            "^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z.-]+))?(?:\\+[0-9A-Za-z.-]+)?$",
            RegexOptions.CultureInvariant);

        internal static SemanticVersion Parse(string value)
        {
            var match = Pattern.Match(value);
            if (!match.Success) throw new InvalidDataException("invalid Agent semantic version");
            return new SemanticVersion(int.Parse(match.Groups[1].Value), int.Parse(match.Groups[2].Value),
                int.Parse(match.Groups[3].Value), match.Groups[4].Success ? match.Groups[4].Value : null);
        }

        public int CompareTo(SemanticVersion? other)
        {
            if (other is null) return 1;
            var core = Major.CompareTo(other.Major);
            if (core == 0) core = Minor.CompareTo(other.Minor);
            if (core == 0) core = Patch.CompareTo(other.Patch);
            if (core != 0) return core;
            if (PreRelease is null) return other.PreRelease is null ? 0 : 1;
            if (other.PreRelease is null) return -1;
            var left = PreRelease.Split('.');
            var right = other.PreRelease.Split('.');
            for (var index = 0; index < Math.Max(left.Length, right.Length); index++)
            {
                if (index >= left.Length) return -1;
                if (index >= right.Length) return 1;
                var leftNumeric = int.TryParse(left[index], out var leftNumber);
                var rightNumeric = int.TryParse(right[index], out var rightNumber);
                int compared;
                if (leftNumeric && rightNumeric) compared = leftNumber.CompareTo(rightNumber);
                else if (leftNumeric) compared = -1;
                else if (rightNumeric) compared = 1;
                else compared = string.CompareOrdinal(left[index], right[index]);
                if (compared != 0) return compared;
            }
            return 0;
        }
    }

    private static class Native
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct STARTUPINFO
        {
            internal int cb;
            internal string? lpReserved;
            internal string? lpDesktop;
            internal string? lpTitle;
            internal int dwX;
            internal int dwY;
            internal int dwXSize;
            internal int dwYSize;
            internal int dwXCountChars;
            internal int dwYCountChars;
            internal int dwFillAttribute;
            internal int dwFlags;
            internal short wShowWindow;
            internal short cbReserved2;
            internal IntPtr lpReserved2;
            internal IntPtr hStdInput;
            internal IntPtr hStdOutput;
            internal IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            internal IntPtr hProcess;
            internal IntPtr hThread;
            internal uint dwProcessId;
            internal uint dwThreadId;
        }

        [DllImport("kernel32.dll")]
        internal static extern uint WTSGetActiveConsoleSessionId();

        [DllImport("Wtsapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool WTSQueryUserToken(uint sessionId, out IntPtr token);

        [DllImport("userenv.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CreateEnvironmentBlock(out IntPtr environment, IntPtr token, bool inherit);

        [DllImport("userenv.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool DestroyEnvironmentBlock(IntPtr environment);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CreateProcessAsUserW(IntPtr token, string? applicationName, StringBuilder commandLine,
            IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint creationFlags,
            IntPtr environment, string? currentDirectory, ref STARTUPINFO startupInfo,
            out PROCESS_INFORMATION processInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseHandle(IntPtr handle);
    }
}
