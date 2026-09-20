using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace BKE.LicensingAgent.Infrastructure;

public sealed record MachineIdentity(
    string DeviceId,
    string Platform,
    string Architecture);

public static class MachineIdentityProvider
{
    private const string FingerprintSchemaVersion = "bke-device-v1";

    public static MachineIdentity Calculate()
    {
        string platform;
        string release;
        string architecture;

        if (OperatingSystem.IsWindows())
        {
            platform = "windows";
            var osVersion = Environment.OSVersion.Version;
            release = LegacyWindowsRelease(osVersion);
            architecture = (
                Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE") ??
                System.Runtime.InteropServices.RuntimeInformation.OSArchitecture.ToString()
            ).ToLowerInvariant();
        }
        else
        {
            platform = RunUname("-s").ToLowerInvariant();
            release = RunUname("-r").ToLowerInvariant();
            architecture = RunUname("-m").ToLowerInvariant();
        }

        var normalized =
            $"architecture={architecture.Trim().ToLowerInvariant()}|" +
            $"os_version={release.Trim().ToLowerInvariant()}|" +
            $"platform={platform.Trim().ToLowerInvariant()}";
        var digest = SHA256.HashData(
            Encoding.UTF8.GetBytes($"{FingerprintSchemaVersion}|{normalized}"));

        return new MachineIdentity(
            Convert.ToHexString(digest).ToLowerInvariant(),
            platform.Trim().ToLowerInvariant(),
            architecture.Trim().ToLowerInvariant());
    }

    public static string ProtocolPlatform(string platform)
    {
        var normalized = platform.Trim().ToLowerInvariant();
        return normalized switch
        {
            "windows" => "windows",
            "linux" => "linux",
            "darwin" or "macos" or "osx" => "macos",
            _ => throw new InvalidOperationException(
                $"Unsupported machine platform for BKE account session: {platform}"),
        };
    }

    public static string ProtocolArchitecture(string architecture)
    {
        var normalized = architecture.Trim().ToLowerInvariant();
        return normalized switch
        {
            "amd64" or "x86_64" or "x64" => "x64",
            "arm64" or "aarch64" => "arm64",
            "x86" or "i386" or "i686" => "x86",
            _ => throw new InvalidOperationException(
                $"Unsupported machine architecture for BKE account session: {architecture}"),
        };
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static string LegacyWindowsRelease(Version osVersion)
    {
        var productName = Microsoft.Win32.Registry.GetValue(
            @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "ProductName",
            null)?.ToString() ?? string.Empty;
        var isServer = productName.Contains("Server", StringComparison.OrdinalIgnoreCase);

        if (isServer && osVersion.Major >= 10)
        {
            if (osVersion.Build >= 26100) return "2025Server";
            if (osVersion.Build >= 20348) return "2022Server";
            if (osVersion.Build >= 17763) return "2019Server";
            if (osVersion.Build >= 14393) return "2016Server";
        }

        return osVersion.Major >= 10 && osVersion.Build >= 22000
            ? "11"
            : osVersion.Major >= 10 ? "10" : osVersion.Major.ToString();
    }

    private static string RunUname(string argument)
    {
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = "uname",
            Arguments = argument,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        }) ?? throw new InvalidOperationException("Could not execute uname");

        var output = process.StandardOutput.ReadToEnd().Trim();
        process.WaitForExit();
        if (process.ExitCode != 0 || string.IsNullOrWhiteSpace(output))
        {
            throw new InvalidOperationException("Could not resolve platform identity");
        }
        return output;
    }
}
