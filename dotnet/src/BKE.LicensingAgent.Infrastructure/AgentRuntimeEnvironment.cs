namespace BKE.LicensingAgent.Infrastructure;

public sealed record AgentRuntimeEnvironment(
    string Name,
    string EnvFilePath,
    string? PlatformBaseUrl);

public static class AgentRuntimeEnvironmentLoader
{
    public const string EnvironmentVariableName = "BKE_ENVIRONMENT";
    public const string PlatformBaseUrlVariableName = "BKE_PLATFORM_BASE_URL";
    public const string ProductionEnvironment = "production";
    public const string UtmEnvironment = "utm";

    private const long MaxEnvFileBytes = 64 * 1024;

    private static readonly HashSet<string> AllowedEnvironments =
        new(StringComparer.Ordinal)
        {
            ProductionEnvironment,
            UtmEnvironment,
            "development",
            "certification",
        };

    public static string DefaultEnvFilePath()
    {
        var programData = Environment.GetFolderPath(
            Environment.SpecialFolder.CommonApplicationData);

        if (string.IsNullOrWhiteSpace(programData))
        {
            throw new InvalidOperationException(
                "Common application data directory is unavailable.");
        }

        return Path.Combine(
            programData,
            "BKE Digital Solutions",
            "Licensing Agent",
            ".env");
    }

    public static AgentRuntimeEnvironment LoadDefault() =>
        Load(DefaultEnvFilePath());

    public static AgentRuntimeEnvironment Load(string envFilePath)
    {
        if (string.IsNullOrWhiteSpace(envFilePath))
        {
            throw new ArgumentException(
                "Agent environment file path is required.",
                nameof(envFilePath));
        }

        var fullPath = Path.GetFullPath(envFilePath);

        if (File.Exists(fullPath))
        {
            var info = new FileInfo(fullPath);
            if (info.Length > MaxEnvFileBytes)
            {
                throw new InvalidDataException(
                    "BKE Agent .env exceeds the maximum supported size.");
            }

            foreach (var pair in Parse(File.ReadAllText(fullPath)))
            {
                Environment.SetEnvironmentVariable(
                    pair.Key,
                    pair.Value,
                    EnvironmentVariableTarget.Process);
            }
        }

        var environment = (
            Environment.GetEnvironmentVariable(EnvironmentVariableName) ??
            ProductionEnvironment
        ).Trim().ToLowerInvariant();

        if (!AllowedEnvironments.Contains(environment))
        {
            throw new InvalidOperationException(
                "BKE_ENVIRONMENT must be production, utm, development, or certification.");
        }

        var platformBaseUrl =
            Environment.GetEnvironmentVariable(PlatformBaseUrlVariableName)?.Trim();

        if (environment == UtmEnvironment)
        {
            ValidateUtmPlatformBaseUrl(platformBaseUrl);
        }

        return new AgentRuntimeEnvironment(
            environment,
            fullPath,
            string.IsNullOrWhiteSpace(platformBaseUrl)
                ? null
                : platformBaseUrl.TrimEnd('/'));
    }

    public static IReadOnlyDictionary<string, string> Parse(string content)
    {
        if (content is null)
        {
            throw new ArgumentNullException(nameof(content));
        }

        var result = new Dictionary<string, string>(StringComparer.Ordinal);

        using var reader = new StringReader(content);
        string? rawLine;
        var lineNumber = 0;

        while ((rawLine = reader.ReadLine()) is not null)
        {
            lineNumber += 1;

            var line = rawLine.Trim();
            if (lineNumber == 1)
            {
                line = line.TrimStart('﻿');
            }

            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }

            if (line.StartsWith("export ", StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"BKE Agent .env line {lineNumber} must not use export syntax.");
            }

            var equals = line.IndexOf('=');
            if (equals <= 0)
            {
                throw new InvalidDataException(
                    $"BKE Agent .env line {lineNumber} is malformed.");
            }

            var key = line[..equals].Trim();
            var value = line[(equals + 1)..].Trim();

            if (!ValidKey(key))
            {
                throw new InvalidDataException(
                    $"BKE Agent .env line {lineNumber} has an invalid key.");
            }

            if (key == "BKE_AGENT_DATA_DIR")
            {
                throw new InvalidDataException(
                    "BKE_AGENT_DATA_DIR is installer-owned and must not be set in Agent .env.");
            }

            if (value.Length >= 2 &&
                ((value[0] == '"' && value[^1] == '"') ||
                 (value[0] == '\'' && value[^1] == '\'')))
            {
                value = value[1..^1];
            }
            else if (
                (value.StartsWith('"') && !value.EndsWith('"')) ||
                (value.StartsWith('\'') && !value.EndsWith('\'')))
            {
                throw new InvalidDataException(
                    $"BKE Agent .env line {lineNumber} has an unterminated quote.");
            }

            if (value.IndexOf('\0') >= 0)
            {
                throw new InvalidDataException(
                    $"BKE Agent .env line {lineNumber} contains a NUL character.");
            }

            if (!result.TryAdd(key, value))
            {
                throw new InvalidDataException(
                    $"BKE Agent .env contains duplicate key {key}.");
            }
        }

        return result;
    }

    private static void ValidateUtmPlatformBaseUrl(string? rawValue)
    {
        if (string.IsNullOrWhiteSpace(rawValue))
        {
            throw new InvalidOperationException(
                "BKE_PLATFORM_BASE_URL is required when BKE_ENVIRONMENT=utm.");
        }

        if (!Uri.TryCreate(rawValue, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttps &&
             uri.Scheme != Uri.UriSchemeHttp) ||
            !string.IsNullOrEmpty(uri.Query) ||
            !string.IsNullOrEmpty(uri.Fragment))
        {
            throw new InvalidOperationException(
                "UTM BKE_PLATFORM_BASE_URL must be an absolute HTTP(S) URL without query or fragment.");
        }

        var host = uri.Host.TrimEnd('.');
        if (host.Equals("jl-bke.com", StringComparison.OrdinalIgnoreCase) ||
            host.EndsWith(".jl-bke.com", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "UTM environment refuses the production jl-bke.com authority.");
        }
    }

    private static bool ValidKey(string value)
    {
        if (value.Length == 0 ||
            value[0] is < 'A' or > 'Z')
        {
            return false;
        }

        for (var index = 1; index < value.Length; index++)
        {
            var character = value[index];
            if (character is >= 'A' and <= 'Z' ||
                character is >= '0' and <= '9' ||
                character == '_')
            {
                continue;
            }

            return false;
        }

        return true;
    }
}
