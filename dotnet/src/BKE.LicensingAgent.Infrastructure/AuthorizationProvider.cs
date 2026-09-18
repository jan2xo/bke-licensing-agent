using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;
using Microsoft.Data.Sqlite;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.OpenSsl;

namespace BKE.LicensingAgent.Infrastructure;

public sealed class AuthorizationProvider : IAuthorizationService
{
    private const string FingerprintSchemaVersion = "bke-device-v1";
    private const int ExpectedSchemaVersion = 8;
    private static readonly Regex ProductIdPattern = new("^[a-z0-9-]+$", RegexOptions.CultureInvariant);
    private static readonly Regex VersionPattern = new("^\\d+\\.\\d+\\.\\d+(?:[-+].*)?$", RegexOptions.CultureInvariant);

    private readonly string _dataDir;
    private readonly int _port;

    public AuthorizationProvider()
    {
        _dataDir = Environment.GetEnvironmentVariable("BKE_AGENT_DATA_DIR")
            ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "share", "bke_licensing_agent");
        _port = int.TryParse(Environment.GetEnvironmentVariable("BKE_AGENT_PORT"), out var configuredPort)
            ? configuredPort
            : LocalAgentContract.DefaultPort;
    }

    public Task<AuthorizationResponse> AuthorizeAsync(
        AuthorizeRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            return Task.FromResult(Authorize(request));
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return Task.FromResult(new AuthorizationResponse(false, "authorization_provider_unavailable"));
        }
    }

    private AuthorizationResponse Authorize(AuthorizeRequest request)
    {
        var databasePath = Path.Combine(_dataDir, "agent.db");
        if (!File.Exists(databasePath))
        {
            return new AuthorizationResponse(false, "unknown_product_or_version");
        }

        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadOnly,
            Cache = SqliteCacheMode.Private,
        }.ToString());
        connection.Open();

        if (ReadSchemaVersion(connection) != ExpectedSchemaVersion)
        {
            return new AuthorizationResponse(false, "authorization_provider_unavailable");
        }

        var product = LoadDiscoveredProduct(connection, request.ProductId, request.Version);
        if (product is null || !ValidateManifest(product, request.ProductId, request.Version))
        {
            return new AuthorizationResponse(false, "unknown_product_or_version");
        }

        var deviceId = CalculateDeviceFingerprint();
        var binding = LoadActiveBinding(connection, request.ProductId, request.InstallationId, deviceId);
        if (binding is null)
        {
            return new AuthorizationResponse(
                false,
                "activation_required",
                LicenseCenterUrl(request.ProductId, request.Version, request.InstallationId));
        }

        var trustedKeys = LoadTrustedKeys();
        if (trustedKeys.Count == 0)
        {
            return new AuthorizationResponse(false, "trusted_keys_unavailable");
        }

        try
        {
            var activeRecord = LoadActiveVerifiedLicense(connection, binding.ActiveLicenseId);
            if (activeRecord is null || !BindingMatchesRecord(binding, activeRecord))
            {
                return new AuthorizationResponse(false, "lease_authority_mismatch");
            }

            var signedRecord = LoadLeaseRecord(connection, binding.ActiveLeaseId);
            if (signedRecord is null)
            {
                return new AuthorizationResponse(false, "lease_authority_mismatch");
            }

            var lease = VerifySignedLease(signedRecord, trustedKeys);

            if (lease.Revoked)
            {
                return new AuthorizationResponse(false, "lease_revoked");
            }
            if (lease.SupersededBy is not null)
            {
                return new AuthorizationResponse(false, "lease_superseded");
            }
            if (!string.Equals(lease.Version, request.Version, StringComparison.Ordinal))
            {
                return new AuthorizationResponse(false, "lease_version_rejected");
            }
            if (!LeaseMatchesStoredAuthority(lease, signedRecord, request, deviceId))
            {
                return new AuthorizationResponse(false, "lease_authority_mismatch");
            }
            if (lease.LeaseId != activeRecord.LeaseId ||
                lease.Generation != activeRecord.Generation ||
                lease.ServerRevision != activeRecord.ServerRevision)
            {
                return new AuthorizationResponse(false, "lease_authority_mismatch");
            }

            var now = DateTimeOffset.UtcNow;
            var skew = TimeSpan.FromSeconds(30);
            if (now + skew < lease.NotBefore)
            {
                return new AuthorizationResponse(false, "lease_not_yet_valid");
            }
            if (now - skew >= lease.ExpiresAt)
            {
                return new AuthorizationResponse(false, "lease_expired");
            }

            return new AuthorizationResponse(true, "authorized");
        }
        catch
        {
            return new AuthorizationResponse(false, "unverifiable_signed_lease");
        }
    }

    private static int ReadSchemaVersion(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT version FROM schema_version LIMIT 1";
        var value = command.ExecuteScalar();
        return value is long version ? checked((int)version) : Convert.ToInt32(value);
    }

    private static DiscoveredProduct? LoadDiscoveredProduct(SqliteConnection connection, string productId, string version)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT product_id, version, manifest_path, product_root, entry_point_path
            FROM discovered_products
            WHERE product_id = $product_id AND version = $version
            ORDER BY discovered_at DESC
            LIMIT 1
            """;
        command.Parameters.AddWithValue("$product_id", productId);
        command.Parameters.AddWithValue("$version", version);
        using var reader = command.ExecuteReader();
        return reader.Read()
            ? new DiscoveredProduct(
                reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3), reader.GetString(4))
            : null;
    }

    private static ActiveBinding? LoadActiveBinding(
        SqliteConnection connection,
        string productId,
        string installationId,
        string deviceId)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT product_id, installation_id, device_id, active_license_id, active_lease_id,
                   generation, server_revision, binding_version
            FROM active_license_bindings
            WHERE product_id = $product_id AND installation_id = $installation_id AND device_id = $device_id
            """;
        command.Parameters.AddWithValue("$product_id", productId);
        command.Parameters.AddWithValue("$installation_id", installationId);
        command.Parameters.AddWithValue("$device_id", deviceId);
        using var reader = command.ExecuteReader();
        return reader.Read()
            ? new ActiveBinding(
                reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3), reader.GetString(4),
                reader.GetInt32(5), reader.GetInt32(6), reader.GetInt32(7))
            : null;
    }

    private static LicenseRecord? LoadActiveVerifiedLicense(SqliteConnection connection, string licenseId)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT license_id, product_id, product_version, installation_id, device_id, lease_id,
                   generation, server_revision, issued_at, not_before, expires_at, status, key_id,
                   signed_payload, signed_signature, signed_algorithm
            FROM verified_licenses
            WHERE license_id = $license_id
            ORDER BY updated_at DESC
            LIMIT 1
            """;
        command.Parameters.AddWithValue("$license_id", licenseId);
        return ReadLicenseRecord(command);
    }

    private static LicenseRecord? LoadLeaseRecord(SqliteConnection connection, string leaseId)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT license_id, product_id, product_version, installation_id, device_id, lease_id,
                   generation, server_revision, issued_at, not_before, expires_at, status, key_id,
                   signed_payload, signed_signature, signed_algorithm
            FROM verified_licenses
            WHERE lease_id = $lease_id
            LIMIT 1
            """;
        command.Parameters.AddWithValue("$lease_id", leaseId);
        return ReadLicenseRecord(command);
    }

    private static LicenseRecord? ReadLicenseRecord(SqliteCommand command)
    {
        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return null;
        }
        return new LicenseRecord(
            reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3), reader.GetString(4),
            reader.GetString(5), reader.GetInt32(6), reader.GetInt32(7), reader.GetString(8), reader.GetString(9),
            reader.GetString(10), reader.GetString(11), reader.GetString(12),
            reader.IsDBNull(13) ? null : reader.GetString(13),
            reader.IsDBNull(14) ? null : reader.GetString(14),
            reader.IsDBNull(15) ? null : reader.GetString(15));
    }

    private static bool BindingMatchesRecord(ActiveBinding binding, LicenseRecord record) =>
        record.LicenseId == binding.ActiveLicenseId &&
        record.ProductId == binding.ProductId &&
        record.InstallationId == binding.InstallationId &&
        record.DeviceId == binding.DeviceId &&
        record.LeaseId == binding.ActiveLeaseId &&
        record.Generation == binding.Generation &&
        record.ServerRevision == binding.ServerRevision;

    private Dictionary<string, string> LoadTrustedKeys()
    {
        var directory = Path.Combine(_dataDir, "trusted-keys");
        if (!Directory.Exists(directory))
        {
            return new Dictionary<string, string>(StringComparer.Ordinal);
        }
        return Directory.EnumerateFiles(directory, "*.pem", SearchOption.TopDirectoryOnly)
            .OrderBy(path => path, StringComparer.Ordinal)
            .ToDictionary(
                path => Path.GetFileNameWithoutExtension(path),
                File.ReadAllText,
                StringComparer.Ordinal);
    }

    private static LeasePayload VerifySignedLease(LicenseRecord record, IReadOnlyDictionary<string, string> trustedKeys)
    {
        if (string.IsNullOrEmpty(record.SignedPayload) ||
            string.IsNullOrEmpty(record.SignedSignature) ||
            string.IsNullOrEmpty(record.SignedAlgorithm))
        {
            throw new InvalidDataException("Signed lease envelope is missing");
        }
        if (!string.Equals(record.SignedAlgorithm, "Ed25519", StringComparison.Ordinal))
        {
            throw new InvalidDataException("Unsupported lease signature algorithm");
        }
        if (!trustedKeys.TryGetValue(record.KeyId, out var pem))
        {
            throw new InvalidDataException("Lease signing key is not trusted");
        }

        using var textReader = new StringReader(pem);
        var keyObject = new PemReader(textReader).ReadObject();
        if (keyObject is not Ed25519PublicKeyParameters publicKey)
        {
            throw new InvalidDataException("Trusted key is not Ed25519");
        }

        var signature = Convert.FromBase64String(record.SignedSignature);
        var payloadBytes = Encoding.UTF8.GetBytes(record.SignedPayload);
        var verifier = new Ed25519Signer();
        verifier.Init(false, publicKey);
        verifier.BlockUpdate(payloadBytes, 0, payloadBytes.Length);
        if (!verifier.VerifySignature(signature))
        {
            throw new CryptographicException("Lease signature is invalid");
        }

        return ParseLeasePayload(record.SignedPayload);
    }

    private static LeasePayload ParseLeasePayload(string payload)
    {
        using var document = JsonDocument.Parse(payload);
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException("Malformed lease payload");
        }

        var allowed = new HashSet<string>(StringComparer.Ordinal)
        {
            "license_id", "lease_id", "generation", "server_revision", "product_id", "installation_id",
            "device_id", "version", "issuer", "issued_at", "not_before", "expires_at", "key_id", "algorithm",
            "revoked", "superseded_by"
        };
        foreach (var property in root.EnumerateObject())
        {
            if (!allowed.Contains(property.Name))
            {
                throw new InvalidDataException("Malformed lease payload");
            }
        }

        var lease = new LeasePayload(
            RequiredString(root, "license_id"),
            RequiredString(root, "lease_id"),
            RequiredNonNegativeInt(root, "generation"),
            OptionalNonNegativeInt(root, "server_revision", 0),
            RequiredString(root, "product_id"),
            RequiredString(root, "installation_id"),
            RequiredString(root, "device_id"),
            RequiredString(root, "version"),
            RequiredString(root, "issuer"),
            RequiredDateTime(root, "issued_at"),
            RequiredDateTime(root, "not_before"),
            RequiredDateTime(root, "expires_at"),
            RequiredString(root, "key_id"),
            RequiredString(root, "algorithm"),
            OptionalBoolean(root, "revoked", false),
            OptionalNullableString(root, "superseded_by"));

        return lease;
    }

    private static bool LeaseMatchesStoredAuthority(
        LeasePayload lease,
        LicenseRecord record,
        AuthorizeRequest request,
        string deviceId) =>
        lease.LicenseId == record.LicenseId &&
        lease.LeaseId == record.LeaseId &&
        lease.ProductId == request.ProductId &&
        lease.InstallationId == request.InstallationId &&
        lease.DeviceId == deviceId &&
        lease.Generation == record.Generation &&
        lease.ServerRevision == record.ServerRevision &&
        lease.KeyId == record.KeyId &&
        lease.Algorithm == record.SignedAlgorithm;

    private static bool ValidateManifest(DiscoveredProduct record, string productId, string version)
    {
        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(record.ManifestPath));
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            var allowed = new HashSet<string>(StringComparer.Ordinal)
            {
                "schemaVersion", "productId", "displayName", "publisher", "version", "entryPoint", "icon",
                "updateChannel", "minimumAgentVersion", "platform", "architecture"
            };
            foreach (var property in root.EnumerateObject())
            {
                if (!allowed.Contains(property.Name))
                {
                    return false;
                }
            }

            if (!root.TryGetProperty("schemaVersion", out var schemaVersion) || schemaVersion.ValueKind != JsonValueKind.Number || schemaVersion.GetInt32() != 1)
            {
                return false;
            }
            var manifestProductId = RequiredString(root, "productId");
            var displayName = RequiredString(root, "displayName");
            var manifestVersion = RequiredString(root, "version");
            var entryPoint = RequiredString(root, "entryPoint");
            var updateChannel = RequiredString(root, "updateChannel");
            var minimumAgentVersion = RequiredString(root, "minimumAgentVersion");
            var platform = RequiredString(root, "platform");
            var architecture = RequiredString(root, "architecture");

            if (!ProductIdPattern.IsMatch(manifestProductId) || displayName.Length == 0 ||
                !VersionPattern.IsMatch(manifestVersion) || !VersionPattern.IsMatch(minimumAgentVersion) ||
                !new[] { "stable", "beta", "alpha" }.Contains(updateChannel, StringComparer.Ordinal) ||
                !new[] { "windows", "macos", "linux" }.Contains(platform, StringComparer.Ordinal) ||
                !new[] { "x86", "x64", "arm64" }.Contains(architecture, StringComparer.Ordinal) ||
                !ValidRelativePath(entryPoint))
            {
                return false;
            }

            if (root.TryGetProperty("publisher", out var publisher) && (publisher.ValueKind != JsonValueKind.String || string.IsNullOrEmpty(publisher.GetString())))
            {
                return false;
            }
            if (root.TryGetProperty("icon", out var icon) &&
                (icon.ValueKind != JsonValueKind.String || string.IsNullOrEmpty(icon.GetString()) || !ValidRelativePath(icon.GetString()!)))
            {
                return false;
            }

            if (manifestProductId != productId || manifestVersion != version ||
                record.ProductId != productId || record.Version != version)
            {
                return false;
            }

            var expectedEntryPoint = Path.GetFullPath(Path.Combine(record.ProductRoot, entryPoint));
            var recordedEntryPoint = Path.GetFullPath(record.EntryPointPath);
            var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
            return string.Equals(expectedEntryPoint, recordedEntryPoint, comparison);
        }
        catch
        {
            return false;
        }
    }

    private static bool ValidRelativePath(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.StartsWith('/') || value.StartsWith('\\') ||
            (value.Length >= 2 && value[1] == ':'))
        {
            return false;
        }
        return !value.Replace('\\', '/').Split('/').Contains("..", StringComparer.Ordinal);
    }

    private string LicenseCenterUrl(string productId, string version, string installationId) =>
        $"http://127.0.0.1:{_port}/license-center?product_id={Uri.EscapeDataString(productId)}&version={Uri.EscapeDataString(version)}&installation_id={Uri.EscapeDataString(installationId)}";

    private static string CalculateDeviceFingerprint()
    {
        string platform;
        string release;
        string architecture;

        if (OperatingSystem.IsWindows())
        {
            platform = "windows";
            var osVersion = Environment.OSVersion.Version;
            release = LegacyWindowsRelease(osVersion);
            architecture = (Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE") ??
                            System.Runtime.InteropServices.RuntimeInformation.OSArchitecture.ToString()).ToLowerInvariant();
        }
        else
        {
            platform = RunUname("-s").ToLowerInvariant();
            release = RunUname("-r").ToLowerInvariant();
            architecture = RunUname("-m").ToLowerInvariant();
        }

        var normalized = $"architecture={architecture.Trim().ToLowerInvariant()}|os_version={release.Trim().ToLowerInvariant()}|platform={platform.Trim().ToLowerInvariant()}";
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes($"{FingerprintSchemaVersion}|{normalized}"));
        return Convert.ToHexString(digest).ToLowerInvariant();
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

    private static string RequiredString(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.String || string.IsNullOrEmpty(value.GetString()))
        {
            throw new InvalidDataException($"Missing or invalid {name}");
        }
        return value.GetString()!;
    }

    private static int RequiredNonNegativeInt(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.Number || !value.TryGetInt32(out var result) || result < 0)
        {
            throw new InvalidDataException($"Missing or invalid {name}");
        }
        return result;
    }

    private static int OptionalNonNegativeInt(JsonElement root, string name, int fallback)
    {
        if (!root.TryGetProperty(name, out var value))
        {
            return fallback;
        }
        if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt32(out var result) || result < 0)
        {
            throw new InvalidDataException($"Invalid {name}");
        }
        return result;
    }

    private static DateTimeOffset RequiredDateTime(JsonElement root, string name)
    {
        var text = RequiredString(root, name);
        return DateTimeOffset.TryParse(text, System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.RoundtripKind, out var result)
            ? result
            : throw new InvalidDataException($"Invalid {name}");
    }

    private static bool OptionalBoolean(JsonElement root, string name, bool fallback)
    {
        if (!root.TryGetProperty(name, out var value))
        {
            return fallback;
        }
        return value.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => throw new InvalidDataException($"Invalid {name}"),
        };
    }

    private static string? OptionalNullableString(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }
        if (value.ValueKind != JsonValueKind.String)
        {
            throw new InvalidDataException($"Invalid {name}");
        }
        return value.GetString();
    }

    private sealed record DiscoveredProduct(string ProductId, string Version, string ManifestPath, string ProductRoot, string EntryPointPath);
    private sealed record ActiveBinding(
        string ProductId, string InstallationId, string DeviceId, string ActiveLicenseId, string ActiveLeaseId,
        int Generation, int ServerRevision, int BindingVersion);
    private sealed record LicenseRecord(
        string LicenseId, string ProductId, string ProductVersion, string InstallationId, string DeviceId, string LeaseId,
        int Generation, int ServerRevision, string IssuedAt, string NotBefore, string ExpiresAt, string Status, string KeyId,
        string? SignedPayload, string? SignedSignature, string? SignedAlgorithm);
    private sealed record LeasePayload(
        string LicenseId, string LeaseId, int Generation, int ServerRevision, string ProductId, string InstallationId,
        string DeviceId, string Version, string Issuer, DateTimeOffset IssuedAt, DateTimeOffset NotBefore,
        DateTimeOffset ExpiresAt, string KeyId, string Algorithm, bool Revoked, string? SupersededBy);
}
