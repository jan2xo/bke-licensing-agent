using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;
using Microsoft.Data.Sqlite;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.OpenSsl;

namespace BKE.LicensingAgent.Infrastructure;

public sealed class ActivationProvider : IActivationService
{
    private const string FingerprintSchemaVersion = "bke-device-v1";
    private const int ExpectedSchemaVersion = 8;
    private static readonly HashSet<HttpStatusCode> RetryableStatuses = new()
    {
        HttpStatusCode.RequestTimeout,
        (HttpStatusCode)425,
        (HttpStatusCode)429,
        HttpStatusCode.InternalServerError,
        HttpStatusCode.BadGateway,
        HttpStatusCode.ServiceUnavailable,
        HttpStatusCode.GatewayTimeout,
    };

    private readonly AuthorizationProvider _authorization;
    private readonly string _dataDir;
    private readonly string _platformBaseUrl;
    private readonly HttpClient _http;

    public ActivationProvider(AuthorizationProvider authorization)
    {
        _authorization = authorization;
        _dataDir = Environment.GetEnvironmentVariable("BKE_AGENT_DATA_DIR")
            ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "share", "bke_licensing_agent");
        _platformBaseUrl = (Environment.GetEnvironmentVariable("BKE_PLATFORM_BASE_URL") ?? "https://jl-bke.com").TrimEnd('/');
        ValidatePlatformBaseUrl(_platformBaseUrl);
        _http = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(20),
        };
    }

    public async Task<AuthorizationResponse> ActivateAsync(
        ActivateRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var context = await _authorization.AuthorizeAsync(
            new AuthorizeRequest(request.ProductId, request.Version, request.InstallationId),
            cancellationToken);
        if (context.Reason == "unknown_product_or_version")
        {
            return new AuthorizationResponse(false, "invalid_product_context");
        }
        if (context.Reason == "authorization_provider_unavailable")
        {
            return new AuthorizationResponse(false, "activation_failed");
        }

        if (request.InstallationId.Length is < 32 or > 256)
        {
            return new AuthorizationResponse(false, "activation_failed");
        }

        try
        {
            var trustedKeys = await FetchTrustedKeysAsync(cancellationToken);
            if (trustedKeys.Count == 0)
            {
                return new AuthorizationResponse(false, "trusted_keys_unavailable");
            }
            PersistTrustedKeys(trustedKeys);

            var identity = CalculateDeviceIdentity();
            var envelope = await ActivateRemoteAsync(request, identity, cancellationToken);
            var lease = VerifyLeaseEnvelope(envelope, trustedKeys);
            RequireLeaseIdentity(lease, request, identity.DeviceId);

            PersistVerifiedLicense(lease, envelope);
            PersistActiveBinding(lease);

            var finalDecision = await _authorization.AuthorizeAsync(
                new AuthorizeRequest(request.ProductId, request.Version, request.InstallationId),
                cancellationToken);
            if (!finalDecision.Authorized)
            {
                return new AuthorizationResponse(false, "activation_failed");
            }
            return new AuthorizationResponse(true, finalDecision.Reason);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return new AuthorizationResponse(false, "activation_failed");
        }
    }

    private async Task<Dictionary<string, string>> FetchTrustedKeysAsync(CancellationToken cancellationToken)
    {
        var payload = await SendJsonAsync(HttpMethod.Get, "/keys", null, null, cancellationToken);
        using var document = JsonDocument.Parse(payload);
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object ||
            !root.TryGetProperty("keys", out var keysElement) ||
            keysElement.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException("Invalid trusted key response");
        }

        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var item in keysElement.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidDataException("Invalid trusted key metadata");
            }
            var keyId = RequiredString(item, "key_id");
            var publicKey = RequiredString(item, "public_key");
            var algorithm = RequiredString(item, "algorithm");
            if (algorithm == "Ed25519")
            {
                result[keyId] = publicKey;
            }
        }
        return result;
    }

    private void PersistTrustedKeys(IReadOnlyDictionary<string, string> trustedKeys)
    {
        var directory = Path.Combine(_dataDir, "trusted-keys");
        Directory.CreateDirectory(directory);
        foreach (var pair in trustedKeys)
        {
            if (string.IsNullOrWhiteSpace(pair.Key) ||
                pair.Key.IndexOfAny(new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar }) >= 0 ||
                pair.Key is "." or "..")
            {
                throw new InvalidDataException("Invalid trusted key identifier");
            }
            File.WriteAllText(Path.Combine(directory, $"{pair.Key}.pem"), pair.Value);
        }
    }

    private async Task<LeaseEnvelope> ActivateRemoteAsync(
        ActivateRequest request,
        DeviceIdentity identity,
        CancellationToken cancellationToken)
    {
        var wire = JsonSerializer.Serialize(new
        {
            licenseKey = request.LicenseKey,
            installationId = request.InstallationId,
            deviceId = identity.DeviceId,
            operationId = Guid.NewGuid().ToString(),
            productVersion = request.Version,
            operatingSystem = identity.Platform,
            architecture = identity.Architecture,
        });
        var responseJson = await SendJsonAsync(
            HttpMethod.Post,
            "/api/licenses/activate",
            wire,
            "bke.licensing.v3",
            cancellationToken);

        using var document = JsonDocument.Parse(responseJson);
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().Count() != 1 ||
            !root.TryGetProperty("lease", out var leaseElement) || leaseElement.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException("Invalid activation response");
        }
        return ParseEnvelope(leaseElement);
    }

    private async Task<string> SendJsonAsync(
        HttpMethod method,
        string path,
        string? json,
        string? protocolVersion,
        CancellationToken cancellationToken)
    {
        Exception? lastError = null;
        for (var attempt = 0; attempt <= 2; attempt++)
        {
            using var request = new HttpRequestMessage(method, $"{_platformBaseUrl}{path}");
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Headers.UserAgent.ParseAdd("bke-licensing-agent");
            request.Headers.TryAddWithoutValidation("X-Request-ID", Guid.NewGuid().ToString());
            if (protocolVersion is not null)
            {
                request.Headers.TryAddWithoutValidation("x-bke-licensing-version", protocolVersion);
            }
            if (json is not null)
            {
                request.Content = new StringContent(json, Encoding.UTF8, "application/json");
            }

            try
            {
                using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                if (RetryableStatuses.Contains(response.StatusCode) && attempt < 2)
                {
                    await Task.Delay(TimeSpan.FromSeconds(0.25 * Math.Pow(2, attempt)), cancellationToken);
                    continue;
                }
                if (!response.IsSuccessStatusCode)
                {
                    throw new HttpRequestException($"Licensing platform returned {(int)response.StatusCode}");
                }
                return await response.Content.ReadAsStringAsync(cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception error) when (attempt < 2 && error is HttpRequestException or TaskCanceledException)
            {
                lastError = error;
                await Task.Delay(TimeSpan.FromSeconds(0.25 * Math.Pow(2, attempt)), cancellationToken);
            }
            catch (Exception error)
            {
                lastError = error;
                break;
            }
        }
        throw new HttpRequestException("Licensing platform request failed", lastError);
    }

    private static LeaseEnvelope ParseEnvelope(JsonElement root)
    {
        var allowed = new HashSet<string>(StringComparer.Ordinal)
        {
            "payload", "signature", "key_id", "algorithm"
        };
        foreach (var property in root.EnumerateObject())
        {
            if (!allowed.Contains(property.Name))
            {
                throw new InvalidDataException("Malformed lease envelope");
            }
        }
        if (root.EnumerateObject().Count() != allowed.Count)
        {
            throw new InvalidDataException("Malformed lease envelope");
        }
        return new LeaseEnvelope(
            RequiredString(root, "payload"),
            RequiredString(root, "signature"),
            RequiredString(root, "key_id"),
            RequiredString(root, "algorithm"));
    }

    private static LeasePayload VerifyLeaseEnvelope(
        LeaseEnvelope envelope,
        IReadOnlyDictionary<string, string> trustedKeys)
    {
        if (envelope.Algorithm != "Ed25519")
        {
            throw new InvalidDataException("Unsupported lease signature algorithm");
        }
        if (!trustedKeys.TryGetValue(envelope.KeyId, out var pem))
        {
            throw new InvalidDataException("Lease signing key is not trusted");
        }

        using var textReader = new StringReader(pem);
        var keyObject = new PemReader(textReader).ReadObject();
        if (keyObject is not Ed25519PublicKeyParameters publicKey)
        {
            throw new InvalidDataException("Trusted key is not Ed25519");
        }

        var signature = Convert.FromBase64String(envelope.Signature);
        var payloadBytes = Encoding.UTF8.GetBytes(envelope.Payload);
        var verifier = new Ed25519Signer();
        verifier.Init(false, publicKey);
        verifier.BlockUpdate(payloadBytes, 0, payloadBytes.Length);
        if (!verifier.VerifySignature(signature))
        {
            throw new CryptographicException("Lease signature is invalid");
        }

        var lease = ParseLeasePayload(envelope.Payload);
        if (lease.KeyId != envelope.KeyId || lease.Algorithm != envelope.Algorithm)
        {
            throw new InvalidDataException("Lease key metadata does not match envelope");
        }
        if (lease.Revoked)
        {
            throw new InvalidDataException("Lease is revoked");
        }
        if (lease.SupersededBy is not null)
        {
            throw new InvalidDataException("Lease has been superseded");
        }
        return lease;
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

        return new LeasePayload(
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
    }

    private static void RequireLeaseIdentity(LeasePayload lease, ActivateRequest request, string deviceId)
    {
        if (lease.ProductId != request.ProductId ||
            lease.InstallationId != request.InstallationId ||
            lease.DeviceId != deviceId ||
            lease.Version != request.Version)
        {
            throw new InvalidDataException("Lease identity does not match activation request");
        }
    }

    private void PersistVerifiedLicense(LeasePayload lease, LeaseEnvelope envelope)
    {
        var databasePath = Path.Combine(_dataDir, "agent.db");
        using var connection = OpenWritableDatabase(databasePath);
        var now = DateTimeOffset.UtcNow.ToString("O");
        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO verified_licenses VALUES (
                $license_id, $product_id, $product_version, $installation_id, $device_id, $lease_id,
                $generation, $server_revision, $issued_at, $not_before, $expires_at, $status, $key_id,
                $created_at, $updated_at, $signed_payload, $signed_signature, $signed_algorithm
            )
            ON CONFLICT(lease_id) DO UPDATE SET
                license_id=excluded.license_id,
                product_version=excluded.product_version,
                status=excluded.status,
                updated_at=excluded.updated_at
            """;
        command.Parameters.AddWithValue("$license_id", lease.LicenseId);
        command.Parameters.AddWithValue("$product_id", lease.ProductId);
        command.Parameters.AddWithValue("$product_version", lease.Version);
        command.Parameters.AddWithValue("$installation_id", lease.InstallationId);
        command.Parameters.AddWithValue("$device_id", lease.DeviceId);
        command.Parameters.AddWithValue("$lease_id", lease.LeaseId);
        command.Parameters.AddWithValue("$generation", lease.Generation);
        command.Parameters.AddWithValue("$server_revision", lease.ServerRevision);
        command.Parameters.AddWithValue("$issued_at", lease.IssuedAt.ToString("O"));
        command.Parameters.AddWithValue("$not_before", lease.NotBefore.ToString("O"));
        command.Parameters.AddWithValue("$expires_at", lease.ExpiresAt.ToString("O"));
        command.Parameters.AddWithValue("$status", "verified");
        command.Parameters.AddWithValue("$key_id", lease.KeyId);
        command.Parameters.AddWithValue("$created_at", now);
        command.Parameters.AddWithValue("$updated_at", now);
        command.Parameters.AddWithValue("$signed_payload", envelope.Payload);
        command.Parameters.AddWithValue("$signed_signature", envelope.Signature);
        command.Parameters.AddWithValue("$signed_algorithm", envelope.Algorithm);
        command.ExecuteNonQuery();
    }

    private void PersistActiveBinding(LeasePayload lease)
    {
        var databasePath = Path.Combine(_dataDir, "agent.db");
        using var connection = OpenWritableDatabase(databasePath);
        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO active_license_bindings VALUES (
                $product_id, $installation_id, $device_id, $active_license_id, $active_lease_id,
                $generation, $server_revision, 1, $updated_at
            )
            ON CONFLICT(product_id, installation_id, device_id) DO UPDATE SET
                active_license_id=excluded.active_license_id,
                active_lease_id=excluded.active_lease_id,
                generation=excluded.generation,
                server_revision=excluded.server_revision,
                binding_version=excluded.binding_version,
                updated_at=excluded.updated_at
            """;
        command.Parameters.AddWithValue("$product_id", lease.ProductId);
        command.Parameters.AddWithValue("$installation_id", lease.InstallationId);
        command.Parameters.AddWithValue("$device_id", lease.DeviceId);
        command.Parameters.AddWithValue("$active_license_id", lease.LicenseId);
        command.Parameters.AddWithValue("$active_lease_id", lease.LeaseId);
        command.Parameters.AddWithValue("$generation", lease.Generation);
        command.Parameters.AddWithValue("$server_revision", lease.ServerRevision);
        command.Parameters.AddWithValue("$updated_at", DateTimeOffset.UtcNow.ToString("O"));
        command.ExecuteNonQuery();
    }

    private static SqliteConnection OpenWritableDatabase(string path)
    {
        if (!File.Exists(path))
        {
            throw new InvalidDataException("Agent database is unavailable");
        }
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadWrite,
            Cache = SqliteCacheMode.Private,
        }.ToString());
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT version FROM schema_version LIMIT 1";
        var value = command.ExecuteScalar();
        var version = value is long raw ? checked((int)raw) : Convert.ToInt32(value);
        if (version != ExpectedSchemaVersion)
        {
            connection.Dispose();
            throw new InvalidDataException("Agent database schema mismatch");
        }
        return connection;
    }

    private static DeviceIdentity CalculateDeviceIdentity()
    {
        string platform;
        string release;
        string architecture;
        if (OperatingSystem.IsWindows())
        {
            platform = "windows";
            var osVersion = Environment.OSVersion.Version;
            release = osVersion.Major >= 10 && osVersion.Build >= 22000
                ? "11"
                : osVersion.Major >= 10 ? "10" : osVersion.Major.ToString();
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
        return new DeviceIdentity(
            Convert.ToHexString(digest).ToLowerInvariant(),
            platform.Trim().ToLowerInvariant(),
            architecture.Trim().ToLowerInvariant());
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

    private static void ValidatePlatformBaseUrl(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp) ||
            !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment))
        {
            throw new InvalidOperationException("BKE_PLATFORM_BASE_URL must be an absolute HTTP(S) URL without query or fragment");
        }
        if (uri.Scheme == Uri.UriSchemeHttps)
        {
            return;
        }
        var allowLocal = Environment.GetEnvironmentVariable("BKE_AGENT_VNEXT_ALLOW_INSECURE_LOCAL") == "1";
        if (!allowLocal || !uri.IsLoopback)
        {
            throw new InvalidOperationException("HTTPS is required outside isolated loopback Gen2 certification");
        }
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

    private sealed record DeviceIdentity(string DeviceId, string Platform, string Architecture);
    private sealed record LeaseEnvelope(string Payload, string Signature, string KeyId, string Algorithm);
    private sealed record LeasePayload(
        string LicenseId, string LeaseId, int Generation, int ServerRevision, string ProductId, string InstallationId,
        string DeviceId, string Version, string Issuer, DateTimeOffset IssuedAt, DateTimeOffset NotBefore,
        DateTimeOffset ExpiresAt, string KeyId, string Algorithm, bool Revoked, string? SupersededBy);
}
