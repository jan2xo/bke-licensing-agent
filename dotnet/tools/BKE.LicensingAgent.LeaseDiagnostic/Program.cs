using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using OpenSslPemReader = Org.BouncyCastle.OpenSsl.PemReader;

namespace BKE.LicensingAgent.LeaseDiagnostic;

internal static class Program
{
    public static int Main(string[] args)
    {
        try
        {
            var options = Parse(args);
            var dataRoot = Path.GetFullPath(Required(options, "--data-root"));
            var productId = Required(options, "--product-id");
            var version = Required(options, "--version");
            var installationId = Required(options, "--installation-id");
            var dbPath = Path.Combine(dataRoot, "agent.db");

            Console.WriteLine("BKE historical lease compatibility diagnostic");
            Console.WriteLine("mode=READ_ONLY");
            Console.WriteLine($"data_root={dataRoot}");
            Console.WriteLine($"product_id={productId}");
            Console.WriteLine($"version={version}");
            Console.WriteLine($"installation_id={installationId}");

            if (!File.Exists(dbPath))
            {
                return Fail("database", $"agent.db not found: {dbPath}");
            }

            Console.WriteLine($"agent_db_sha256={Sha256File(dbPath)}");

            var csb = new SqliteConnectionStringBuilder
            {
                DataSource = dbPath,
                Mode = SqliteOpenMode.ReadOnly,
                Cache = SqliteCacheMode.Private,
            };

            using var connection = new SqliteConnection(csb.ToString());
            connection.Open();

            var binding = LoadBinding(connection, productId, installationId);
            Pass("binding_lookup");
            Console.WriteLine($"binding.device_id={binding.DeviceId}");
            Console.WriteLine($"binding.active_license_id={binding.ActiveLicenseId}");
            Console.WriteLine($"binding.active_lease_id={binding.ActiveLeaseId}");
            Console.WriteLine($"binding.generation={binding.Generation}");
            Console.WriteLine($"binding.server_revision={binding.ServerRevision}");
            Console.WriteLine($"binding.binding_version={binding.BindingVersion}");

            var active = LoadLicenseById(connection, binding.ActiveLicenseId);
            Pass("active_license_lookup");
            PrintRecord("active", active);

            if (!BindingMatchesRecord(binding, active))
            {
                return Fail("binding_vs_active_license", "active binding does not match the referenced verified license row");
            }
            Pass("binding_vs_active_license");

            var signed = LoadLicenseByLeaseId(connection, binding.ActiveLeaseId);
            Pass("signed_lease_lookup");
            PrintRecord("signed", signed);

            if (string.IsNullOrEmpty(signed.SignedPayload) ||
                string.IsNullOrEmpty(signed.SignedSignature) ||
                string.IsNullOrEmpty(signed.SignedAlgorithm))
            {
                return Fail("signed_envelope", "signed lease envelope is missing payload/signature/algorithm");
            }
            Pass("signed_envelope");

            Console.WriteLine($"signed.payload_bytes={Encoding.UTF8.GetByteCount(signed.SignedPayload)}");
            Console.WriteLine($"signed.payload_sha256={Sha256Bytes(Encoding.UTF8.GetBytes(signed.SignedPayload))}");
            Console.WriteLine($"signed.signature_chars={signed.SignedSignature.Length}");
            Console.WriteLine($"signed.algorithm={signed.SignedAlgorithm}");
            Console.WriteLine($"signed.key_id={signed.KeyId}");

            if (!string.Equals(signed.SignedAlgorithm, "Ed25519", StringComparison.Ordinal))
            {
                return Fail("algorithm", $"unsupported algorithm: {signed.SignedAlgorithm}");
            }
            Pass("algorithm");

            var keyPath = Path.Combine(dataRoot, "trusted-keys", signed.KeyId + ".pem");
            if (!File.Exists(keyPath))
            {
                return Fail("trusted_key_lookup", $"trusted key file is missing: {keyPath}");
            }
            Pass("trusted_key_lookup");
            Console.WriteLine($"trusted_key.path={keyPath}");
            Console.WriteLine($"trusted_key.sha256={Sha256File(keyPath)}");

            object? keyObject;
            try
            {
                using var textReader = new StringReader(File.ReadAllText(keyPath));
                keyObject = new OpenSslPemReader(textReader).ReadObject();
            }
            catch (Exception exception)
            {
                return Fail("trusted_key_parse", exception);
            }

            Console.WriteLine($"trusted_key.object_type={keyObject?.GetType().FullName ?? "<null>"}");
            if (keyObject is not Ed25519PublicKeyParameters publicKey)
            {
                return Fail("trusted_key_type", "PEM did not parse as Ed25519PublicKeyParameters");
            }
            Pass("trusted_key_parse");
            Pass("trusted_key_type");

            byte[] signature;
            try
            {
                signature = Convert.FromBase64String(signed.SignedSignature);
            }
            catch (Exception exception)
            {
                return Fail("signature_base64", exception);
            }
            Pass("signature_base64");
            Console.WriteLine($"signature.bytes={signature.Length}");

            try
            {
                var payloadBytes = Encoding.UTF8.GetBytes(signed.SignedPayload);
                var verifier = new Ed25519Signer();
                verifier.Init(false, publicKey);
                verifier.BlockUpdate(payloadBytes, 0, payloadBytes.Length);
                var valid = verifier.VerifySignature(signature);
                Console.WriteLine($"signature.valid={valid.ToString().ToLowerInvariant()}");
                if (!valid)
                {
                    return Fail("signature_verify", "Ed25519 signature verification returned false");
                }
            }
            catch (Exception exception)
            {
                return Fail("signature_verify", exception);
            }
            Pass("signature_verify");

            JsonDocument document;
            try
            {
                document = JsonDocument.Parse(signed.SignedPayload);
            }
            catch (Exception exception)
            {
                return Fail("payload_json", exception);
            }
            using (document)
            {
                var root = document.RootElement;
                if (root.ValueKind != JsonValueKind.Object)
                {
                    return Fail("payload_shape", $"expected object, got {root.ValueKind}");
                }
                Pass("payload_json");
                Pass("payload_shape");

                var propertySummary = string.Join(",",
                    root.EnumerateObject()
                        .Select(property => $"{property.Name}:{property.Value.ValueKind}")
                        .OrderBy(value => value, StringComparer.Ordinal));
                Console.WriteLine($"payload.properties={propertySummary}");

                var allowed = new HashSet<string>(StringComparer.Ordinal)
                {
                    "license_id", "lease_id", "generation", "server_revision", "product_id", "installation_id",
                    "device_id", "version", "issuer", "issued_at", "not_before", "expires_at", "key_id", "algorithm",
                    "revoked", "superseded_by",
                };

                var extras = root.EnumerateObject()
                    .Select(property => property.Name)
                    .Where(name => !allowed.Contains(name))
                    .OrderBy(name => name, StringComparer.Ordinal)
                    .ToArray();
                if (extras.Length != 0)
                {
                    return Fail("payload_allowed_fields", "unexpected fields: " + string.Join(",", extras));
                }
                Pass("payload_allowed_fields");

                LeasePayload lease;
                try
                {
                    lease = ParseLease(root);
                }
                catch (Exception exception)
                {
                    return Fail("payload_strict_parse", exception);
                }
                Pass("payload_strict_parse");

                Console.WriteLine($"payload.license_id={lease.LicenseId}");
                Console.WriteLine($"payload.lease_id={lease.LeaseId}");
                Console.WriteLine($"payload.generation={lease.Generation}");
                Console.WriteLine($"payload.server_revision={lease.ServerRevision}");
                Console.WriteLine($"payload.product_id={lease.ProductId}");
                Console.WriteLine($"payload.installation_id={lease.InstallationId}");
                Console.WriteLine($"payload.device_id={lease.DeviceId}");
                Console.WriteLine($"payload.version={lease.Version}");
                Console.WriteLine($"payload.key_id={lease.KeyId}");
                Console.WriteLine($"payload.algorithm={lease.Algorithm}");
                Console.WriteLine($"payload.revoked={lease.Revoked.ToString().ToLowerInvariant()}");
                Console.WriteLine($"payload.superseded_by={(lease.SupersededBy ?? "<null>")}");
                Console.WriteLine($"payload.not_before={lease.NotBefore:O}");
                Console.WriteLine($"payload.expires_at={lease.ExpiresAt:O}");

                if (lease.Revoked || lease.SupersededBy is not null)
                {
                    return Fail("payload_lifecycle", "lease is revoked or superseded");
                }
                Pass("payload_lifecycle");

                var comparisons = new Dictionary<string, bool>(StringComparer.Ordinal)
                {
                    ["license_id_vs_record"] = lease.LicenseId == signed.LicenseId,
                    ["lease_id_vs_record"] = lease.LeaseId == signed.LeaseId,
                    ["product_id_vs_request"] = lease.ProductId == productId,
                    ["installation_id_vs_request"] = lease.InstallationId == installationId,
                    ["device_id_vs_binding"] = lease.DeviceId == binding.DeviceId,
                    ["version_vs_request"] = lease.Version == version,
                    ["generation_vs_record"] = lease.Generation == signed.Generation,
                    ["server_revision_vs_record"] = lease.ServerRevision == signed.ServerRevision,
                    ["key_id_vs_record"] = lease.KeyId == signed.KeyId,
                    ["algorithm_vs_record"] = lease.Algorithm == signed.SignedAlgorithm,
                    ["active_lease_id_vs_payload"] = lease.LeaseId == active.LeaseId,
                    ["active_generation_vs_payload"] = lease.Generation == active.Generation,
                    ["active_server_revision_vs_payload"] = lease.ServerRevision == active.ServerRevision,
                };
                foreach (var pair in comparisons)
                {
                    Console.WriteLine($"compare.{pair.Key}={pair.Value.ToString().ToLowerInvariant()}");
                }
                var failedComparisons = comparisons.Where(pair => !pair.Value).Select(pair => pair.Key).ToArray();
                if (failedComparisons.Length != 0)
                {
                    return Fail("stored_authority_match", "mismatches: " + string.Join(",", failedComparisons));
                }
                Pass("stored_authority_match");

                var now = DateTimeOffset.UtcNow;
                var skew = TimeSpan.FromSeconds(30);
                Console.WriteLine($"clock.now={now:O}");
                Console.WriteLine($"clock.not_before_pass={(now + skew >= lease.NotBefore).ToString().ToLowerInvariant()}");
                Console.WriteLine($"clock.not_expired={(now - skew < lease.ExpiresAt).ToString().ToLowerInvariant()}");
            }

            Console.WriteLine("RESULT=PASS");
            return 0;
        }
        catch (Exception exception)
        {
            return Fail("unhandled", exception);
        }
    }

    private static ActiveBinding LoadBinding(SqliteConnection connection, string productId, string installationId)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT device_id, active_license_id, active_lease_id, generation, server_revision, binding_version
            FROM active_license_bindings
            WHERE product_id = $product_id AND installation_id = $installation_id
            ORDER BY updated_at DESC
            """;
        command.Parameters.AddWithValue("$product_id", productId);
        command.Parameters.AddWithValue("$installation_id", installationId);
        using var reader = command.ExecuteReader();
        var rows = new List<ActiveBinding>();
        while (reader.Read())
        {
            rows.Add(new ActiveBinding(
                reader.GetString(0), reader.GetString(1), reader.GetString(2),
                reader.GetInt32(3), reader.GetInt32(4), reader.GetInt32(5)));
        }
        Console.WriteLine($"binding.count={rows.Count}");
        if (rows.Count != 1)
        {
            throw new InvalidDataException($"expected exactly one active binding for product/install, found {rows.Count}");
        }
        return rows[0];
    }

    private static LicenseRecord LoadLicenseById(SqliteConnection connection, string licenseId)
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
        return ReadLicense(command, "license_id");
    }

    private static LicenseRecord LoadLicenseByLeaseId(SqliteConnection connection, string leaseId)
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
        return ReadLicense(command, "lease_id");
    }

    private static LicenseRecord ReadLicense(SqliteCommand command, string selector)
    {
        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            throw new InvalidDataException($"verified license row not found by {selector}");
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
        record.InstallationId is not null &&
        record.DeviceId == binding.DeviceId &&
        record.LeaseId == binding.ActiveLeaseId &&
        record.Generation == binding.Generation &&
        record.ServerRevision == binding.ServerRevision;

    private static void PrintRecord(string prefix, LicenseRecord record)
    {
        Console.WriteLine($"{prefix}.license_id={record.LicenseId}");
        Console.WriteLine($"{prefix}.product_id={record.ProductId}");
        Console.WriteLine($"{prefix}.product_version={record.ProductVersion}");
        Console.WriteLine($"{prefix}.installation_id={record.InstallationId}");
        Console.WriteLine($"{prefix}.device_id={record.DeviceId}");
        Console.WriteLine($"{prefix}.lease_id={record.LeaseId}");
        Console.WriteLine($"{prefix}.generation={record.Generation}");
        Console.WriteLine($"{prefix}.server_revision={record.ServerRevision}");
        Console.WriteLine($"{prefix}.status={record.Status}");
        Console.WriteLine($"{prefix}.key_id={record.KeyId}");
        Console.WriteLine($"{prefix}.signed_payload_present={(!string.IsNullOrEmpty(record.SignedPayload)).ToString().ToLowerInvariant()}");
        Console.WriteLine($"{prefix}.signed_signature_present={(!string.IsNullOrEmpty(record.SignedSignature)).ToString().ToLowerInvariant()}");
        Console.WriteLine($"{prefix}.signed_algorithm={record.SignedAlgorithm ?? "<null>"}");
    }

    private static LeasePayload ParseLease(JsonElement root) =>
        new(
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

    private static string RequiredString(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var value) ||
            value.ValueKind != JsonValueKind.String ||
            string.IsNullOrEmpty(value.GetString()))
        {
            throw new InvalidDataException($"Missing or invalid {name}; kind={(root.TryGetProperty(name, out var found) ? found.ValueKind : JsonValueKind.Undefined)}");
        }
        return value.GetString()!;
    }

    private static int RequiredNonNegativeInt(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var value) ||
            value.ValueKind != JsonValueKind.Number ||
            !value.TryGetInt32(out var result) ||
            result < 0)
        {
            throw new InvalidDataException($"Missing or invalid {name}; kind={(root.TryGetProperty(name, out var found) ? found.ValueKind : JsonValueKind.Undefined)} raw={(root.TryGetProperty(name, out found) ? found.GetRawText() : "<missing>")}");
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
            throw new InvalidDataException($"Invalid {name}; kind={value.ValueKind} raw={value.GetRawText()}");
        }
        return result;
    }

    private static DateTimeOffset RequiredDateTime(JsonElement root, string name)
    {
        var text = RequiredString(root, name);
        if (!DateTimeOffset.TryParse(
            text,
            System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.RoundtripKind,
            out var result))
        {
            throw new InvalidDataException($"Invalid {name}");
        }
        return result;
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
            _ => throw new InvalidDataException($"Invalid {name}; kind={value.ValueKind} raw={value.GetRawText()}"),
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
            throw new InvalidDataException($"Invalid {name}; kind={value.ValueKind}");
        }
        return value.GetString();
    }

    private static Dictionary<string, string> Parse(string[] args)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = 0; index < args.Length; index++)
        {
            var name = args[index];
            if (!name.StartsWith("--", StringComparison.Ordinal) || index + 1 >= args.Length)
            {
                throw new InvalidDataException($"invalid argument: {name}");
            }
            if (!result.TryAdd(name, args[++index]))
            {
                throw new InvalidDataException($"duplicate argument: {name}");
            }
        }
        return result;
    }

    private static string Required(IReadOnlyDictionary<string, string> options, string name) =>
        options.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : throw new InvalidDataException($"{name} is required");

    private static string Sha256File(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }

    private static string Sha256Bytes(byte[] value) =>
        Convert.ToHexString(SHA256.HashData(value)).ToLowerInvariant();

    private static void Pass(string stage) => Console.WriteLine($"PASS {stage}");

    private static int Fail(string stage, string message)
    {
        Console.WriteLine($"FAIL {stage}");
        Console.WriteLine($"failure.message={message}");
        Console.WriteLine("RESULT=FAIL");
        return 1;
    }

    private static int Fail(string stage, Exception exception)
    {
        Console.WriteLine($"FAIL {stage}");
        Console.WriteLine($"failure.type={exception.GetType().FullName}");
        Console.WriteLine($"failure.message={exception.Message}");
        Console.WriteLine("RESULT=FAIL");
        return 1;
    }

    private sealed record ActiveBinding(
        string DeviceId,
        string ActiveLicenseId,
        string ActiveLeaseId,
        int Generation,
        int ServerRevision,
        int BindingVersion);

    private sealed record LicenseRecord(
        string LicenseId,
        string ProductId,
        string ProductVersion,
        string InstallationId,
        string DeviceId,
        string LeaseId,
        int Generation,
        int ServerRevision,
        string IssuedAt,
        string NotBefore,
        string ExpiresAt,
        string Status,
        string KeyId,
        string? SignedPayload,
        string? SignedSignature,
        string? SignedAlgorithm);

    private sealed record LeasePayload(
        string LicenseId,
        string LeaseId,
        int Generation,
        int ServerRevision,
        string ProductId,
        string InstallationId,
        string DeviceId,
        string Version,
        string Issuer,
        DateTimeOffset IssuedAt,
        DateTimeOffset NotBefore,
        DateTimeOffset ExpiresAt,
        string KeyId,
        string Algorithm,
        bool Revoked,
        string? SupersededBy);
}
