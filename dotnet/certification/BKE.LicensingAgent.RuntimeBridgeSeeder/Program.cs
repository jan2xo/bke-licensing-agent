using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.Win32;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

const string ProductId = "runtime-bridge-cert";
const string Version = "2.0.0";
const string InstallationId = "runtime-bridge-installation";
const string LicenseId = "runtime-bridge-license";
const string LeaseId = "runtime-bridge-lease";
const string KeyId = "runtime-bridge-state-key";
const int ExpectedSchemaVersion = 8;

if (!OperatingSystem.IsWindows())
{
    Console.Error.WriteLine("This certification seeder is Windows-only.");
    return 2;
}

var dataRoot = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
    "BKE Digital Solutions",
    "Licensing Agent");

for (var i = 0; i < args.Length; i++)
{
    if (args[i] == "--data-root" && i + 1 < args.Length)
    {
        dataRoot = Path.GetFullPath(args[++i]);
    }
    else
    {
        Console.Error.WriteLine($"Unknown or incomplete argument: {args[i]}");
        return 2;
    }
}

Directory.CreateDirectory(dataRoot);
var databasePath = Path.Combine(dataRoot, "agent.db");
if (!File.Exists(databasePath))
{
    Console.Error.WriteLine($"Agent database is missing: {databasePath}");
    return 3;
}

var productRoot = Path.Combine(dataRoot, "runtime-bridge-product");
Directory.CreateDirectory(productRoot);
var manifestPath = Path.Combine(productRoot, "bke.manifest.json");
var entryPointPath = Path.Combine(productRoot, "product.exe");
File.WriteAllText(entryPointPath, "BKE runtime bridge durable product fixture\n", new UTF8Encoding(false));

var architecture = (Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE")
                    ?? RuntimeInformation.OSArchitecture.ToString())
    .Trim()
    .ToLowerInvariant();

var manifest = new Dictionary<string, object?>
{
    ["schemaVersion"] = 1,
    ["productId"] = ProductId,
    ["displayName"] = "Runtime Bridge Certification Product",
    ["version"] = Version,
    ["entryPoint"] = "product.exe",
    ["updateChannel"] = "stable",
    ["minimumAgentVersion"] = "1.0.0",
    ["platform"] = "windows",
    ["architecture"] = architecture,
};
File.WriteAllText(
    manifestPath,
    JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = false }),
    new UTF8Encoding(false));

var privateKey = new Ed25519PrivateKeyParameters(new SecureRandom());
var publicKey = privateKey.GeneratePublicKey();
var trustedKeysDir = Path.Combine(dataRoot, "trusted-keys");
Directory.CreateDirectory(trustedKeysDir);
var trustedKeyPath = Path.Combine(trustedKeysDir, $"{KeyId}.pem");

using (var sw = new StringWriter(CultureInfo.InvariantCulture))
{
    var pemWriter = new PemWriter(sw);
    pemWriter.WriteObject(publicKey);
    pemWriter.Writer.Flush();
    File.WriteAllText(trustedKeyPath, sw.ToString(), new UTF8Encoding(false));
}

var deviceId = CalculateDeviceFingerprint();
var now = DateTimeOffset.UtcNow;
var issuedAt = now.ToString("O", CultureInfo.InvariantCulture);
var notBefore = now.AddMinutes(-5).ToString("O", CultureInfo.InvariantCulture);
var expiresAt = now.AddDays(7).ToString("O", CultureInfo.InvariantCulture);

var lease = new Dictionary<string, object?>
{
    ["license_id"] = LicenseId,
    ["lease_id"] = LeaseId,
    ["generation"] = 1,
    ["server_revision"] = 1,
    ["product_id"] = ProductId,
    ["installation_id"] = InstallationId,
    ["device_id"] = deviceId,
    ["version"] = Version,
    ["issuer"] = "runtime-bridge-certification",
    ["issued_at"] = issuedAt,
    ["not_before"] = notBefore,
    ["expires_at"] = expiresAt,
    ["key_id"] = KeyId,
    ["algorithm"] = "Ed25519",
    ["revoked"] = false,
    ["superseded_by"] = null,
};

var payload = JsonSerializer.Serialize(lease);
var payloadBytes = Encoding.UTF8.GetBytes(payload);
var signer = new Ed25519Signer();
signer.Init(true, privateKey);
signer.BlockUpdate(payloadBytes, 0, payloadBytes.Length);
var signatureBytes = signer.GenerateSignature();
var signature = Convert.ToBase64String(signatureBytes);

var verifier = new Ed25519Signer();
verifier.Init(false, publicKey);
verifier.BlockUpdate(payloadBytes, 0, payloadBytes.Length);
if (!verifier.VerifySignature(signatureBytes))
{
    Console.Error.WriteLine("Self-check failed: generated Ed25519 signature did not verify.");
    return 4;
}

var cs = new SqliteConnectionStringBuilder
{
    DataSource = databasePath,
    Mode = SqliteOpenMode.ReadWrite,
}.ToString();

using var connection = new SqliteConnection(cs);
connection.Open();

using (var command = connection.CreateCommand())
{
    command.CommandText = "SELECT version FROM schema_version LIMIT 1";
    var value = command.ExecuteScalar();
    if (value is null || Convert.ToInt32(value, CultureInfo.InvariantCulture) != ExpectedSchemaVersion)
    {
        Console.Error.WriteLine($"Unexpected Agent database schema version: {value ?? "<missing>"}");
        return 5;
    }
}

using var transaction = connection.BeginTransaction();

Execute(
    connection,
    transaction,
    "DELETE FROM active_license_bindings WHERE product_id=$product_id",
    ("$product_id", ProductId));
Execute(
    connection,
    transaction,
    "DELETE FROM verified_licenses WHERE product_id=$product_id",
    ("$product_id", ProductId));
Execute(
    connection,
    transaction,
    "DELETE FROM discovered_products WHERE product_id=$product_id",
    ("$product_id", ProductId));

Execute(
    connection,
    transaction,
    """
    INSERT INTO discovered_products
      (product_id, display_name, version, manifest_path, product_root, entry_point_path, discovered_at)
    VALUES
      ($product_id, $display_name, $version, $manifest_path, $product_root, $entry_point_path, $discovered_at)
    """,
    ("$product_id", ProductId),
    ("$display_name", "Runtime Bridge Certification Product"),
    ("$version", Version),
    ("$manifest_path", manifestPath),
    ("$product_root", productRoot),
    ("$entry_point_path", entryPointPath),
    ("$discovered_at", issuedAt));

Execute(
    connection,
    transaction,
    """
    INSERT INTO verified_licenses
      (license_id, product_id, product_version, installation_id, device_id, lease_id,
       generation, server_revision, issued_at, not_before, expires_at, status, key_id,
       created_at, updated_at, signed_payload, signed_signature, signed_algorithm)
    VALUES
      ($license_id, $product_id, $product_version, $installation_id, $device_id, $lease_id,
       1, 1, $issued_at, $not_before, $expires_at, 'verified', $key_id,
       $created_at, $updated_at, $signed_payload, $signed_signature, 'Ed25519')
    """,
    ("$license_id", LicenseId),
    ("$product_id", ProductId),
    ("$product_version", Version),
    ("$installation_id", InstallationId),
    ("$device_id", deviceId),
    ("$lease_id", LeaseId),
    ("$issued_at", issuedAt),
    ("$not_before", notBefore),
    ("$expires_at", expiresAt),
    ("$key_id", KeyId),
    ("$created_at", issuedAt),
    ("$updated_at", issuedAt),
    ("$signed_payload", payload),
    ("$signed_signature", signature));

Execute(
    connection,
    transaction,
    """
    INSERT INTO active_license_bindings
      (product_id, installation_id, device_id, active_license_id, active_lease_id,
       generation, server_revision, binding_version, updated_at)
    VALUES
      ($product_id, $installation_id, $device_id, $license_id, $lease_id,
       1, 1, 1, $updated_at)
    """,
    ("$product_id", ProductId),
    ("$installation_id", InstallationId),
    ("$device_id", deviceId),
    ("$license_id", LicenseId),
    ("$lease_id", LeaseId),
    ("$updated_at", issuedAt));

transaction.Commit();

Console.WriteLine(JsonSerializer.Serialize(new
{
    status = "seeded",
    product_id = ProductId,
    version = Version,
    installation_id = InstallationId,
    device_id = deviceId,
    architecture,
    expires_at = expiresAt,
    trusted_key = trustedKeyPath,
}));

return 0;

static void Execute(
    SqliteConnection connection,
    SqliteTransaction transaction,
    string sql,
    params (string Name, object Value)[] parameters)
{
    using var command = connection.CreateCommand();
    command.Transaction = transaction;
    command.CommandText = sql;
    foreach (var (name, value) in parameters)
    {
        command.Parameters.AddWithValue(name, value);
    }
    command.ExecuteNonQuery();
}

static string CalculateDeviceFingerprint()
{
    const string platform = "windows";
    var osVersion = Environment.OSVersion.Version;
    var release = LegacyWindowsRelease(osVersion);
    var architecture = (Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE")
                        ?? RuntimeInformation.OSArchitecture.ToString())
        .Trim()
        .ToLowerInvariant();

    var normalized =
        $"architecture={architecture}|os_version={release.Trim().ToLowerInvariant()}|platform={platform}";
    var digest = SHA256.HashData(
        Encoding.UTF8.GetBytes($"bke-device-v1|{normalized}"));
    return Convert.ToHexString(digest).ToLowerInvariant();
}

static string LegacyWindowsRelease(Version osVersion)
{
    var productName = Registry.GetValue(
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
        : osVersion.Major >= 10 ? "10" : osVersion.Major.ToString(CultureInfo.InvariantCulture);
}
