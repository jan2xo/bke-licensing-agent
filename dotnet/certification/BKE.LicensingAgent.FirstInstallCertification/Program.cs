using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using BKE.LicensingAgent.Storage;
using Microsoft.Data.Sqlite;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

if (!OperatingSystem.IsWindows())
{
    Console.WriteLine("BKE first-install certification: SKIPPED (Windows required)");
    return;
}

if (args.Length != 2 || args[0] != "--helper" || string.IsNullOrWhiteSpace(args[1]))
{
    throw new InvalidDataException("--helper <bke-updater-core.exe> is required");
}

var helper = Path.GetFullPath(args[1]);
if (!File.Exists(helper))
{
    throw new FileNotFoundException("Published updater helper is missing.", helper);
}

var root = Path.Combine(
    Path.GetTempPath(),
    "bke-first-install-cert-" + Guid.NewGuid().ToString("N"));
var dataRoot = Path.Combine(root, "agent-data");
var runtime = Path.Combine(dataRoot, "privileged", "runtime");
var stage = Path.Combine(runtime, "stage");
var transactions = Path.Combine(runtime, "transactions");
var approved = Path.Combine(root, "approved");
var installRoot = Path.Combine(approved, "Certification Product");
var entryPoint = "product.exe";
var databasePath = Path.Combine(dataRoot, "agent.db");

Directory.CreateDirectory(runtime);
Directory.CreateDirectory(stage);
Directory.CreateDirectory(transactions);
Directory.CreateDirectory(approved);

try
{
    var targetPair = KeyPair();
    var agentPair = KeyPair();
    var digitalPair = KeyPair();

    var targetUnsigned = new SortedDictionary<string, object?>(StringComparer.Ordinal)
    {
        ["schema"] = "bke.install-target-policy.v1",
        ["policy_id"] = "first-install-cert-windows-x64-v1",
        ["revision"] = 1,
        ["product_id"] = "bke-certification-product",
        ["platform"] = "windows",
        ["architecture"] = "x86_64",
        ["install_root"] = installRoot,
        ["entry_point"] = entryPoint,
        ["signing_key_id"] = "target-cert-v1",
        ["algorithm"] = "Ed25519",
    };
    var targetPolicy = Signed(targetUnsigned, targetPair.Private);
    var targetPath = Path.Combine(runtime, "target-policy.json");
    WriteJson(targetPath, targetPolicy);

    var targetHash = Sha256(Canonical(targetPolicy));
    var artifactBytes = Encoding.UTF8.GetBytes("certified-first-install-artifact");
    var artifactPath = Path.Combine(runtime, "artifact.bin");
    File.WriteAllBytes(artifactPath, artifactBytes);
    var artifactHash = Sha256(artifactBytes);

    var stagedExecutable = Path.Combine(stage, entryPoint);
    File.WriteAllBytes(stagedExecutable, Encoding.ASCII.GetBytes("MZ-first-install-cert"));

    WriteJson(
        Path.Combine(runtime, "trust.json"),
        new SortedDictionary<string, object?>(StringComparer.Ordinal)
        {
            ["schema"] = "bke.updater-trust.v1",
            ["agent_keys"] = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["agent-cert-v1"] = Convert.ToBase64String(agentPair.Public.GetEncoded()),
            },
            ["digital_keys"] = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["digital-cert-v1"] = Convert.ToBase64String(digitalPair.Public.GetEncoded()),
            },
            ["target_keys"] = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["target-cert-v1"] = Convert.ToBase64String(targetPair.Public.GetEncoded()),
            },
            ["approved_install_roots"] = new[] { approved },
            ["expected_channel"] = "stable",
            ["last_update_policy_revision"] = null,
            ["last_target_policy_revision"] = null,
        });

    // First prove that filesystem commit and local inventory are one transaction.
    WriteManifest(stage, "9.9.9");
    var invalidRequest = BuildRequest(
        "agent-" + Guid.NewGuid().ToString("N"),
        installRoot,
        entryPoint,
        artifactHash,
        artifactBytes.LongLength,
        targetHash,
        agentPair.Private);
    var invalidRequestPath = Path.Combine(runtime, "request-invalid.json");
    WriteJson(invalidRequestPath, invalidRequest);
    var invalidTransaction = "invalid-manifest-" + Guid.NewGuid().ToString("N");
    var invalid = Run(
        helper,
        runtime,
        invalidRequestPath,
        targetPath,
        artifactPath,
        stage,
        transactions,
        invalidTransaction);

    Require(invalid.ExitCode != 0, "mismatched installed manifest was accepted");
    Require(!Directory.Exists(installRoot), "failed manifest registration left an installed product behind");
    using (var failedState = JsonDocument.Parse(
               File.ReadAllText(
                   Path.Combine(transactions, invalidTransaction, "state.json"))))
    {
        Require(
            failedState.RootElement.GetProperty("state").GetString() == "FAILED_CLEANED",
            "failed manifest registration did not clean the first install");
    }

    // Now install a valid product into an otherwise empty Agent data directory.
    WriteManifest(stage, "1.0.0");
    Require(!File.Exists(databasePath), "fresh-install certification unexpectedly started with agent.db");

    var request1 = BuildRequest(
        "agent-" + Guid.NewGuid().ToString("N"),
        installRoot,
        entryPoint,
        artifactHash,
        artifactBytes.LongLength,
        targetHash,
        agentPair.Private);
    var request1Path = Path.Combine(runtime, "request-1.json");
    WriteJson(request1Path, request1);

    var transaction1 = "first-install-" + Guid.NewGuid().ToString("N");
    var first = Run(
        helper,
        runtime,
        request1Path,
        targetPath,
        artifactPath,
        stage,
        transactions,
        transaction1);

    Require(first.ExitCode == 0, $"first install failed: {first.StandardError}");
    Require(File.Exists(Path.Combine(installRoot, entryPoint)), "installed entry point is missing");
    Require(
        File.ReadAllBytes(Path.Combine(installRoot, entryPoint))
            .SequenceEqual(File.ReadAllBytes(stagedExecutable)),
        "installed entry point bytes drifted");

    using (var state = JsonDocument.Parse(
               File.ReadAllText(
                   Path.Combine(transactions, transaction1, "state.json"))))
    {
        Require(state.RootElement.GetProperty("state").GetString() == "COMMITTED", "first install was not committed");
        Require(state.RootElement.GetProperty("operation").GetString() == "PROVISION", "transaction operation drifted");
        Require(state.RootElement.GetProperty("target_version").GetString() == "1.0.0", "transaction target version drifted");
    }

    Require(File.Exists(databasePath), "fresh first install did not create agent.db");
    using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder
           {
               DataSource = databasePath,
               Mode = SqliteOpenMode.ReadOnly,
           }.ToString()))
    {
        connection.Open();

        using (var schema = connection.CreateCommand())
        {
            schema.CommandText = "SELECT version FROM schema_version LIMIT 1";
            Require(
                Convert.ToInt32(schema.ExecuteScalar()) == AgentDatabase.CurrentSchemaVersion,
                "fresh Agent database did not reach current schema");
        }

        using var product = connection.CreateCommand();
        product.CommandText = """
            SELECT product_id, display_name, version, manifest_path, product_root, entry_point_path,
                   install_provenance, uninstall_strategy, uninstall_executable, uninstall_arguments_json
            FROM discovered_products
            WHERE product_id = 'bke-certification-product'
            """;
        using var reader = product.ExecuteReader();
        Require(reader.Read(), "fresh first install did not register discovered product");
        Require(reader.GetString(0) == "bke-certification-product", "registered product_id drifted");
        Require(reader.GetString(1) == "Certification Product", "registered display_name drifted");
        Require(reader.GetString(2) == "1.0.0", "registered version drifted");
        Require(
            Path.GetFullPath(reader.GetString(3)) ==
            Path.GetFullPath(Path.Combine(installRoot, "bke.manifest.json")),
            "registered manifest path drifted");
        Require(
            Path.GetFullPath(reader.GetString(4)) == Path.GetFullPath(installRoot),
            "registered product root drifted");
        Require(
            Path.GetFullPath(reader.GetString(5)) ==
            Path.GetFullPath(Path.Combine(installRoot, entryPoint)),
            "registered entry point path drifted");
        Require(reader.GetString(6) == "BKE_MANAGED_PACKAGE", "first install provenance drifted");
        Require(reader.GetString(7) == "MANAGED_DIRECTORY", "first install uninstall strategy drifted");
        Require(reader.IsDBNull(8), "BKE-managed package unexpectedly stored an uninstall executable");
        Require(reader.IsDBNull(9), "BKE-managed package unexpectedly stored uninstall arguments");
        Require(!reader.Read(), "duplicate discovered product rows were registered");
    }

    var installedHashBefore = Sha256(File.ReadAllBytes(Path.Combine(installRoot, entryPoint)));
    var request2 = BuildRequest(
        "agent-" + Guid.NewGuid().ToString("N"),
        installRoot,
        entryPoint,
        artifactHash,
        artifactBytes.LongLength,
        targetHash,
        agentPair.Private);
    var request2Path = Path.Combine(runtime, "request-2.json");
    WriteJson(request2Path, request2);

    var second = Run(
        helper,
        runtime,
        request2Path,
        targetPath,
        artifactPath,
        stage,
        transactions,
        "duplicate-" + Guid.NewGuid().ToString("N"));

    Require(second.ExitCode != 0, "duplicate first install was accepted");
    Require(
        Sha256(File.ReadAllBytes(Path.Combine(installRoot, entryPoint))) == installedHashBefore,
        "duplicate first install modified the existing product");

    Console.WriteLine("BKE privileged first-install certification: PASS");
    Console.WriteLine(
        "Checks: signed request/policy, invalid-manifest cleanup, current-schema bootstrap, BKE-managed provenance, discovered_products commit, duplicate refusal");
}
finally
{
    try { Directory.Delete(root, recursive: true); } catch { }
}

static void WriteManifest(string stage, string version)
{
    WriteJson(
        Path.Combine(stage, "bke.manifest.json"),
        new SortedDictionary<string, object?>(StringComparer.Ordinal)
        {
            ["schemaVersion"] = 1,
            ["productId"] = "bke-certification-product",
            ["displayName"] = "Certification Product",
            ["version"] = version,
            ["entryPoint"] = "product.exe",
            ["updateChannel"] = "stable",
            ["minimumAgentVersion"] = "0.1.0",
            ["platform"] = "windows",
            ["architecture"] = "x64",
        });
}

static (Ed25519PrivateKeyParameters Private, Ed25519PublicKeyParameters Public) KeyPair()
{
    var generator = new Ed25519KeyPairGenerator();
    generator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
    var pair = generator.GenerateKeyPair();
    return (
        (Ed25519PrivateKeyParameters)pair.Private,
        (Ed25519PublicKeyParameters)pair.Public);
}

static SortedDictionary<string, object?> BuildRequest(
    string requestId,
    string installRoot,
    string entryPoint,
    string artifactHash,
    long artifactSize,
    string targetHash,
    Ed25519PrivateKeyParameters agentPrivate)
{
    var now = DateTimeOffset.UtcNow;
    var unsigned = new SortedDictionary<string, object?>(StringComparer.Ordinal)
    {
        ["schema"] = "bke.privileged-provision-request.v1",
        ["request_id"] = requestId,
        ["product_id"] = "bke-certification-product",
        ["target_version"] = "1.0.0",
        ["platform"] = "windows",
        ["architecture"] = "x86_64",
        ["install_root"] = installRoot,
        ["entry_point"] = entryPoint,
        ["artifact_sha256"] = artifactHash,
        ["artifact_size"] = artifactSize,
        ["target_policy_sha256"] = targetHash,
        ["issued_at"] = now.ToString("O"),
        ["expires_at"] = now.AddMinutes(2).ToString("O"),
        ["signing_key_id"] = "agent-cert-v1",
        ["algorithm"] = "Ed25519",
    };
    return Signed(unsigned, agentPrivate);
}

static SortedDictionary<string, object?> Signed(
    SortedDictionary<string, object?> unsigned,
    Ed25519PrivateKeyParameters privateKey)
{
    var canonical = Canonical(unsigned);
    var signer = new Ed25519Signer();
    signer.Init(true, privateKey);
    signer.BlockUpdate(canonical, 0, canonical.Length);
    var result = new SortedDictionary<string, object?>(unsigned, StringComparer.Ordinal)
    {
        ["signature"] = Convert.ToBase64String(signer.GenerateSignature()),
    };
    return result;
}

static byte[] Canonical(object value) =>
    JsonSerializer.SerializeToUtf8Bytes(
        value,
        new JsonSerializerOptions
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            WriteIndented = false,
        });

static string Sha256(byte[] value) =>
    Convert.ToHexString(SHA256.HashData(value)).ToLowerInvariant();

static void WriteJson(string path, object value) =>
    File.WriteAllText(
        path,
        JsonSerializer.Serialize(
            value,
            new JsonSerializerOptions
            {
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                WriteIndented = true,
            }) + Environment.NewLine,
        new UTF8Encoding(false));

static (int ExitCode, string StandardError) Run(
    string helper,
    string runtime,
    string request,
    string targetPolicy,
    string artifact,
    string stage,
    string transactions,
    string transactionId)
{
    var start = new ProcessStartInfo
    {
        FileName = helper,
        UseShellExecute = false,
        RedirectStandardOutput = true,
        RedirectStandardError = true,
    };
    foreach (var argument in new[]
             {
                 "--privileged-provision",
                 "--runtime-root", runtime,
                 "--request", request,
                 "--target-policy", targetPolicy,
                 "--artifact", artifact,
                 "--staged-root", stage,
                 "--transaction-root", transactions,
                 "--transaction-id", transactionId,
             })
    {
        start.ArgumentList.Add(argument);
    }

    using var process = Process.Start(start)
        ?? throw new InvalidOperationException("first-install certification helper did not start");
    var output = process.StandardOutput.ReadToEnd();
    var error = process.StandardError.ReadToEnd();
    process.WaitForExit();
    if (!string.IsNullOrWhiteSpace(output))
        Console.WriteLine(output.Trim());
    return (process.ExitCode, error.Trim());
}

static void Require(bool condition, string message)
{
    if (!condition)
        throw new InvalidOperationException(message);
}
