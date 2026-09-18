using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO.Pem;

namespace BKE.LicensingAgent.ReleaseTooling;

internal static class Program
{
    public static int Main(string[] args)
    {
        try
        {
            if (args.Length == 0) throw new InvalidDataException("release tooling command is required");
            return args[0] switch
            {
                "generate-disposable-trust" => GenerateDisposableTrust(args[1..]),
                "generate-production-update-key" => GenerateProductionUpdateKey(args[1..]),
                "build-signing-request" => BuildSigningRequest(args[1..]),
                _ => throw new InvalidDataException($"unknown release tooling command: {args[0]}"),
            };
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"BKE release tooling failed: {exception.Message}");
            return 1;
        }
    }

    private static int GenerateDisposableTrust(string[] args)
    {
        var options = Parse(args);
        var root = Path.GetFullPath(Required(options, "--root"));
        var targetRoot = Path.Combine(root, "privileged-payload");
        var targetKeys = Path.Combine(targetRoot, "target-keys");
        var targetPolicies = Path.Combine(targetRoot, "target-policies");
        var updateKeys = Path.Combine(root, "update-authority-keys");
        Directory.CreateDirectory(targetKeys);
        Directory.CreateDirectory(targetPolicies);
        Directory.CreateDirectory(updateKeys);

        var targetGenerator = new Ed25519KeyPairGenerator();
        targetGenerator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        var targetPair = targetGenerator.GenerateKeyPair();
        var targetPrivate = (Ed25519PrivateKeyParameters)targetPair.Private;
        var targetPublic = (Ed25519PublicKeyParameters)targetPair.Public;
        var targetKeyId = options.GetValueOrDefault("--target-key-id") ?? "dotnet-packaging-target-v1";
        var policyId = options.GetValueOrDefault("--policy-id") ?? "dotnet-packaging-only";

        using (var stream = File.CreateText(Path.Combine(targetKeys, targetKeyId + ".pem")))
        {
            var writer = new OpenSslPemWriter(stream);
            var info = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(targetPublic);
            writer.WriteObject(new BouncyPemObject("PUBLIC KEY", info.GetEncoded()));
        }

        var unsigned = new SortedDictionary<string, object?>(StringComparer.Ordinal)
        {
            ["schema"] = "bke.install-target-policy.v1",
            ["policy_id"] = policyId,
            ["revision"] = 1,
            ["product_id"] = "bke-certification-product",
            ["platform"] = "windows",
            ["architecture"] = "x86_64",
            ["install_root"] = @"C:\Program Files\BKE Digital Solutions\Certification Product",
            ["entry_point"] = "product.exe",
            ["signing_key_id"] = targetKeyId,
            ["algorithm"] = "Ed25519",
        };
        var canonical = Canonical(unsigned);
        var signer = new Ed25519Signer();
        signer.Init(true, targetPrivate);
        signer.BlockUpdate(canonical, 0, canonical.Length);
        var policy = new SortedDictionary<string, object?>(unsigned, StringComparer.Ordinal)
        {
            ["signature"] = Convert.ToBase64String(signer.GenerateSignature()),
        };
        File.WriteAllText(
            Path.Combine(targetPolicies, policyId + ".json"),
            JsonSerializer.Serialize(policy, JsonIndented) + Environment.NewLine,
            new UTF8Encoding(false));

        var updateGenerator = new Ed25519KeyPairGenerator();
        updateGenerator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        var updatePair = updateGenerator.GenerateKeyPair();
        var updatePublic = (Ed25519PublicKeyParameters)updatePair.Public;
        var updateKeyId = options.GetValueOrDefault("--update-key-id") ?? "dotnet-packaging-update-v1";
        var updateDocument = new SortedDictionary<string, object?>(StringComparer.Ordinal)
        {
            ["schema"] = "bke.update-authority-key.v1",
            ["key_id"] = updateKeyId,
            ["algorithm"] = "Ed25519",
            ["public_key"] = Convert.ToBase64String(updatePublic.GetEncoded()),
        };
        File.WriteAllText(
            Path.Combine(updateKeys, updateKeyId + ".json"),
            JsonSerializer.Serialize(updateDocument) + Environment.NewLine,
            new UTF8Encoding(false));

        Console.WriteLine("Disposable .NET packaging trust generated.");
        return 0;
    }

    private static int GenerateProductionUpdateKey(string[] args)
    {
        var options = Parse(args);
        if (Required(options, "--authorization") != "AUTHORIZE_OFFLINE_PRODUCTION_KEY_GENERATION")
            throw new InvalidDataException("exact production-key generation authorization token is required");

        var keyId = Required(options, "--key-id");
        if (!System.Text.RegularExpressions.Regex.IsMatch(keyId, "^[A-Za-z0-9._-]{1,160}$"))
            throw new InvalidDataException("production key ID is malformed");

        var output = Path.GetFullPath(Required(options, "--output-dir"));
        if (InsideGitTree(output))
            throw new InvalidDataException("refusing to write production private key material inside a Git repository");
        if (Directory.Exists(output) || File.Exists(output))
            throw new IOException("production key output directory already exists");
        Directory.CreateDirectory(output);

        var generator = new Ed25519KeyPairGenerator();
        generator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        var pair = generator.GenerateKeyPair();
        var privateKey = (Ed25519PrivateKeyParameters)pair.Private;
        var publicKey = (Ed25519PublicKeyParameters)pair.Public;

        var privateInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);
        var privatePath = Path.Combine(output, "BKE-UPDATE-AUTHORITY-PRIVATE.pem");
        using (var stream = File.CreateText(privatePath))
        {
            var writer = new OpenSslPemWriter(stream);
            writer.WriteObject(new BouncyPemObject("PRIVATE KEY", privateInfo.GetEncoded()));
        }

        var publicDocument = new SortedDictionary<string, object?>(StringComparer.Ordinal)
        {
            ["schema"] = "bke.update-authority-key.v1",
            ["key_id"] = keyId,
            ["algorithm"] = "Ed25519",
            ["public_key"] = Convert.ToBase64String(publicKey.GetEncoded()),
        };
        File.WriteAllText(
            Path.Combine(output, keyId + ".json"),
            JsonSerializer.Serialize(publicDocument) + Environment.NewLine,
            new UTF8Encoding(false));

        var fingerprint = Convert.ToHexString(SHA256.HashData(publicKey.GetEncoded())).ToLowerInvariant();
        File.WriteAllText(Path.Combine(output, "PUBLIC-KEY-SHA256.txt"), fingerprint + Environment.NewLine, Encoding.ASCII);
        File.WriteAllText(
            Path.Combine(output, "README-PRIVATE-KEY.txt"),
            $"PRIVATE KEY HANDLING{Environment.NewLine}Do not commit or package BKE-UPDATE-AUTHORITY-PRIVATE.pem.{Environment.NewLine}key_id={keyId}{Environment.NewLine}public_key_sha256={fingerprint}{Environment.NewLine}",
            new UTF8Encoding(false));

        Console.WriteLine("Production update-authority keypair generated offline.");
        Console.WriteLine($"key_id={keyId}");
        Console.WriteLine($"public_key_sha256={fingerprint}");
        Console.WriteLine("PRIVATE KEY WAS NOT PRINTED.");
        return 0;
    }

    private static int BuildSigningRequest(string[] args)
    {
        var options = Parse(args);
        var manifestPath = Path.GetFullPath(Required(options, "--manifest"));
        var outputPath = Path.GetFullPath(Required(options, "--output"));
        using var document = JsonDocument.Parse(File.ReadAllText(manifestPath));
        var root = document.RootElement;

        if (RequiredString(root, "schema") != "bke.production-release-preflight.v1" ||
            RequiredString(root, "status") != "PASS" ||
            root.GetProperty("production_ready").ValueKind != JsonValueKind.False ||
            RequiredString(root, "signing_state") != "NOT_SIGNED" ||
            RequiredString(root, "production_update_authority") != "NOT_ACTIVATED" ||
            RequiredString(root, "production_catalog_publication") != "NOT_AUTHORIZED" ||
            RequiredString(root, "production_deployment") != "NOT_AUTHORIZED")
        {
            throw new InvalidDataException("preflight manifest is not eligible for a signing request");
        }

        var architectures = root.GetProperty("architectures").EnumerateArray()
            .Select(item => item.GetString()).Where(item => item is not null).Cast<string>().ToHashSet(StringComparer.Ordinal);
        if (!architectures.SetEquals(["x64", "arm64"]))
            throw new InvalidDataException("expected exactly x64 + arm64 release architectures");

        var installers = root.GetProperty("installers");
        var artifacts = new List<Dictionary<string, object?>>();
        foreach (var architecture in new[] { "x64", "arm64" })
        {
            var item = installers.GetProperty(architecture);
            var hash = RequiredString(item, "sha256");
            if (!System.Text.RegularExpressions.Regex.IsMatch(hash, "^[a-f0-9]{64}$"))
                throw new InvalidDataException($"{architecture} SHA-256 is invalid");
            var bytes = item.GetProperty("bytes").GetInt64();
            if (bytes <= 0) throw new InvalidDataException($"{architecture} byte size is invalid");
            var auth = RequiredString(item, "authenticode_status");
            if (auth == "Valid") throw new InvalidDataException($"{architecture} installer is already Authenticode-valid");

            artifacts.Add(new Dictionary<string, object?>
            {
                ["architecture"] = architecture,
                ["file"] = RequiredString(item, "file"),
                ["unsigned_sha256"] = hash,
                ["unsigned_bytes"] = bytes,
                ["pre_sign_authenticode_status"] = auth,
            });
        }

        var result = new Dictionary<string, object?>
        {
            ["schema"] = "bke.production-signing-request.v1",
            ["source_sha"] = RequiredString(root, "source_sha"),
            ["version"] = RequiredString(root, "version"),
            ["artifacts"] = artifacts,
            ["windows_signing"] = new Dictionary<string, object?>
            {
                ["required"] = true,
                ["approved_signer_subject"] = null,
                ["approved_signer_thumbprint"] = null,
                ["authorization_state"] = "OWNER_AUTHORIZATION_REQUIRED",
            },
            ["update_authority"] = new Dictionary<string, object?>
            {
                ["required"] = true,
                ["production_key_id"] = null,
                ["authorization_state"] = "OWNER_AUTHORIZATION_REQUIRED",
            },
            ["production_catalog_publication"] = "NOT_AUTHORIZED",
            ["production_deployment"] = "NOT_AUTHORIZED",
            ["signing_authorized"] = false,
            ["publish_allowed"] = false,
        };

        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
        File.WriteAllText(outputPath, JsonSerializer.Serialize(result, JsonIndented) + Environment.NewLine, new UTF8Encoding(false));
        Console.WriteLine(outputPath);
        return 0;
    }

    private static Dictionary<string, string> Parse(string[] args)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = 0; index < args.Length; index++)
        {
            var name = args[index];
            if (!name.StartsWith("--", StringComparison.Ordinal) || index + 1 >= args.Length)
                throw new InvalidDataException($"invalid release tooling argument: {name}");
            if (!result.TryAdd(name, args[++index]))
                throw new InvalidDataException($"duplicate release tooling argument: {name}");
        }
        return result;
    }

    private static string Required(IReadOnlyDictionary<string, string> options, string name) =>
        options.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : throw new InvalidDataException($"{name} is required");

    private static bool InsideGitTree(string path)
    {
        var current = new DirectoryInfo(path);
        while (current is not null)
        {
            if (Directory.Exists(Path.Combine(current.FullName, ".git"))) return true;
            current = current.Parent;
        }
        return false;
    }

    private static string RequiredString(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(value.GetString()))
            throw new InvalidDataException($"{name} is required");
        return value.GetString()!;
    }

    private static byte[] Canonical(object value) =>
        JsonSerializer.SerializeToUtf8Bytes(value, new JsonSerializerOptions
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            WriteIndented = false,
        });

    private static readonly JsonSerializerOptions JsonIndented = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };
}
