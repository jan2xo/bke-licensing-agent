using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO.Pem;

namespace BKE.LicensingAgent.Provisioner;

internal static class Program
{
    private const string SigningKeyId = "agent-machine-ed25519-v1";
    private static readonly HashSet<string> TargetPolicyFields = new(StringComparer.Ordinal)
    {
        "schema", "policy_id", "revision", "product_id", "platform", "architecture",
        "install_root", "entry_point", "signing_key_id", "algorithm", "signature",
    };

    public static int Main()
    {
        try
        {
            if (!OperatingSystem.IsWindows())
            {
                throw new InvalidOperationException("Windows privileged provisioning must run on Windows");
            }

            Provision();
            Console.WriteLine("BKE privileged runtime provisioning complete");
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"BKE privileged runtime provisioning failed: {exception.Message}");
            return 1;
        }
    }

    private static void Provision()
    {
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        var installRoot = Path.Combine(programFiles, "BKE Digital Solutions", "Licensing Agent");
        var dataRoot = Path.Combine(programData, "BKE Digital Solutions", "Licensing Agent");
        var privileged = Path.Combine(dataRoot, "privileged");
        var runtimeRoot = Path.Combine(privileged, "runtime");
        var helperExecutable = Path.Combine(installRoot, "updater", "bke-updater-core.exe");
        var signingPrivateKey = Path.Combine(privileged, "agent-request-signing.pem");
        var targetKeysDirectory = Path.Combine(privileged, "target-keys");
        var targetPoliciesDirectory = Path.Combine(privileged, "target-policies");
        var sourceRoot = Path.Combine(installRoot, "provisioning");
        var sourceKeys = Path.Combine(sourceRoot, "target-keys");
        var sourcePolicies = Path.Combine(sourceRoot, "target-policies");
        var configPath = Path.Combine(dataRoot, "privileged-update.json");

        if (!File.Exists(helperExecutable))
        {
            throw new InvalidDataException("trusted .NET updater helper is missing");
        }

        var keys = ValidatePublicKeys(sourceKeys);
        ValidatePolicies(sourcePolicies, keys);

        Directory.CreateDirectory(dataRoot);
        Directory.CreateDirectory(runtimeRoot);
        Protect(dataRoot);
        Protect(runtimeRoot);

        EnsureMachineSigningKey(signingPrivateKey);
        ReplaceDirectory(sourceKeys, targetKeysDirectory, ".staging");
        ReplaceDirectory(sourcePolicies, targetPoliciesDirectory, ".staging");

        var config = new SortedDictionary<string, object?>(StringComparer.Ordinal)
        {
            ["runtime_root"] = runtimeRoot,
            ["helper_executable"] = helperExecutable,
            ["signing_key_id"] = SigningKeyId,
            ["signing_private_key"] = signingPrivateKey,
            ["target_keys_dir"] = targetKeysDirectory,
            ["target_policies_dir"] = targetPoliciesDirectory,
            ["approved_install_roots"] = new[] { Path.Combine(programFiles, "BKE Digital Solutions") },
            ["expected_channel"] = "stable",
        };
        var temporary = configPath + ".tmp";
        File.WriteAllText(
            temporary,
            JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true }),
            new UTF8Encoding(false));
        File.Move(temporary, configPath, true);

        foreach (var path in new[]
                 {
                     dataRoot, runtimeRoot, signingPrivateKey,
                     targetKeysDirectory, targetPoliciesDirectory, configPath,
                 })
        {
            Protect(path);
        }
    }

    private static Dictionary<string, Ed25519PublicKeyParameters> ValidatePublicKeys(string directory)
    {
        if (!Directory.Exists(directory))
        {
            throw new InvalidDataException($"provisioning source unavailable: {directory}");
        }

        var result = new Dictionary<string, Ed25519PublicKeyParameters>(StringComparer.Ordinal);
        foreach (var path in Directory.EnumerateFiles(directory, "*.pem").OrderBy(value => value, StringComparer.Ordinal))
        {
            using var reader = new StreamReader(path, Encoding.ASCII, detectEncodingFromByteOrderMarks: true);
            var pem = new OpenSslPemReader(reader).ReadObject();
            var key = pem switch
            {
                Ed25519PublicKeyParameters direct => direct,
                AsymmetricCipherKeyPair pair when pair.Public is Ed25519PublicKeyParameters publicKey => publicKey,
                _ => throw new InvalidDataException($"BKE target key must be Ed25519: {Path.GetFileName(path)}"),
            };
            result[Path.GetFileNameWithoutExtension(path)] = key;
        }

        if (result.Count == 0)
        {
            throw new InvalidDataException("at least one BKE target public key is required");
        }
        return result;
    }

    private static void ValidatePolicies(
        string directory,
        IReadOnlyDictionary<string, Ed25519PublicKeyParameters> keys)
    {
        if (!Directory.Exists(directory))
        {
            throw new InvalidDataException($"provisioning source unavailable: {directory}");
        }

        var paths = Directory.EnumerateFiles(directory, "*.json").OrderBy(value => value, StringComparer.Ordinal).ToArray();
        if (paths.Length == 0)
        {
            throw new InvalidDataException("at least one signed BKE target policy is required");
        }

        foreach (var path in paths)
        {
            using var document = JsonDocument.Parse(File.ReadAllText(path));
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !root.EnumerateObject().Select(property => property.Name).ToHashSet(StringComparer.Ordinal).SetEquals(TargetPolicyFields) ||
                RequiredString(root, "schema") != "bke.install-target-policy.v1" ||
                RequiredString(root, "algorithm") != "Ed25519")
            {
                throw new InvalidDataException($"unsupported target policy contract: {Path.GetFileName(path)}");
            }

            var keyId = RequiredString(root, "signing_key_id");
            if (!keys.TryGetValue(keyId, out var key))
            {
                throw new InvalidDataException($"unknown BKE target signing key: {Path.GetFileName(path)}");
            }

            byte[] signature;
            try
            {
                signature = Convert.FromBase64String(RequiredString(root, "signature"));
            }
            catch (FormatException exception)
            {
                throw new InvalidDataException($"invalid target policy signature: {Path.GetFileName(path)}", exception);
            }

            var unsigned = root.EnumerateObject()
                .Where(property => property.Name != "signature")
                .OrderBy(property => property.Name, StringComparer.Ordinal)
                .ToDictionary(
                    property => property.Name,
                    property => JsonSerializer.Deserialize<object?>(property.Value.GetRawText()),
                    StringComparer.Ordinal);
            var canonical = JsonSerializer.SerializeToUtf8Bytes(
                unsigned,
                new JsonSerializerOptions
                {
                    Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                    WriteIndented = false,
                });

            var verifier = new Ed25519Signer();
            verifier.Init(false, key);
            verifier.BlockUpdate(canonical, 0, canonical.Length);
            if (!verifier.VerifySignature(signature))
            {
                throw new InvalidDataException($"invalid target policy signature: {Path.GetFileName(path)}");
            }
        }
    }

    private static void EnsureMachineSigningKey(string path)
    {
        if (File.Exists(path))
        {
            using var reader = new StreamReader(path, Encoding.ASCII, detectEncodingFromByteOrderMarks: true);
            var existing = new OpenSslPemReader(reader).ReadObject();
            var isEd25519 = existing is Ed25519PrivateKeyParameters ||
                            existing is AsymmetricCipherKeyPair pair && pair.Private is Ed25519PrivateKeyParameters;
            if (!isEd25519)
            {
                throw new InvalidDataException("existing Agent privileged signing key must be Ed25519");
            }
            return;
        }

        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var generator = new Ed25519KeyPairGenerator();
        generator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        var keyPair = generator.GenerateKeyPair();
        var privateInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private);

        var temporary = path + "." + Guid.NewGuid().ToString("N");
        using (var stream = File.CreateText(temporary))
        {
            var writer = new OpenSslPemWriter(stream);
            writer.WriteObject(new BouncyPemObject("PRIVATE KEY", privateInfo.GetEncoded()));
            stream.Flush();
        }
        File.Move(temporary, path);
    }

    private static void ReplaceDirectory(string source, string destination, string suffix)
    {
        if (!Directory.Exists(source))
        {
            throw new InvalidDataException($"provisioning source unavailable: {source}");
        }

        var staging = destination + suffix;
        var previous = destination + ".previous";
        if (Directory.Exists(staging)) Directory.Delete(staging, true);
        CopyDirectory(source, staging);
        if (Directory.Exists(previous)) Directory.Delete(previous, true);
        if (Directory.Exists(destination)) Directory.Move(destination, previous);
        Directory.Move(staging, destination);
        if (Directory.Exists(previous)) Directory.Delete(previous, true);
    }

    private static void CopyDirectory(string source, string destination)
    {
        Directory.CreateDirectory(destination);
        foreach (var file in Directory.EnumerateFiles(source))
        {
            File.Copy(file, Path.Combine(destination, Path.GetFileName(file)), overwrite: true);
        }
        foreach (var directory in Directory.EnumerateDirectories(source))
        {
            CopyDirectory(directory, Path.Combine(destination, Path.GetFileName(directory)));
        }
    }

    private static void Protect(string path)
    {
        var isDirectory = Directory.Exists(path);
        if (!isDirectory && !File.Exists(path))
        {
            throw new InvalidDataException($"cannot protect missing path: {path}");
        }

        var start = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.SystemDirectory, "icacls.exe"),
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        start.ArgumentList.Add(path);
        start.ArgumentList.Add("/inheritance:r");
        start.ArgumentList.Add("/grant:r");
        start.ArgumentList.Add(isDirectory ? "SYSTEM:(OI)(CI)F" : "SYSTEM:F");
        start.ArgumentList.Add(isDirectory ? "*S-1-5-32-544:(OI)(CI)F" : "*S-1-5-32-544:F");

        using var process = Process.Start(start) ?? throw new InvalidOperationException("icacls could not start");
        process.WaitForExit();
        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"icacls failed for {path}: {process.StandardError.ReadToEnd().Trim()}");
        }
    }

    private static string RequiredString(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var value) ||
            value.ValueKind != JsonValueKind.String ||
            string.IsNullOrWhiteSpace(value.GetString()))
        {
            throw new InvalidDataException($"target policy is missing {name}");
        }
        return value.GetString()!;
    }
}
