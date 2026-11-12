using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO.Pem;

namespace BKE.LicensingAgent.Infrastructure;

/// <summary>
/// Public-only DS account-product issuer trust, exclusively from the
/// administrator-installed Agent trust payload under Program Files.
/// Never read trust from env/Launcher/catalog/network/user-writable data.
/// This is intentionally PREPRODUCTION only until separately authorized.
/// </summary>
public static class AccountProductLeaseInstalledTrust
{
    public const string BundleSchema = "bke.account-product-lease-trust.v1";
    public const string ExactIssuerSourceSha =
        "09c16bc5c7e1d6ab3cb8df0ba569e6da05498f3f";
    public const string ExactLibraryArchiveSha256 =
        "4d2f8e4295effcfd4aa3b6492944e8dbba3ec75e86c83727a30daa74e4f75d60";
    private static readonly Regex Kid = new(
        "^[A-Za-z0-9._-]{1,128}$", RegexOptions.CultureInvariant);
    private static readonly HashSet<string> TopFields = new(
        ["schema", "issuer_source_sha", "library_archive_sha256", "keys"],
        StringComparer.Ordinal);
    private static readonly HashSet<string> KeyFields = new(
        ["kid", "public_key_pem", "state"], StringComparer.Ordinal);

    public static IReadOnlyDictionary<string, AccountProductLeaseTrustedKey>
        LoadInstalled(string environment)
    {
        if (environment is not ("development" or "certification" or "utm") ||
            !OperatingSystem.IsWindows())
            throw new InvalidOperationException(
                "Installed account-product issuer trust is PREPRODUCTION Windows-only.");

        var programFiles = Environment.GetFolderPath(
            Environment.SpecialFolder.ProgramFiles);
        if (string.IsNullOrWhiteSpace(programFiles))
            throw new InvalidOperationException("Windows Program Files trust root is missing.");
        var installRoot = Path.Combine(programFiles,
            "BKE Digital Solutions", "Licensing Agent");
        var expectedRuntime = Path.GetFullPath(Path.Combine(installRoot, "runtime"));
        var actualRuntime = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(AppContext.BaseDirectory));
        if (!string.Equals(actualRuntime,
            Path.TrimEndingDirectorySeparator(expectedRuntime),
            StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException(
                "The Agent runtime is not in its administrator-installed directory.");

        var trustDir = Path.Combine(installRoot, "trust", "account-product-lease-keys");
        var file = Path.Combine(trustDir, "issuers.json");
        // No reparse-point hop is permitted between installed runtime and its
        // issuer bundle. Installer uses elevated Program Files ownership.
        foreach (var dir in new[] {
            installRoot, expectedRuntime,
            Path.Combine(installRoot, "trust"), trustDir
        })
        {
            var info = new DirectoryInfo(dir);
            if (!info.Exists || (info.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException(
                    "Installed Agent trust directory is missing or redirected.");
        }
        var bundle = new FileInfo(file);
        if (!bundle.Exists || bundle.Length is < 50 or > 32768 ||
            (bundle.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException(
                "Installed DS account issuer trust bundle is unavailable or redirected.");
        return Parse(File.ReadAllText(file, new UTF8Encoding(false, true)));
    }

    /// <summary>
    /// Parser is independently contract-certified. The installed file path,
    /// privilege and nonproduction invariant are enforced by LoadInstalled.
    /// </summary>
    internal static IReadOnlyDictionary<string, AccountProductLeaseTrustedKey>
        Parse(string text)
    {
        if (string.IsNullOrWhiteSpace(text) ||
            Encoding.UTF8.GetByteCount(text) > 32768 ||
            text[0] == '\uFEFF' ||
            text.Contains("PRIVATE KEY", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Issuer trust is empty, oversized or contains private material.");
        JsonDocument json;
        try {
            json = JsonDocument.Parse(text, new JsonDocumentOptions {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 8
            });
        }
        catch (JsonException error) {
            throw new InvalidDataException("Installed issuer trust is invalid JSON.", error);
        }
        using (json)
        {
            var root = json.RootElement;
            RequireExactFields(root, TopFields);
            if (Required(root, "schema") != BundleSchema ||
                Required(root, "issuer_source_sha") != ExactIssuerSourceSha ||
                Required(root, "library_archive_sha256") != ExactLibraryArchiveSha256)
                throw new InvalidDataException(
                    "Installed issuer trust has an unapproved protocol or source provenance.");
            if (!root.TryGetProperty("keys", out var keys) ||
                keys.ValueKind != JsonValueKind.Array ||
                keys.GetArrayLength() is < 1 or > 16)
                throw new InvalidDataException("Issuer keyset is missing or oversized.");

            var trusted = new Dictionary<string, AccountProductLeaseTrustedKey>(
                StringComparer.Ordinal);
            int active = 0;
            foreach (var item in keys.EnumerateArray())
            {
                RequireExactFields(item, KeyFields);
                var kid = Required(item, "kid");
                var publicPem = Required(item, "public_key_pem");
                var state = Required(item, "state");
                if (!Kid.IsMatch(kid) || publicPem.Length > 2048 ||
                    state is not ("ACTIVE" or "VERIFY_ONLY") ||
                    !ValidEd25519PublicKey(publicPem) ||
                    !trusted.TryAdd(kid,
                        new AccountProductLeaseTrustedKey(publicPem, state)))
                    throw new InvalidDataException(
                        "Installed DS issuer key is invalid, duplicate or untrusted.");
                if (state == "ACTIVE") active++;
            }
            if (active != 1)
                throw new InvalidDataException("Exactly one installed ACTIVE DS issuer is required.");
            return trusted;
        }
    }

    private static void RequireExactFields(
        JsonElement root, HashSet<string> fields)
    {
        if (root.ValueKind != JsonValueKind.Object ||
            root.EnumerateObject().Count() != fields.Count ||
            root.EnumerateObject().Select(x => x.Name).Distinct(StringComparer.Ordinal)
                .Count() != fields.Count ||
            root.EnumerateObject().Any(x => !fields.Contains(x.Name)))
            throw new InvalidDataException("Installed issuer trust has ambiguous fields.");
    }

    private static string Required(JsonElement value, string name)
    {
        if (!value.TryGetProperty(name, out var property) ||
            property.ValueKind != JsonValueKind.String)
            throw new InvalidDataException("Installed issuer trust field is missing.");
        var result = property.GetString();
        if (string.IsNullOrEmpty(result) ||
            result.Length > 4096 ||
            (name != "public_key_pem" && result.Trim() != result))
            throw new InvalidDataException("Installed issuer trust field is malformed.");
        return result;
    }

    private static bool ValidEd25519PublicKey(string value)
    {
        try
        {
            using var reader = new StringReader(value);
            var pem = new PemReader(reader).ReadPemObject();
            if (pem is null || pem.Type != "PUBLIC KEY" ||
                pem.Content.Length != 44 ||
                !reader.ReadToEnd().Trim().Equals("", StringComparison.Ordinal))
                return false;
            var canonical = "-----BEGIN PUBLIC KEY-----\n" +
                Convert.ToBase64String(pem.Content) +
                "\n-----END PUBLIC KEY-----\n";
            return string.Equals(value, canonical, StringComparison.Ordinal) &&
                PublicKeyFactory.CreateKey(pem.Content)
                    is Ed25519PublicKeyParameters;
        }
        catch { return false; }
    }
}
