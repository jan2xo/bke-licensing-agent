using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO.Pem;

namespace BKE.LicensingAgent.Infrastructure;

/// <summary>
/// Reusable, local-only consumer of bke.product-lease.v1. This does NOT issue
/// entitlements, verify Agent proof-of-possession, or grant product execution.
/// DS owns issuance; the authentic product must independently enforce PoP.
/// </summary>
public static class AccountProductLeaseJwsVerifier
{
    private const string LeaseSchema = "bke.product-lease.v1";
    private const string LeaseTyp = "bke.product-lease.v1+jws";
    private static readonly Regex KidPattern = new(
        "^[A-Za-z0-9._-]{1,128}$", RegexOptions.CultureInvariant);
    private static readonly Regex Base64UrlPattern = new(
        "^[A-Za-z0-9_-]+$", RegexOptions.CultureInvariant);
    private static readonly Regex ThumbprintPattern = new(
        "^[A-Za-z0-9_-]{43}$", RegexOptions.CultureInvariant);
    private static readonly HashSet<string> HeaderFields =
        new(["alg", "kid", "typ"], StringComparer.Ordinal);
    private static readonly HashSet<string> ClaimFields = new(
        [
            "schema", "issuer", "audience", "leaseId", "accountId", "userId",
            "productId", "agentSessionId", "agentKeyThumbprint",
            "keyProtection", "plan", "allowedActions", "issuedAt",
            "refreshAfter", "expiresAt",
        ], StringComparer.Ordinal);
    private const string TimestampFormat = "yyyy-MM-dd'T'HH:mm:ss.fff'Z'";

    public static AccountProductLeaseCheck Verify(
        string jws,
        IReadOnlyDictionary<string, AccountProductLeaseTrustedKey> trustedKeys,
        AccountProductLeaseExpected expected)
    {
        if (string.IsNullOrEmpty(jws) || jws.Length > 16384)
            return Bad("MALFORMED_JWS");

        var pieces = jws.Split('.');
        if (pieces.Length != 3 || pieces.Any(string.IsNullOrEmpty))
            return Bad("MALFORMED_JWS");

        var headerBytes = DecodeCanonicalBase64Url(pieces[0]);
        var payloadBytes = DecodeCanonicalBase64Url(pieces[1]);
        var signature = DecodeCanonicalBase64Url(pieces[2]);
        if (headerBytes is null || payloadBytes is null ||
            signature is null || signature.Length != 64)
            return Bad("MALFORMED_JWS");

        using var header = ParseStrictJson(headerBytes);
        if (header is null || !ExactFields(header.RootElement, HeaderFields) ||
            ReadBoundedText(header.RootElement, "alg", 32) != "EdDSA" ||
            ReadBoundedText(header.RootElement, "typ", 128) != LeaseTyp)
            return Bad("MALFORMED_JWS");

        var kid = ReadBoundedText(header.RootElement, "kid", 128);
        if (kid is null || !KidPattern.IsMatch(kid))
            return Bad("MALFORMED_JWS");

        if (!trustedKeys.TryGetValue(kid, out var key) || key is null ||
            key.State is not ("ACTIVE" or "VERIFY_ONLY"))
            return Bad("UNTRUSTED_KID");

        var signingInput = Encoding.ASCII.GetBytes(pieces[0] + "." + pieces[1]);
        if (!VerifySignature(key.PublicKeyPem, signingInput, signature))
            return Bad("INVALID_SIGNATURE");

        using var payload = ParseStrictJson(payloadBytes);
        if (payload is null || !TryReadClaims(payload.RootElement, out var claims))
            return Bad("INVALID_CLAIMS");

        if (claims!.Issuer != expected.Issuer ||
            claims.Audience != expected.Audience ||
            claims.AccountId != expected.AccountId ||
            claims.UserId != expected.UserId ||
            claims.ProductId != expected.ProductId ||
            claims.AgentSessionId != expected.AgentSessionId ||
            claims.AgentKeyThumbprint != expected.AgentKeyThumbprint ||
            !claims.AllowedActions.Contains(expected.Action, StringComparer.Ordinal))
            return Bad("CLAIM_MISMATCH");

        if (expected.AllowedFutureSkewMs < 0 || expected.AllowedFutureSkewMs > 300000)
            return Bad("INVALID_CLAIMS");
        if (claims.IssuedAt > expected.Now.AddMilliseconds(expected.AllowedFutureSkewMs))
            return Bad("FUTURE_ISSUED_AT");
        if (expected.Now >= claims.ExpiresAt)
            return Bad("EXPIRED");

        return new AccountProductLeaseCheck(true, null, kid, claims);
    }

    private static AccountProductLeaseCheck Bad(string reason) =>
        new(false, reason);

    private static byte[]? DecodeCanonicalBase64Url(string token)
    {
        if (token.Length is < 1 or > 16384 || !Base64UrlPattern.IsMatch(token))
            return null;
        if (token.Length % 4 == 1) return null;
        try
        {
            var input = token.Replace('-', '+').Replace('_', '/');
            input = input.PadRight(input.Length + (4 - input.Length % 4) % 4, '=');
            var decoded = Convert.FromBase64String(input);
            var canonical = Convert.ToBase64String(decoded)
                .TrimEnd('=').Replace('+', '-').Replace('/', '_');
            return canonical == token ? decoded : null;
        }
        catch (FormatException) { return null; }
    }

    private static JsonDocument? ParseStrictJson(byte[] bytes)
    {
        // System.Text.Json has permissive duplicate-member semantics unless
        // explicitly checked. Forbid overlong/lossy UTF-8 and any UTF-8 BOM.
        if (bytes.Length >= 3 && bytes[0] == 0xef && bytes[1] == 0xbb &&
            bytes[2] == 0xbf)
            return null;
        try
        {
            _ = new UTF8Encoding(false, true).GetString(bytes);
            var doc = JsonDocument.Parse(bytes, new JsonDocumentOptions
            {
                MaxDepth = 32,
                CommentHandling = JsonCommentHandling.Disallow,
                AllowTrailingCommas = false,
            });
            try
            {
                RejectDuplicateMembers(doc.RootElement);
                return doc;
            }
            catch
            {
                doc.Dispose();
                return null;
            }
        }
        catch (Exception ex) when (
            ex is DecoderFallbackException or JsonException or ArgumentException)
        {
            return null;
        }
    }

    private static void RejectDuplicateMembers(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in value.EnumerateObject())
            {
                // Property.Name is already unescaped: "product\u0049d"
                // and "productId" collide, as required by the TS contract.
                if (!names.Add(property.Name))
                    throw new FormatException("DUPLICATE_JSON_MEMBER");
                RejectDuplicateMembers(property.Value);
            }
        }
        else if (value.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in value.EnumerateArray())
                RejectDuplicateMembers(item);
        }
    }

    private static bool ExactFields(JsonElement value, HashSet<string> fields)
    {
        if (value.ValueKind != JsonValueKind.Object) return false;
        var found = value.EnumerateObject().Select(item => item.Name).ToArray();
        return found.Length == fields.Count && found.All(fields.Contains);
    }

    private static string? ReadBoundedText(JsonElement root, string name, int max = 128)
    {
        if (!root.TryGetProperty(name, out var element) ||
            element.ValueKind != JsonValueKind.String)
            return null;
        var value = element.GetString();
        return value is not null && value.Length > 0 &&
            value.Length <= max && value.Trim() == value ? value : null;
    }

    private static bool TryTime(JsonElement root, string field, out DateTimeOffset value)
    {
        value = default;
        var raw = ReadBoundedText(root, field, 32);
        return raw is not null &&
            DateTimeOffset.TryParseExact(
                raw, TimestampFormat, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out value) &&
            value.ToString(TimestampFormat, CultureInfo.InvariantCulture) == raw;
    }

    private static bool TryReadClaims(
        JsonElement element, out AccountProductLeaseClaims? claims)
    {
        claims = null;
        if (!ExactFields(element, ClaimFields)) return false;
        if (ReadBoundedText(element, "schema", 64) != LeaseSchema) return false;
        var issuer = ReadBoundedText(element, "issuer", 256);
        var audience = ReadBoundedText(element, "audience", 256);
        var leaseId = ReadBoundedText(element, "leaseId");
        var accountId = ReadBoundedText(element, "accountId");
        var userId = ReadBoundedText(element, "userId");
        var productId = ReadBoundedText(element, "productId");
        var sessionId = ReadBoundedText(element, "agentSessionId");
        var thumbprint = ReadBoundedText(element, "agentKeyThumbprint");
        var protection = ReadBoundedText(element, "keyProtection");
        var plan = ReadBoundedText(element, "plan");
        if (issuer is null || audience is null || leaseId is null ||
            accountId is null || userId is null || productId is null ||
            sessionId is null || thumbprint is null ||
            !ThumbprintPattern.IsMatch(thumbprint) ||
            protection is not ("tpm" or "software") || plan is null)
            return false;

        if (!element.TryGetProperty("allowedActions", out var actionsElement) ||
            actionsElement.ValueKind != JsonValueKind.Array)
            return false;
        var actions = new List<string>();
        foreach (var action in actionsElement.EnumerateArray())
        {
            if (action.ValueKind != JsonValueKind.String) return false;
            var word = action.GetString();
            if (word is not ("OPEN" or "USE") || actions.Contains(word))
                return false;
            actions.Add(word);
        }
        if (actions.Count is < 1 or > 2) return false;

        if (!TryTime(element, "issuedAt", out var issued) ||
            !TryTime(element, "refreshAfter", out var refresh) ||
            !TryTime(element, "expiresAt", out var expiry) ||
            issued > refresh || refresh >= expiry)
            return false;

        claims = new AccountProductLeaseClaims(
            LeaseSchema, issuer, audience, leaseId, accountId, userId,
            productId, sessionId, thumbprint, protection, plan,
            actions.ToArray(), issued, refresh, expiry);
        return true;
    }

    private static bool VerifySignature(
        string publicKeyPem, byte[] signingInput, byte[] signature)
    {
        try
        {
            using var reader = new StringReader(publicKeyPem);
            var objectReader = new PemReader(reader);
            var pem = objectReader.ReadPemObject();
            if (pem is null || pem.Type != "PUBLIC KEY") return false;
            var publicKey = PublicKeyFactory.CreateKey(pem.Content);
            if (publicKey is not Ed25519PublicKeyParameters edKey)
                return false;
            var verifier = new Ed25519Signer();
            verifier.Init(false, edKey);
            verifier.BlockUpdate(signingInput, 0, signingInput.Length);
            return verifier.VerifySignature(signature);
        }
        catch { return false; }
    }
}

public sealed record AccountProductLeaseTrustedKey(
    string PublicKeyPem, string State);

public sealed record AccountProductLeaseExpected(
    string Issuer,
    string Audience,
    string AccountId,
    string UserId,
    string ProductId,
    string AgentSessionId,
    string AgentKeyThumbprint,
    string Action,
    DateTimeOffset Now,
    long AllowedFutureSkewMs = 300000);

public sealed record AccountProductLeaseClaims(
    string Schema,
    string Issuer,
    string Audience,
    string LeaseId,
    string AccountId,
    string UserId,
    string ProductId,
    string AgentSessionId,
    string AgentKeyThumbprint,
    string KeyProtection,
    string Plan,
    string[] AllowedActions,
    DateTimeOffset IssuedAt,
    DateTimeOffset RefreshAfter,
    DateTimeOffset ExpiresAt);

public sealed record AccountProductLeaseCheck(
    bool Ok, string? Reason, string? Kid = null,
    AccountProductLeaseClaims? Claims = null);
