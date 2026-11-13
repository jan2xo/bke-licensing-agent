using System.Buffers;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace BKE.LicensingAgent.Infrastructure;

/// <summary>
/// Exact Windows facts observed by the privileged installed Agent, never by
/// an HTTP caller or mutable product manifest.
/// </summary>
public sealed record InstalledStartupPolicyScope(
    string ProductId, string Version, string InstallationId,
    string ImagePath, string ImageSha256, string AllowedUserSid);

/// <summary>
/// One-shot, installed-provisioner initiated PREPRODUCTION-only acquisition.
/// Digital Solutions owns signing, SQL mode, attestation nonce and audit.
/// The Agent independently checks installed public trust and exact observed
/// machine/installation facts before a privileged installer may persist bytes.
/// No Host listener, key enrollment, user login or production fallback.
/// </summary>
public static class PreproductionStartupPolicyAcquisition
{
    // The immutable, certified merge of DS PR #372; this SHA is NOT the
    // different historical signer_source_sha embedded in the signed payload.
    public const string ExactDigitalSolutionsTransportSha =
        "b282c8d1664efd6a59df9672a549b313343fa508";
    public const string Protocol = "bke.installed-startup-issuance.v1";
    public const string RelativeRoute = "/api/agent-sessions/startup-policy";
    private const int MaxEnvelopeBytes = 16384;
    private const int MaxResponseBytes = 24576;
    private const int MaxAttestationBytes = 7000;
    private static readonly HashSet<string> ResponseFields = new(
        ["status", "signed_policy_envelope", "kid", "activation_mode", "expires_at"],
        StringComparer.Ordinal);

    public static void RequirePreproductionOrigin(Uri origin)
    {
        if (!origin.IsAbsoluteUri ||
            origin.Scheme != Uri.UriSchemeHttps &&
            !(origin.Scheme == Uri.UriSchemeHttp && origin.IsLoopback) ||
            !string.IsNullOrEmpty(origin.UserInfo) ||
            !string.IsNullOrEmpty(origin.Query) ||
            !string.IsNullOrEmpty(origin.Fragment) ||
            origin.AbsolutePath != "/" ||
            origin.Host.Equals("jl-bke.com", StringComparison.OrdinalIgnoreCase) ||
            origin.Host.EndsWith(".jl-bke.com", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Approved preproduction DS origin unavailable.");
    }

    public static async Task<string> AcquireVerifiedAsync(
        HttpClient client, Uri origin, string signedInstalledAttestation,
        InstalledStartupPolicyScope observed,
        IReadOnlyDictionary<string, AccountProductLeaseTrustedKey> installedIssuerKeys,
        string protectedProgramFilesRoot,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        RequirePreproductionOrigin(origin);
        if (client is null || installedIssuerKeys is null || observed is null ||
            string.IsNullOrWhiteSpace(signedInstalledAttestation) ||
            Encoding.UTF8.GetByteCount(signedInstalledAttestation) > MaxAttestationBytes ||
            now.Offset != TimeSpan.Zero ||
            string.IsNullOrWhiteSpace(protectedProgramFilesRoot))
            throw new InvalidDataException("Preproduction installed startup request invalid.");

        // A separate explicit protocol, no ambient cookies, user login or
        // commercial license key in transport. Credential authorization stays
        // inside the installed Agent's startup service after policy retrieval.
        var body = JsonSerializer.Serialize(new {
            signed_install_attestation = signedInstalledAttestation,
        });
        using var req = new HttpRequestMessage(HttpMethod.Post,
            new Uri(origin, RelativeRoute));
        req.Headers.TryAddWithoutValidation("x-bke-startup-policy-protocol", Protocol);
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        req.Content = new StringContent(body, Encoding.UTF8, "application/json");
        using var response = await client.SendAsync(req,
            HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        if (response.StatusCode != HttpStatusCode.Created ||
            !response.Headers.TryGetValues("x-bke-startup-policy-protocol", out var protocols) ||
            !protocols.SequenceEqual([Protocol]) ||
            response.Headers.Location is not null ||
            response.Headers.Contains("set-cookie") ||
            response.Content.Headers.ContentType?.MediaType != "application/json" ||
            response.Content.Headers.ContentLength > MaxResponseBytes)
            throw new InvalidDataException("Preproduction startup issuer response untrusted.");

        await using var input = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var memory = new MemoryStream();
        var buffer = ArrayPool<byte>.Shared.Rent(4096);
        try
        {
            int count;
            while ((count = await input.ReadAsync(buffer.AsMemory(0, buffer.Length),
                       cancellationToken)) != 0)
            {
                if (memory.Length + count > MaxResponseBytes)
                    throw new InvalidDataException("Startup issuer response too large.");
                memory.Write(buffer, 0, count);
            }
        }
        finally { ArrayPool<byte>.Shared.Return(buffer, clearArray: true); }
        var responseBytes = memory.ToArray();
        try
        {
            string raw;
            try { raw = new UTF8Encoding(false, true).GetString(responseBytes); }
            catch (DecoderFallbackException) {
                throw new InvalidDataException("Invalid startup response encoding.");
            }
            return ValidateSignedResponse(raw, observed, installedIssuerKeys,
                protectedProgramFilesRoot, now);
        }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(responseBytes); }
    }

    /// <summary>
    /// Strict transport-to-installed-issuer check. Called only after a
    /// nonproduction HTTP 201. The actual host always independently re-loads
    /// the same signed envelope from the protected installed trust root.
    /// </summary>
    public static string ValidateSignedResponse(
        string raw, InstalledStartupPolicyScope observed,
        IReadOnlyDictionary<string, AccountProductLeaseTrustedKey> installedIssuerKeys,
        string protectedProgramFilesRoot, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(raw) ||
            Encoding.UTF8.GetByteCount(raw) > MaxResponseBytes ||
            raw[0] == '\uFEFF' || observed is null || installedIssuerKeys is null)
            throw new InvalidDataException("Startup policy transport response invalid.");

        using var json = JsonDocument.Parse(raw, new JsonDocumentOptions {
            AllowTrailingCommas = false, CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 6,
        });
        var root = json.RootElement;
        var fields = root.ValueKind == JsonValueKind.Object
            ? root.EnumerateObject().Select(x => x.Name).ToArray()
            : [];
        if (fields.Length != ResponseFields.Count ||
            fields.Distinct(StringComparer.Ordinal).Count() != ResponseFields.Count ||
            fields.Any(x => !ResponseFields.Contains(x)))
            throw new InvalidDataException("Startup policy transport fields invalid.");

        static string Field(JsonElement row, string name, int maximum)
        {
            if (!row.TryGetProperty(name, out var value) ||
                value.ValueKind != JsonValueKind.String ||
                string.IsNullOrWhiteSpace(value.GetString()) ||
                value.GetString()!.Length > maximum)
                throw new InvalidDataException("Startup policy transport field unavailable.");
            return value.GetString()!;
        }
        if (Field(root, "status", 16) != "issued")
            throw new InvalidDataException("Startup policy was not issued.");
        var envelope = Field(root, "signed_policy_envelope", MaxEnvelopeBytes);
        if (Encoding.UTF8.GetByteCount(envelope) > MaxEnvelopeBytes)
            throw new InvalidDataException("Startup policy envelope too large.");
        var keyId = Field(root, "kid", 128);
        var activation = Field(root, "activation_mode", 16);
        var expiry = Field(root, "expires_at", 40);

        using var signed = JsonDocument.Parse(envelope);
        var signedRoot = signed.RootElement;
        if (signedRoot.ValueKind != JsonValueKind.Object ||
            !signedRoot.TryGetProperty("kid", out var signedKid) ||
            signedKid.ValueKind != JsonValueKind.String ||
            signedKid.GetString() != keyId)
            throw new InvalidDataException("Startup policy issuer identity mismatch.");
        var verified = InstalledStandaloneStartupPolicyRegistry.VerifyEnvelope(
            envelope, installedIssuerKeys, protectedProgramFilesRoot, now);
        if (verified.ProductId != observed.ProductId ||
            verified.Version != observed.Version ||
            verified.InstallationId != observed.InstallationId ||
            !string.Equals(verified.ImagePath, observed.ImagePath,
                StringComparison.OrdinalIgnoreCase) ||
            verified.ImageSha256 != observed.ImageSha256 ||
            verified.AllowedUserSid != observed.AllowedUserSid ||
            verified.ActivationMode != activation ||
            verified.ExpiresAt.ToString("O", CultureInfo.InvariantCulture) != expiry)
            throw new InvalidDataException(
                "Signed startup policy does not match the protected installed target.");

        return envelope;
    }
}
