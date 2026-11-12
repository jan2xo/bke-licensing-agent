using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using BKE.LicensingAgent.Application;

namespace BKE.LicensingAgent.Infrastructure;

/// <summary>
/// Source-only, Agent-owned consumer of DS's PREPRODUCTION account-product
/// JWS issuance. This is NOT installed product authorization or a local API.
/// The caller supplies an offline-pinned DS public-key trust set, NEVER
/// keys delivered alongside a lease or fetched from arbitrary network input.
/// No product execution can be granted by this class.
/// </summary>
public sealed class AgentAccountProductLeaseRemote : IDisposable
{
    private const string Protocol = "bke.account-session.v1";
    private static readonly Regex Scope = new(
        "^[A-Za-z0-9._-]{1,128}$", RegexOptions.CultureInvariant);
    private readonly IAgentMachineKeySigner _signer;
    private readonly Func<ActiveAccountSessionState, AgentEd25519SessionBinding> _binding;
    private readonly Func<AgentEd25519SessionBinding, AgentMachineKeyRegistrationReceipt?> _readReceipt;
    private readonly IReadOnlyDictionary<string, AccountProductLeaseTrustedKey> _trustedKeys;
    private readonly HttpClient _http;
    private readonly Uri _base;

    public AgentAccountProductLeaseRemote(
        WindowsDpapiEd25519MachineKeyStore keys,
        IReadOnlyDictionary<string, AccountProductLeaseTrustedKey> pinnedDsKeys,
        string? baseUrl = null,
        HttpMessageHandler? handler = null)
        : this(keys, AgentMachineKeyEnrollmentRemote.Binding,
            binding => keys.ReadReceipt(binding, keys), pinnedDsKeys, baseUrl, handler) { }

    public AgentAccountProductLeaseRemote(
        WindowsTpmEcdsaP256MachineKeyStore keys,
        WindowsDpapiEd25519MachineKeyStore receipts,
        IReadOnlyDictionary<string, AccountProductLeaseTrustedKey> pinnedDsKeys,
        string? baseUrl = null,
        HttpMessageHandler? handler = null)
        : this(keys, AgentMachineKeyEnrollmentRemote.Binding,
            binding => receipts.ReadReceipt(binding, keys), pinnedDsKeys, baseUrl, handler) { }

    [SupportedOSPlatform("windows")]
    public static AgentAccountProductLeaseRemote CreatePreferred(
        ActiveAccountSessionState trustedSession,
        IReadOnlyDictionary<string, AccountProductLeaseTrustedKey> pinnedDsKeys,
        string? dataDirectory = null,
        bool allowSoftwareFallback = false,
        string? baseUrl = null,
        HttpMessageHandler? handler = null)
    {
        var binding = AgentMachineKeyEnrollmentRemote.Binding(trustedSession);
        // The enrollment path owns new-key creation. A lease consumer must
        // never mint a fresh machine identity when prior custody was lost.
        var receipts = new WindowsDpapiEd25519MachineKeyStore(dataDirectory);
        var hardware = new WindowsTpmEcdsaP256MachineKeyStore(dataDirectory);
        if (!hardware.HasStoredIdentity && !receipts.HasStoredIdentity)
            throw new InvalidDataException(
                "No existing protected Agent machine key; enroll before leasing.");
        var signer = WindowsPreferredAgentMachineKey.Open(
            binding, dataDirectory, allowSoftwareFallback);
        return new AgentAccountProductLeaseRemote(
            signer, AgentMachineKeyEnrollmentRemote.Binding,
            b => receipts.ReadReceipt(b, signer),
            pinnedDsKeys, baseUrl, handler);
    }

    // Named certification friend only; production always uses Windows-protected
    // machine binding, key custody and DPAPI-protected registration receipts.
    internal AgentAccountProductLeaseRemote(
        IAgentMachineKeySigner signer,
        Func<ActiveAccountSessionState, AgentEd25519SessionBinding> binding,
        Func<AgentEd25519SessionBinding, AgentMachineKeyRegistrationReceipt?> readReceipt,
        IReadOnlyDictionary<string, AccountProductLeaseTrustedKey> pinnedDsKeys,
        string? baseUrl = null,
        HttpMessageHandler? handler = null)
    {
        _signer = signer ?? throw new ArgumentNullException(nameof(signer));
        _binding = binding ?? throw new ArgumentNullException(nameof(binding));
        _readReceipt = readReceipt ?? throw new ArgumentNullException(nameof(readReceipt));
        if (pinnedDsKeys is null || pinnedDsKeys.Count is < 1 or > 16 ||
            pinnedDsKeys.Any(pair => !Scope.IsMatch(pair.Key) ||
                string.IsNullOrWhiteSpace(pair.Value?.PublicKeyPem) ||
                pair.Value.State is not ("ACTIVE" or "VERIFY_ONLY")))
            throw new InvalidOperationException("An explicit, pinned DS lease trust set is required.");
        // Freeze the caller-provided dictionary; an HTTP response cannot extend it.
        _trustedKeys = new Dictionary<string, AccountProductLeaseTrustedKey>(
            pinnedDsKeys, StringComparer.Ordinal);
        var baseText = (baseUrl ??
            Environment.GetEnvironmentVariable("BKE_PLATFORM_BASE_URL") ??
            AgentRuntimeEnvironmentLoader.ProductionPlatformBaseUrl).TrimEnd('/');
        if (!Uri.TryCreate(baseText, UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttps ||
            !string.IsNullOrEmpty(uri.UserInfo) ||
            !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment) ||
            uri.AbsolutePath != "/")
            throw new InvalidOperationException("DS lease transport requires a clean HTTPS origin.");
        _base = uri;
        if (handler is HttpClientHandler supplied && supplied.AllowAutoRedirect)
            throw new InvalidOperationException("DS lease transport forbids credential redirects.");
        _http = new HttpClient(handler ?? new HttpClientHandler {
            AllowAutoRedirect = false
        }, disposeHandler: true) { Timeout = TimeSpan.FromSeconds(20) };
    }

    /// <summary>
    /// Obtain and cryptographically inspect an account-product JWS ONLY.
    /// The result is not an installed trust anchor, entitlement cache, or
    /// permission to launch; a separate installed authorization gate owns that.
    /// </summary>
    public async Task<AccountProductLeaseCheck> RequestVerifiedAsync(
        ActiveAccountSessionState authenticatedSession,
        string productId,
        string action,
        string platform,
        string architecture,
        CancellationToken cancellationToken)
    {
        var binding = _binding(authenticatedSession);
        var now = DateTimeOffset.UtcNow;
        if (authenticatedSession.AccessTokenExpiresAt <= now.AddSeconds(30) ||
            string.IsNullOrEmpty(authenticatedSession.AccessToken) ||
            authenticatedSession.AccessToken.Length is < 32 or > 8192)
            throw new InvalidDataException("An active trusted Agent session is required.");
        if (productId is null || !Scope.IsMatch(productId) ||
            action is not ("OPEN" or "USE") ||
            platform != "windows" ||
            architecture is not ("x64" or "arm64" or "x86"))
            throw new InvalidDataException("Untrusted product lease scope.");

        // A persisted, live receipt and the original protected private key
        // must BOTH match; a bearer token or caller-provided registration does
        // not suffice to request a signed product lease.
        var receipt = _readReceipt(binding) ??
            throw new InvalidDataException("No protected DS machine-key registration.");
        var identity = _signer.GetOrCreateIdentity(binding, createIfMissing: false);
        if (receipt.RegistrationId is null ||
            !Guid.TryParseExact(receipt.RegistrationId, "D", out var parsed) ||
            parsed.ToString("D") != receipt.RegistrationId ||
            receipt.KeyThumbprint != identity.KeyThumbprint ||
            receipt.Algorithm != identity.Algorithm ||
            receipt.ValidUntil is not { } until || until <= now)
            throw new InvalidDataException("DS registration receipt does not match protected machine key.");

        using var challenge = await PostAsync(
            "/api/agent-sessions/leases/challenge",
            new { registration_id = receipt.RegistrationId,
                product_id = productId, action },
            authenticatedSession.AccessToken, cancellationToken);
        var c = challenge.RootElement;
        RequireFields(c, "status", "registration_id", "challenge_id",
            "message_base64url", "expires_at");
        if (Required(c, "status") != "challenge" ||
            RequiredUuid(c, "registration_id") != receipt.RegistrationId)
            throw new InvalidDataException("DS returned an unrelated lease challenge.");
        string challengeId = RequiredUuid(c, "challenge_id");
        string message = Required(c, "message_base64url", 4096);
        DateTimeOffset deadline = RequiredTime(c, "expires_at");
        // Implementations for EdDSA/TPM ES256 inspect all 11 exact challenge
        // fields, LEASE purpose and product/action BEFORE signing a byte.
        string signature = _signer.SignChallenge(binding,
            receipt.RegistrationId, challengeId, message, deadline,
            productId, action);

        using var issued = await PostAsync(
            "/api/agent-sessions/leases/issue",
            new {
                challenge_id = challengeId,
                message_base64url = message,
                signature_base64url = signature,
                product_id = productId,
                action, platform, architecture
            }, authenticatedSession.AccessToken, cancellationToken);
        var body = issued.RootElement;
        RequireFields(body, "status", "lease_jws", "kid",
            "expires_at", "refresh_after");
        if (Required(body, "status") != "issued")
            throw new InvalidDataException("DS refused to issue the product lease.");
        var jws = Required(body, "lease_jws", 16384);
        var check = AccountProductLeaseJwsVerifier.Verify(jws, _trustedKeys,
            new AccountProductLeaseExpected(
                "BKE Digital Solutions", "bke-product",
                binding.AccountId, binding.UserId, productId,
                binding.SessionId, identity.KeyThumbprint, action,
                DateTimeOffset.UtcNow));
        if (!check.Ok || check.Claims is null || check.Kid is null ||
            !_trustedKeys.TryGetValue(check.Kid, out var issuerKey) ||
            issuerKey.State != "ACTIVE" ||
            Required(body, "kid") != check.Kid ||
            RequiredTime(body, "expires_at") != check.Claims.ExpiresAt ||
            RequiredTime(body, "refresh_after") != check.Claims.RefreshAfter ||
            check.Claims.KeyProtection != "software" ||
            check.Claims.ExpiresAt - check.Claims.IssuedAt > TimeSpan.FromMinutes(5))
            throw new InvalidDataException("DS signed lease failed pinned Agent verification.");
        return check;
    }

    private async Task<JsonDocument> PostAsync(
        string path, object body, string token, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(_base, path));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.TryAddWithoutValidation("x-bke-account-session-version", Protocol);
        request.Headers.UserAgent.ParseAdd("bke-licensing-agent");
        request.Content = new StringContent(JsonSerializer.Serialize(body),
            Encoding.UTF8, "application/json");
        using var response = await _http.SendAsync(request,
            HttpCompletionOption.ResponseHeadersRead, ct);
        if ((int)response.StatusCode is >= 300 and < 400)
            throw new InvalidDataException("DS lease authority attempted credential redirect.");
        if (response.StatusCode != HttpStatusCode.Created)
            throw new HttpRequestException("DS lease authority denied request.",
                null, response.StatusCode);
        if (!response.Headers.TryGetValues(
            "x-bke-account-session-version", out var protocols) ||
            protocols.Count() != 1 || protocols.Single() != Protocol ||
            response.Headers.CacheControl?.NoStore != true ||
            response.Content.Headers.ContentType?.MediaType != "application/json")
            throw new InvalidDataException("DS lease response headers violate protocol.");
        await response.Content.LoadIntoBufferAsync(16384, ct);
        var buffer = await response.Content.ReadAsByteArrayAsync(ct);
        try
        {
            using var json = JsonDocument.Parse(buffer, new JsonDocumentOptions {
                AllowTrailingCommas = false, CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 12
            });
            Unique(json.RootElement);
            return JsonDocument.Parse(json.RootElement.GetRawText());
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException("DS lease response is not valid JSON.", ex);
        }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(buffer); }
    }

    private static void Unique(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var member in value.EnumerateObject())
            {
                if (!names.Add(member.Name))
                    throw new InvalidDataException("DS lease response has ambiguous fields.");
                Unique(member.Value);
            }
        }
        else if (value.ValueKind == JsonValueKind.Array)
            foreach (var child in value.EnumerateArray()) Unique(child);
    }

    private static void RequireFields(JsonElement value, params string[] fields)
    {
        if (value.ValueKind != JsonValueKind.Object ||
            value.EnumerateObject().Count() != fields.Length ||
            fields.Any(field => !value.TryGetProperty(field, out _)))
            throw new InvalidDataException("DS lease response shape is unexpected.");
    }

    private static string Required(JsonElement value, string field, int max = 4096)
    {
        if (!value.TryGetProperty(field, out var property) ||
            property.ValueKind != JsonValueKind.String)
            throw new InvalidDataException("DS lease response is missing " + field);
        string? text = property.GetString();
        if (string.IsNullOrWhiteSpace(text) || text.Length > max ||
            text != text.Trim())
            throw new InvalidDataException("DS lease response field is invalid.");
        return text;
    }

    private static string RequiredUuid(JsonElement value, string field)
    {
        string text = Required(value, field, 64);
        if (!Guid.TryParseExact(text, "D", out var id) ||
            id.ToString("D") != text)
            throw new InvalidDataException("DS lease response identifier invalid.");
        return text;
    }

    private static DateTimeOffset RequiredTime(JsonElement value, string field)
    {
        var text = Required(value, field, 64);
        if (!text.EndsWith('Z') ||
            !DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal, out var time))
            throw new InvalidDataException("DS lease response timestamp invalid.");
        return time;
    }

    public void Dispose() => _http.Dispose();
}
