using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using BKE.LicensingAgent.Application;

namespace BKE.LicensingAgent.Infrastructure;

/// <summary>
/// Internal, source-only Agent↔Digital Solutions key enrollment transport.
/// Reads the existing authenticated Agent session and invokes ONLY key
/// ENROLL / VERIFY / REVOKE. Does not issue product rights or expose loopback.
/// A registration receipt MUST be retained by trusted Agent lifecycle code;
/// this fraction does not yet install an automatic registration lifecycle.
/// </summary>
public sealed class AgentMachineKeyEnrollmentRemote : IDisposable
{
    public const string ProtocolVersion = "bke.account-session.v1";
    private readonly IAgentMachineKeySigner _keys;
    // Only internal friend-assembly certification can substitute a Linux disposable binding.
    // Production constructors always derive the Windows device from protected Agent state.
    private readonly Func<ActiveAccountSessionState, AgentEd25519SessionBinding> _trustedBinding;
    private readonly HttpClient _http;
    private readonly Uri _base;

    // The hardware/software signer choice is made inside the trusted Agent,
    // never from a Launcher/IPC supplied algorithm or claimed TPM label.
    public AgentMachineKeyEnrollmentRemote(
        WindowsDpapiEd25519MachineKeyStore keys,
        string? baseUrl = null,
        HttpMessageHandler? handler = null)
        : this((IAgentMachineKeySigner)keys, baseUrl, handler) { }

    public AgentMachineKeyEnrollmentRemote(
        WindowsTpmEcdsaP256MachineKeyStore keys,
        string? baseUrl = null,
        HttpMessageHandler? handler = null)
        : this((IAgentMachineKeySigner)keys, baseUrl, handler) { }

    [SupportedOSPlatform("windows")]
    public static AgentMachineKeyEnrollmentRemote CreatePreferred(
        ActiveAccountSessionState trustedSession,
        string? dataDirectory = null,
        bool allowSoftwareFallback = false,
        string? baseUrl = null,
        HttpMessageHandler? handler = null)
    {
        var binding = Binding(trustedSession);
        var signer = WindowsPreferredAgentMachineKey.Open(
            binding, dataDirectory, allowSoftwareFallback);
        return new AgentMachineKeyEnrollmentRemote(signer, baseUrl, handler);
    }

    internal IAgentMachineKeySigner TrustedSigner => _keys;

    // Test-only seam: never public, never reachable through production DI or IPC.
    // The signer still validates the complete server-signed enrollment challenge.
    internal AgentMachineKeyEnrollmentRemote(
        IAgentMachineKeySigner keys,
        Func<ActiveAccountSessionState, AgentEd25519SessionBinding> trustedBinding,
        string? baseUrl = null,
        HttpMessageHandler? handler = null)
        : this(keys, baseUrl, handler)
    {
        _trustedBinding = trustedBinding ?? throw new ArgumentNullException(nameof(trustedBinding));
    }

    internal AgentMachineKeyEnrollmentRemote(
        IAgentMachineKeySigner keys,
        string? baseUrl = null,
        HttpMessageHandler? handler = null)
    {
        _keys = keys ?? throw new ArgumentNullException(nameof(keys));
        _trustedBinding = Binding;
        var url = (baseUrl ??
            Environment.GetEnvironmentVariable("BKE_PLATFORM_BASE_URL") ??
            AgentRuntimeEnvironmentLoader.ProductionPlatformBaseUrl).TrimEnd('/');
        _base = ValidatePlatformUrl(url);
        if (handler is HttpClientHandler supplied && supplied.AllowAutoRedirect)
            throw new InvalidOperationException("Agent key transport forbids HTTP redirect following.");
        _http = new HttpClient(handler ?? new HttpClientHandler
        {
            AllowAutoRedirect = false,
        }, disposeHandler: true)
        {
            Timeout = TimeSpan.FromSeconds(20),
        };
    }

    public async Task<AgentMachineKeyRegistrationReceipt> EnrollAsync(
        ActiveAccountSessionState authenticatedSession,
        CancellationToken cancellationToken)
    {
        var binding = _trustedBinding(authenticatedSession);
        // A stolen Agent access bearer alone cannot initiate machine-key enrollment.
        // The high-entropy original device/native-handoff code stays in protected Agent state.
        string? deviceCode = authenticatedSession.EnrollmentDeviceCode;
        if (deviceCode is null || deviceCode.Length != 43 ||
            deviceCode.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not '-' and not '_'))
            throw new InvalidDataException("Original Agent device authorization proof is required.");
        var identity = _keys.GetOrCreateIdentity(binding);
        if (identity.Algorithm is not ("EdDSA" or "ES256") ||
            identity.KeyProtection is not ("software" or "tpm-unverified"))
            throw new InvalidDataException("Unsupported Agent key identity or protection claim.");

        using var enrollment = await SendAsync(
            "/api/agent-sessions/keys/enroll",
            new { public_key_pem = identity.PublicKeyPem, device_code = deviceCode },
            authenticatedSession.AccessToken,
            HttpStatusCode.Created,
            cancellationToken);
        var challenge = enrollment.RootElement;
        if (Required(challenge, "status") != "challenge")
            throw new InvalidDataException("Invalid Agent enrollment response state.");
        var registrationId = RequiredUuid(challenge, "registration_id");
        var challengeId = RequiredUuid(challenge, "challenge_id");
        var encodedMessage = Required(challenge, "message_base64url");
        var expiresAt = RequiredExpiry(challenge, "expires_at");

        // SignChallenge verifies all 11 exact server-provided fields, including
        // authenticated account/session/device, purpose, nonce, and expiration.
        string signature = _keys.SignChallenge(binding, registrationId, challengeId,
            encodedMessage, expiresAt);

        using var verification = await SendAsync(
            "/api/agent-sessions/keys/verify",
            new
            {
                challenge_id = challengeId,
                message_base64url = encodedMessage,
                signature_base64url = signature,
            },
            authenticatedSession.AccessToken,
            HttpStatusCode.OK,
            cancellationToken);
        var result = verification.RootElement;
        if (Required(result, "status") != "enrolled" ||
            RequiredUuid(result, "registration_id") != registrationId)
            throw new InvalidDataException("Agent key enrollment was not server-confirmed.");

        return new AgentMachineKeyRegistrationReceipt(registrationId, identity.KeyThumbprint,
            Algorithm: identity.Algorithm);
    }

    /// <summary>
    /// Server revocation must succeed BEFORE a caller considers key rotation
    /// or local reset. Caller must possess an authenticated session and its
    /// previously recorded registration receipt. No silent offline revocation.
    /// </summary>
    public async Task RevokeAsync(
        ActiveAccountSessionState authenticatedSession,
        AgentMachineKeyRegistrationReceipt registration,
        CancellationToken cancellationToken)
    {
        var binding = _trustedBinding(authenticatedSession);
        ArgumentNullException.ThrowIfNull(registration);
        if (!Guid.TryParseExact(registration.RegistrationId, "D", out var guid) ||
            guid.ToString("D") != registration.RegistrationId)
            throw new InvalidDataException("Agent registration ID is invalid.");
        var identity = _keys.GetOrCreateIdentity(binding, createIfMissing: false);
        if (!string.Equals(identity.KeyThumbprint, registration.KeyThumbprint,
            StringComparison.Ordinal) || identity.Algorithm != registration.Algorithm)
            throw new InvalidDataException("Agent registration key does not match current private key.");

        using var reply = await SendAsync(
            "/api/agent-sessions/keys/revoke",
            new { registration_id = registration.RegistrationId },
            authenticatedSession.AccessToken,
            HttpStatusCode.OK,
            cancellationToken);
        string status = Required(reply.RootElement, "status");
        if (status != "revoked" && status != "already_revoked")
            throw new InvalidDataException("Server did not acknowledge key revocation.");
    }

    internal static AgentEd25519SessionBinding Binding(ActiveAccountSessionState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.AccessTokenExpiresAt <= DateTimeOffset.UtcNow.AddSeconds(30) ||
            string.IsNullOrWhiteSpace(state.AccessToken) ||
            string.IsNullOrWhiteSpace(state.SessionId) ||
            state.Account is null ||
            string.IsNullOrWhiteSpace(state.Account.AccountId) ||
            string.IsNullOrWhiteSpace(state.Account.UserId))
            throw new InvalidDataException("Authenticated Agent account session is unavailable or expiring.");
        var device = MachineIdentityProvider.Calculate();
        if (MachineIdentityProvider.ProtocolPlatform(device.Platform) != "windows")
            throw new PlatformNotSupportedException("Windows protected key custody is required.");
        return new AgentEd25519SessionBinding(state.SessionId,
            state.Account.AccountId, state.Account.UserId, device.DeviceId);
    }

    /// <summary>
    /// Status is authenticated metadata only; it is NOT an Ed25519 proof or
    /// a license. The caller must compare the exact local protected key.
    /// </summary>
    public async Task<AgentMachineKeyRemoteState> StatusAsync(
        ActiveAccountSessionState authenticatedSession,
        string? registrationId,
        CancellationToken cancellationToken)
    {
        _ = _trustedBinding(authenticatedSession);
        if (registrationId is not null &&
            (!Guid.TryParseExact(registrationId, "D", out var parsed) ||
             parsed.ToString("D") != registrationId))
            throw new InvalidDataException("Agent registration lookup ID is invalid.");

        using var reply = await SendAsync(
            "/api/agent-sessions/keys/status",
            registrationId is null ? new { } : (object)new { registration_id = registrationId },
            authenticatedSession.AccessToken,
            HttpStatusCode.OK,
            cancellationToken);

        var root = reply.RootElement;
        string status = Required(root, "status");
        if (status == "none")
        {
            if (root.EnumerateObject().Count() != 1)
                throw new InvalidDataException("Agent key server returned ambiguous empty registration.");
            return new AgentMachineKeyRemoteState("none");
        }
        if (status != "registration")
            throw new InvalidDataException("Agent key server returned invalid registration status.");
        string registration = RequiredUuid(root, "registration_id");
        string state = Required(root, "registration_state");
        string thumbprint = Required(root, "key_thumbprint");
        string algorithm = Required(root, "key_algorithm");
        if (algorithm is not ("EdDSA" or "ES256") ||
            state is not ("pending" or "active" or "revoked" or "expired") ||
            Required(root, "key_protection") != "software" ||
            thumbprint.Length != 43 ||
            thumbprint.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not '-' and not '_') ||
            (registrationId is not null && registration != registrationId))
            throw new InvalidDataException("Agent server registration state is not trustworthy.");
        DateTimeOffset expiry = RequiredExpiry(root, "valid_until");
        return new AgentMachineKeyRemoteState(state, registration, thumbprint, expiry, algorithm);
    }

    public async Task RevokeRegistrationAsync(
        ActiveAccountSessionState authenticatedSession,
        string registrationId,
        string keyThumbprint,
        CancellationToken cancellationToken)
    {
        var binding = _trustedBinding(authenticatedSession);
        if (!Guid.TryParseExact(registrationId, "D", out var parsed) ||
            parsed.ToString("D") != registrationId)
            throw new InvalidDataException("Agent registration revocation ID is invalid.");
        var local = _keys.GetOrCreateIdentity(binding, createIfMissing: false);
        if (local.KeyThumbprint != keyThumbprint)
            throw new InvalidDataException("Cannot revoke a foreign machine-key registration.");
        using var reply = await SendAsync(
            "/api/agent-sessions/keys/revoke",
            new { registration_id = registrationId },
            authenticatedSession.AccessToken,
            HttpStatusCode.OK, cancellationToken);
        string status = Required(reply.RootElement, "status");
        if (status is not ("revoked" or "already_revoked"))
            throw new InvalidDataException("DS machine-key revocation was not confirmed.");
    }

    private async Task<JsonDocument> SendAsync(
        string relativePath,
        object body,
        string token,
        HttpStatusCode requiredStatus,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            new Uri(_base, relativePath));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.TryAddWithoutValidation(
            "x-bke-account-session-version", ProtocolVersion);
        request.Headers.UserAgent.ParseAdd("bke-licensing-agent");
        request.Content = new StringContent(
            JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
        using var response = await _http.SendAsync(request,
            HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        if ((int)response.StatusCode is >= 300 and <= 399)
            throw new InvalidDataException("Agent key authority may not redirect credentials.");
        if (response.StatusCode != requiredStatus)
            throw new HttpRequestException(
                "Agent key authority refused the request.",
                null, response.StatusCode);
        if (!response.Headers.TryGetValues(
            "x-bke-account-session-version", out var versions) ||
            versions.Count() != 1 ||
            versions.Single() != ProtocolVersion)
            throw new InvalidDataException("Agent key authority protocol version mismatch.");
        if (!response.Headers.CacheControl?.NoStore ?? true)
            throw new InvalidDataException("Agent key authority response may not be cached.");
        if (response.Content.Headers.ContentType?.MediaType != "application/json")
            throw new InvalidDataException("Agent key authority response is not JSON.");
        await response.Content.LoadIntoBufferAsync(8192, cancellationToken);
        byte[] data = await response.Content.ReadAsByteArrayAsync(cancellationToken);
        try
        {
            using var json = JsonDocument.Parse(data);
            ValidateUniqueProperties(json.RootElement);
            // Detach from the temporary byte buffer before zeroing it.
            return JsonDocument.Parse(json.RootElement.GetRawText());
        }
        catch (JsonException error)
        {
            throw new InvalidDataException("Agent key authority response is malformed.", error);
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(data);
        }
    }

    private static void ValidateUniqueProperties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var member in element.EnumerateObject())
            {
                if (!names.Add(member.Name))
                    throw new InvalidDataException("Ambiguous Agent key authority response.");
                ValidateUniqueProperties(member.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
            foreach (var child in element.EnumerateArray())
                ValidateUniqueProperties(child);
    }

    private static string Required(JsonElement json, string property)
    {
        if (json.ValueKind != JsonValueKind.Object ||
            !json.TryGetProperty(property, out var value) ||
            value.ValueKind != JsonValueKind.String ||
            string.IsNullOrWhiteSpace(value.GetString()) ||
            value.GetString()!.Length > 4096)
            throw new InvalidDataException("Agent key authority response is missing " + property + ".");
        return value.GetString()!;
    }

    private static string RequiredUuid(JsonElement json, string property)
    {
        string value = Required(json, property);
        if (!Guid.TryParseExact(value, "D", out var parsed) ||
            parsed.ToString("D") != value)
            throw new InvalidDataException("Agent key authority identifier is invalid.");
        return value;
    }

    private static DateTimeOffset RequiredExpiry(JsonElement json, string property)
    {
        string encoded = Required(json, property);
        if (!encoded.EndsWith('Z') ||
            !DateTimeOffset.TryParse(encoded, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal, out var expiry))
            throw new InvalidDataException("Agent key authority challenge expiration is invalid.");
        return expiry;
    }

    private static Uri ValidatePlatformUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttps ||
            !string.IsNullOrWhiteSpace(uri.UserInfo) ||
            !string.IsNullOrEmpty(uri.Query) ||
            !string.IsNullOrEmpty(uri.Fragment) ||
            uri.AbsolutePath != "/")
            throw new InvalidOperationException(
                "Agent key exchange requires an HTTPS root with no credentials, query, or fragment.");
        return uri;
    }

    public void Dispose() => _http.Dispose();
}

public sealed record AgentMachineKeyRegistrationReceipt(
    string RegistrationId, string KeyThumbprint, DateTimeOffset? ValidUntil = null,
    string Algorithm = "EdDSA");

public sealed record AgentMachineKeyRemoteState(
    string Status, string? RegistrationId = null, string? KeyThumbprint = null,
    DateTimeOffset? ValidUntil = null, string? Algorithm = null);
