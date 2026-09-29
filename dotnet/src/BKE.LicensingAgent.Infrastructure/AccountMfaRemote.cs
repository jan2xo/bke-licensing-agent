using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using BKE.LicensingAgent.Application;

namespace BKE.LicensingAgent.Infrastructure;

public sealed class AccountMfaRemote : IAccountMfaRemote, IDisposable
{
    private readonly Uri _platformBaseUri;
    private readonly HttpClient _http;
    private readonly bool _ownsHttpClient;

    public AccountMfaRemote(HttpClient? httpClient = null, string? platformBaseUrl = null)
    {
        var rawBaseUrl = (
            platformBaseUrl ??
            Environment.GetEnvironmentVariable("BKE_PLATFORM_BASE_URL") ??
            AgentRuntimeEnvironmentLoader.ProductionPlatformBaseUrl
        ).TrimEnd('/');

        if (!Uri.TryCreate(rawBaseUrl, UriKind.Absolute, out var baseUri))
        {
            throw new InvalidOperationException("BKE_PLATFORM_BASE_URL is invalid.");
        }

        var allowLocal =
            Environment.GetEnvironmentVariable("BKE_AGENT_VNEXT_ALLOW_INSECURE_LOCAL") == "1" &&
            baseUri.IsLoopback &&
            baseUri.Scheme == Uri.UriSchemeHttp;

        if (baseUri.Scheme != Uri.UriSchemeHttps && !allowLocal)
        {
            throw new InvalidOperationException(
                "Account MFA authority requires HTTPS outside isolated loopback certification.");
        }

        if (!string.IsNullOrEmpty(baseUri.Query) || !string.IsNullOrEmpty(baseUri.Fragment))
        {
            throw new InvalidOperationException(
                "BKE_PLATFORM_BASE_URL must not contain query or fragment.");
        }

        _platformBaseUri = baseUri;
        if (httpClient is null)
        {
            _http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false })
            {
                Timeout = TimeSpan.FromSeconds(20),
            };
            _ownsHttpClient = true;
        }
        else
        {
            _http = httpClient;
            _ownsHttpClient = false;
        }
    }

    public async Task<RemoteAccountMfaResult> StatusAsync(
        string accessToken,
        CancellationToken cancellationToken)
    {
        using var response = await SendAsync(
            HttpMethod.Get,
            "/api/agent-sessions/account/mfa",
            null,
            accessToken,
            cancellationToken);

        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return new RemoteAccountMfaResult(
                "mfa_unavailable",
                ErrorCode: "MFA_UNAVAILABLE",
                Retryable: true);
        }

        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            throw new UnauthorizedAccessException("BKE account MFA status rejected the Agent session.");
        }

        EnsureProtocol(response);
        using var document = await ReadJsonAsync(response, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            return ErrorResult(response.StatusCode, document.RootElement);
        }

        var root = document.RootElement;
        return new RemoteAccountMfaResult(
            "ready",
            Enabled: RequiredBoolean(root, "enabled"),
            EnrollmentPending: RequiredBoolean(root, "enrollment_pending"),
            RecoveryCodesRemaining: RequiredNonNegativeInt(root, "recovery_codes_remaining", 1000));
    }

    public Task<RemoteAccountMfaResult> EnrollStartAsync(
        string accessToken,
        string currentPassword,
        CancellationToken cancellationToken) =>
        ChallengeRequestAsync(
            "/api/agent-sessions/account/mfa/enroll/start",
            accessToken,
            currentPassword,
            "enrollment_challenge_issued",
            cancellationToken);

    public Task<RemoteAccountMfaResult> ChallengeAsync(
        string accessToken,
        string currentPassword,
        CancellationToken cancellationToken) =>
        ChallengeRequestAsync(
            "/api/agent-sessions/account/mfa/challenge",
            accessToken,
            currentPassword,
            "mfa_challenge_issued",
            cancellationToken);

    public Task<RemoteAccountMfaResult> EnrollCompleteAsync(
        string accessToken,
        string currentPassword,
        string challengeToken,
        string code,
        CancellationToken cancellationToken) =>
        MutationRequestAsync(
            "/api/agent-sessions/account/mfa/enroll/complete",
            accessToken,
            new
            {
                current_password = currentPassword,
                challenge_token = challengeToken,
                code,
            },
            "mfa_enabled",
            requireRecoveryCodes: true,
            requireEnrollmentRequired: false,
            cancellationToken);

    public Task<RemoteAccountMfaResult> DisableAsync(
        string accessToken,
        string currentPassword,
        string challengeToken,
        string code,
        CancellationToken cancellationToken) =>
        MutationRequestAsync(
            "/api/agent-sessions/account/mfa/disable",
            accessToken,
            new
            {
                current_password = currentPassword,
                challenge_token = challengeToken,
                code,
            },
            "mfa_disabled",
            requireRecoveryCodes: false,
            requireEnrollmentRequired: true,
            cancellationToken);

    public Task<RemoteAccountMfaResult> RegenerateRecoveryAsync(
        string accessToken,
        string currentPassword,
        string challengeToken,
        string code,
        CancellationToken cancellationToken) =>
        MutationRequestAsync(
            "/api/agent-sessions/account/mfa/recovery/regenerate",
            accessToken,
            new
            {
                current_password = currentPassword,
                challenge_token = challengeToken,
                code,
            },
            "recovery_codes_regenerated",
            requireRecoveryCodes: true,
            requireEnrollmentRequired: false,
            cancellationToken);

    private async Task<RemoteAccountMfaResult> ChallengeRequestAsync(
        string path,
        string accessToken,
        string currentPassword,
        string expectedStatus,
        CancellationToken cancellationToken)
    {
        if (!ValidSecret(accessToken, 8192) || !ValidSecret(currentPassword, 128))
        {
            return new RemoteAccountMfaResult("invalid_input", ErrorCode: "INVALID_INPUT");
        }

        using var response = await SendAsync(
            HttpMethod.Post,
            path,
            JsonSerializer.Serialize(new { current_password = currentPassword }),
            accessToken,
            cancellationToken);

        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return new RemoteAccountMfaResult(
                "mfa_unavailable",
                ErrorCode: "MFA_UNAVAILABLE",
                Retryable: true);
        }

        EnsureProtocol(response);
        using var document = await ReadJsonAsync(response, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            return ErrorResult(response.StatusCode, document.RootElement);
        }

        var root = document.RootElement;
        if (RequiredString(root, "status") != expectedStatus)
        {
            throw new InvalidDataException("Account MFA challenge response drifted.");
        }

        return new RemoteAccountMfaResult(
            "challenge_issued",
            ChallengeToken: RequiredString(root, "challenge_token"),
            ExpiresAt: RequiredString(root, "expires_at"),
            EmailSent: RequiredBoolean(root, "email_sent"),
            MfaReference: RequiredString(root, "mfa_reference"));
    }

    private async Task<RemoteAccountMfaResult> MutationRequestAsync(
        string path,
        string accessToken,
        object payload,
        string expectedStatus,
        bool requireRecoveryCodes,
        bool requireEnrollmentRequired,
        CancellationToken cancellationToken)
    {
        if (!ValidSecret(accessToken, 8192))
        {
            return new RemoteAccountMfaResult("invalid_input", ErrorCode: "INVALID_INPUT");
        }

        using var response = await SendAsync(
            HttpMethod.Post,
            path,
            JsonSerializer.Serialize(payload),
            accessToken,
            cancellationToken);

        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return new RemoteAccountMfaResult(
                "mfa_unavailable",
                ErrorCode: "MFA_UNAVAILABLE",
                Retryable: true);
        }

        EnsureProtocol(response);
        using var document = await ReadJsonAsync(response, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            return ErrorResult(response.StatusCode, document.RootElement);
        }

        var root = document.RootElement;
        if (RequiredString(root, "status") != expectedStatus ||
            !RequiredBoolean(root, "reauthentication_required"))
        {
            throw new InvalidDataException("Account MFA mutation response drifted.");
        }

        return new RemoteAccountMfaResult(
            "completed",
            ReauthenticationRequired: true,
            EnrollmentRequired: requireEnrollmentRequired
                ? RequiredBoolean(root, "enrollment_required")
                : null,
            RecoveryCodes: requireRecoveryCodes
                ? RequiredStringArray(root, "recovery_codes")
                : null);
    }

    private async Task<HttpResponseMessage> SendAsync(
        HttpMethod method,
        string path,
        string? json,
        string accessToken,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, new Uri(_platformBaseUri, path));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.UserAgent.ParseAdd("bke-licensing-agent");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        request.Headers.TryAddWithoutValidation(
            "x-bke-account-session-version",
            AccountSessionRemote.ProtocolVersion);
        request.Headers.TryAddWithoutValidation("x-request-id", Guid.NewGuid().ToString("N"));

        if (json is not null)
        {
            request.Content = new StringContent(json, Encoding.UTF8, "application/json");
        }

        // MFA challenge/mutation calls are deliberately single-attempt.
        // Replaying could create duplicate challenges or repeat a security mutation.
        var response = await _http.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);

        if ((int)response.StatusCode is >= 300 and <= 399)
        {
            response.Dispose();
            throw new HttpRequestException("BKE account MFA authority redirected.");
        }

        return response;
    }

    private static RemoteAccountMfaResult ErrorResult(
        HttpStatusCode statusCode,
        JsonElement root)
    {
        var error = OptionalString(root, "error") ?? "MFA_UNAVAILABLE";
        if (statusCode == HttpStatusCode.Unauthorized && error == "INVALID_TOKEN")
        {
            throw new UnauthorizedAccessException("BKE account session was rejected by MFA authority.");
        }

        var normalized = error switch
        {
            "INVALID_CREDENTIALS" => "invalid_credentials",
            "INVALID_MFA_CHALLENGE" or "INVALID_CHALLENGE" => "invalid_mfa_challenge",
            "INVALID_MFA_CODE" or "INVALID_CODE" => "invalid_mfa_code",
            "INVALID_INPUT" => "invalid_input",
            "RATE_LIMITED" => "rate_limited",
            "PASSWORD_PROVIDER_UNAVAILABLE" => "password_provider_unavailable",
            "MFA_UNAVAILABLE" => "mfa_unavailable",
            _ => error.ToLowerInvariant(),
        };

        return new RemoteAccountMfaResult(
            normalized,
            ErrorCode: error,
            Retryable: (int)statusCode == 429 || statusCode == HttpStatusCode.ServiceUnavailable);
    }

    private static void EnsureProtocol(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues("x-bke-account-session-version", out var values))
        {
            throw new InvalidDataException("Account MFA response is missing its protocol version.");
        }

        var versions = values.ToArray();
        if (versions.Length != 1 || versions[0] != AccountSessionRemote.ProtocolVersion)
        {
            throw new InvalidDataException("Account MFA protocol version drifted.");
        }
    }

    private static async Task<JsonDocument> ReadJsonAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        return await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
    }

    private static string RequiredString(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var value) ||
            value.ValueKind != JsonValueKind.String ||
            string.IsNullOrWhiteSpace(value.GetString()))
        {
            throw new InvalidDataException($"Missing or invalid {name}.");
        }
        return value.GetString()!;
    }

    private static bool RequiredBoolean(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var value) ||
            value.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
        {
            throw new InvalidDataException($"Missing or invalid {name}.");
        }
        return value.GetBoolean();
    }

    private static int RequiredNonNegativeInt(JsonElement root, string name, int maximum)
    {
        if (!root.TryGetProperty(name, out var value) ||
            value.ValueKind != JsonValueKind.Number ||
            !value.TryGetInt32(out var result) ||
            result < 0 ||
            result > maximum)
        {
            throw new InvalidDataException($"Missing or invalid {name}.");
        }
        return result;
    }

    private static IReadOnlyList<string> RequiredStringArray(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var value) ||
            value.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException($"Missing or invalid {name}.");
        }

        var result = value.EnumerateArray()
            .Select(item =>
                item.ValueKind == JsonValueKind.String &&
                !string.IsNullOrWhiteSpace(item.GetString())
                    ? item.GetString()!
                    : throw new InvalidDataException($"Invalid {name} item."))
            .ToArray();

        if (result.Length is < 1 or > 100)
        {
            throw new InvalidDataException($"Invalid {name} length.");
        }

        return result;
    }

    private static string? OptionalString(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var value) ||
            value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }
        return value.ValueKind == JsonValueKind.String ? value.GetString() : null;
    }

    private static bool ValidSecret(string value, int max) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= max;

    public void Dispose()
    {
        if (_ownsHttpClient)
        {
            _http.Dispose();
        }
    }
}
