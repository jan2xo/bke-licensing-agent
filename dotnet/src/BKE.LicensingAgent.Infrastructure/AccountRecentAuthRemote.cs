using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using BKE.LicensingAgent.Application;

namespace BKE.LicensingAgent.Infrastructure;

public sealed class AccountRecentAuthRemote :
    IAccountRecentAuthRemote,
    IDisposable
{
    private readonly Uri _platformBaseUri;
    private readonly HttpClient _http;
    private readonly bool _ownsHttpClient;

    public AccountRecentAuthRemote(
        HttpClient? httpClient = null,
        string? platformBaseUrl = null)
    {
        var rawBaseUrl = (
            platformBaseUrl ??
            Environment.GetEnvironmentVariable("BKE_PLATFORM_BASE_URL") ??
            AgentRuntimeEnvironmentLoader.ProductionPlatformBaseUrl
        ).TrimEnd('/');

        if (!Uri.TryCreate(
                rawBaseUrl,
                UriKind.Absolute,
                out var baseUri))
        {
            throw new InvalidOperationException(
                "BKE_PLATFORM_BASE_URL is invalid.");
        }

        var allowLocal =
            Environment.GetEnvironmentVariable(
                "BKE_AGENT_VNEXT_ALLOW_INSECURE_LOCAL") == "1" &&
            baseUri.IsLoopback &&
            baseUri.Scheme == Uri.UriSchemeHttp;

        if (baseUri.Scheme != Uri.UriSchemeHttps && !allowLocal)
        {
            throw new InvalidOperationException(
                "Recent-auth authority requires HTTPS outside isolated loopback certification.");
        }

        if (!string.IsNullOrEmpty(baseUri.Query) ||
            !string.IsNullOrEmpty(baseUri.Fragment))
        {
            throw new InvalidOperationException(
                "BKE_PLATFORM_BASE_URL must not contain query or fragment.");
        }

        _platformBaseUri = baseUri;
        if (httpClient is null)
        {
            _http = new HttpClient(
                new HttpClientHandler { AllowAutoRedirect = false })
            {
                Timeout = TimeSpan.FromSeconds(30),
            };
            _ownsHttpClient = true;
        }
        else
        {
            _http = httpClient;
            _ownsHttpClient = false;
        }
    }

    public async Task<RemoteAccountRecentAuthResult> StartAsync(
        string accessToken,
        string currentPassword,
        CancellationToken cancellationToken)
    {
        ValidateAccessToken(accessToken);
        if (!ValidSecret(currentPassword, 128))
        {
            throw new InvalidDataException(
                "Invalid current password.");
        }

        using var response = await SendAsync(
            "/api/agent-sessions/account/recent-auth/start",
            accessToken,
            JsonSerializer.Serialize(new
            {
                current_password = currentPassword,
            }),
            cancellationToken);

        using var document = await ReadJsonAsync(
            response,
            cancellationToken);
        var root = document.RootElement;
        EnsureProtocol(response);

        if (response.StatusCode == HttpStatusCode.OK)
        {
            RequireObjectKeys(root, [
                "status",
                "recent_authenticated_until",
            ]);
            if (RequiredString(root, "status", 64) != "verified")
            {
                throw new InvalidDataException(
                    "Recent-auth verified status drifted.");
            }

            return new RemoteAccountRecentAuthResult(
                "verified",
                RecentAuthenticatedUntil:
                    RequiredTimestamp(
                        root,
                        "recent_authenticated_until"));
        }

        if (response.StatusCode == HttpStatusCode.Created)
        {
            RequireObjectKeys(root, [
                "status",
                "challenge_token",
                "expires_at",
                "email_sent",
                "mfa_reference",
            ]);
            if (RequiredString(root, "status", 64) !=
                "mfa_challenge_issued")
            {
                throw new InvalidDataException(
                    "Recent-auth challenge status drifted.");
            }

            return new RemoteAccountRecentAuthResult(
                "mfa_challenge_issued",
                ChallengeToken:
                    RequiredString(root, "challenge_token", 512),
                ExpiresAt:
                    RequiredTimestamp(root, "expires_at"),
                EmailSent:
                    RequiredBoolean(root, "email_sent"),
                MfaReference:
                    RequiredString(root, "mfa_reference", 256));
        }

        return ErrorResult(response.StatusCode, root);
    }

    public async Task<RemoteAccountRecentAuthResult> CompleteAsync(
        string accessToken,
        string challengeToken,
        string code,
        CancellationToken cancellationToken)
    {
        ValidateAccessToken(accessToken);
        if (!ValidSecret(challengeToken, 512) ||
            !ValidSecret(code, 32))
        {
            throw new InvalidDataException(
                "Invalid MFA proof.");
        }

        using var response = await SendAsync(
            "/api/agent-sessions/account/recent-auth/complete",
            accessToken,
            JsonSerializer.Serialize(new
            {
                challenge_token = challengeToken,
                code,
            }),
            cancellationToken);

        using var document = await ReadJsonAsync(
            response,
            cancellationToken);
        var root = document.RootElement;
        EnsureProtocol(response);

        if (response.StatusCode == HttpStatusCode.OK)
        {
            RequireObjectKeys(root, [
                "status",
                "recent_authenticated_until",
            ]);
            if (RequiredString(root, "status", 64) != "verified")
            {
                throw new InvalidDataException(
                    "Recent-auth completion status drifted.");
            }

            return new RemoteAccountRecentAuthResult(
                "verified",
                RecentAuthenticatedUntil:
                    RequiredTimestamp(
                        root,
                        "recent_authenticated_until"));
        }

        return ErrorResult(response.StatusCode, root);
    }

    private async Task<HttpResponseMessage> SendAsync(
        string path,
        string accessToken,
        string json,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            new Uri(_platformBaseUri, path));
        request.Headers.Accept.Add(
            new MediaTypeWithQualityHeaderValue(
                "application/json"));
        request.Headers.UserAgent.ParseAdd(
            "bke-licensing-agent");
        request.Headers.Authorization =
            new AuthenticationHeaderValue(
                "Bearer",
                accessToken);
        request.Headers.TryAddWithoutValidation(
            "x-bke-account-session-version",
            AccountSessionRemote.ProtocolVersion);
        request.Headers.TryAddWithoutValidation(
            "x-request-id",
            Guid.NewGuid().ToString("N"));
        request.Content = new StringContent(
            json,
            Encoding.UTF8,
            "application/json");

        var response = await _http.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);

        if ((int)response.StatusCode is >= 300 and <= 399)
        {
            response.Dispose();
            throw new HttpRequestException(
                "BKE recent-auth endpoint redirected.");
        }

        return response;
    }

    private static RemoteAccountRecentAuthResult ErrorResult(
        HttpStatusCode statusCode,
        JsonElement root)
    {
        RequireObjectKeys(root, ["error"]);
        var error = RequiredString(root, "error", 128);

        if (statusCode == HttpStatusCode.Unauthorized &&
            error == "INVALID_TOKEN")
        {
            throw new UnauthorizedAccessException(
                "BKE account session was rejected by recent-auth authority.");
        }

        var normalized = error switch
        {
            "INVALID_CREDENTIALS" => "invalid_credentials",
            "INVALID_MFA_CHALLENGE" or "INVALID_CHALLENGE" =>
                "invalid_mfa_challenge",
            "INVALID_MFA_CODE" or "INVALID_CODE" =>
                "invalid_mfa_code",
            "INVALID_INPUT" => "invalid_input",
            "RATE_LIMITED" => "rate_limited",
            "PASSWORD_PROVIDER_UNAVAILABLE" =>
                "password_provider_unavailable",
            "MFA_UNAVAILABLE" => "mfa_unavailable",
            _ => throw new InvalidDataException(
                "Recent-auth error code drifted."),
        };

        return new RemoteAccountRecentAuthResult(
            normalized,
            ErrorCode: error,
            Retryable:
                statusCode == (HttpStatusCode)429 ||
                statusCode == HttpStatusCode.ServiceUnavailable);
    }

    private static async Task<JsonDocument> ReadJsonAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        await using var stream =
            await response.Content.ReadAsStreamAsync(
                cancellationToken);
        return await JsonDocument.ParseAsync(
            stream,
            new JsonDocumentOptions { MaxDepth = 8 },
            cancellationToken);
    }

    private static void EnsureProtocol(
        HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues(
                "x-bke-account-session-version",
                out var values))
        {
            throw new InvalidDataException(
                "Recent-auth response is missing its protocol version.");
        }

        var versions = values.ToArray();
        if (versions.Length != 1 ||
            versions[0] != AccountSessionRemote.ProtocolVersion)
        {
            throw new InvalidDataException(
                "Recent-auth protocol version drifted.");
        }
    }

    private static void RequireObjectKeys(
        JsonElement item,
        IReadOnlyCollection<string> expected)
    {
        if (item.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException(
                "Recent-auth response shape is invalid.");
        }

        var keys = item.EnumerateObject()
            .Select(property => property.Name)
            .ToHashSet(StringComparer.Ordinal);
        if (!keys.SetEquals(expected))
        {
            throw new InvalidDataException(
                "Recent-auth response shape drifted.");
        }
    }

    private static string RequiredString(
        JsonElement root,
        string name,
        int maximumLength)
    {
        if (!root.TryGetProperty(name, out var value) ||
            value.ValueKind != JsonValueKind.String ||
            string.IsNullOrWhiteSpace(value.GetString()) ||
            value.GetString()!.Length > maximumLength)
        {
            throw new InvalidDataException(
                $"Missing or invalid {name}.");
        }

        return value.GetString()!;
    }

    private static bool RequiredBoolean(
        JsonElement root,
        string name)
    {
        if (!root.TryGetProperty(name, out var value) ||
            value.ValueKind is not (
                JsonValueKind.True or JsonValueKind.False))
        {
            throw new InvalidDataException(
                $"Missing or invalid {name}.");
        }

        return value.GetBoolean();
    }

    private static string RequiredTimestamp(
        JsonElement root,
        string name)
    {
        var value = RequiredString(root, name, 128);
        if (!DateTimeOffset.TryParse(value, out _))
        {
            throw new InvalidDataException(
                $"Invalid {name}.");
        }

        return value;
    }

    private static void ValidateAccessToken(string accessToken)
    {
        if (string.IsNullOrWhiteSpace(accessToken) ||
            accessToken.Length > 8192)
        {
            throw new InvalidDataException(
                "Invalid Agent access token.");
        }
    }

    private static bool ValidSecret(
        string value,
        int maximumLength) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length <= maximumLength;

    public void Dispose()
    {
        if (_ownsHttpClient)
        {
            _http.Dispose();
        }
    }
}
