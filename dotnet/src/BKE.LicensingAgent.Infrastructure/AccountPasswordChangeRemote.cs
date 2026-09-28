using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using BKE.LicensingAgent.Application;

namespace BKE.LicensingAgent.Infrastructure;

public sealed class AccountPasswordChangeRemote : IAccountPasswordChangeRemote, IDisposable
{
    private readonly Uri _platformBaseUri;
    private readonly HttpClient _http;
    private readonly bool _ownsHttpClient;

    public AccountPasswordChangeRemote(
        HttpClient? httpClient = null,
        string? platformBaseUrl = null)
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
                "Password-change authority requires HTTPS outside isolated loopback certification.");
        }

        if (!string.IsNullOrEmpty(baseUri.Query) || !string.IsNullOrEmpty(baseUri.Fragment))
        {
            throw new InvalidOperationException(
                "BKE_PLATFORM_BASE_URL must not contain query or fragment.");
        }

        _platformBaseUri = baseUri;

        if (httpClient is null)
        {
            _http = new HttpClient(new HttpClientHandler
            {
                AllowAutoRedirect = false,
            })
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

    public async Task<RemoteAccountPasswordChangeResult> ChangeAsync(
        string accessToken,
        string currentPassword,
        string newPassword,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(accessToken) || accessToken.Length > 8192)
        {
            throw new InvalidDataException("Invalid Agent access token.");
        }

        if (currentPassword.Length is < 1 or > 128 ||
            newPassword.Length is < 1 or > 128)
        {
            return new RemoteAccountPasswordChangeResult(
                "invalid_input",
                "INVALID_INPUT");
        }

        var payload = JsonSerializer.Serialize(new
        {
            current_password = currentPassword,
            new_password = newPassword,
        });

        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            new Uri(_platformBaseUri, "/api/agent-sessions/account/password-change"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.UserAgent.ParseAdd("bke-licensing-agent");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        request.Headers.TryAddWithoutValidation(
            "x-bke-account-session-version",
            AccountSessionRemote.ProtocolVersion);
        request.Headers.TryAddWithoutValidation("x-request-id", Guid.NewGuid().ToString());
        request.Content = new StringContent(payload, Encoding.UTF8, "application/json");

        // Credential mutation is deliberately single-attempt. Never replay this POST.
        using var response = await _http.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);

        if ((int)response.StatusCode is >= 300 and <= 399)
        {
            throw new HttpRequestException(
                "BKE password-change authority redirected.");
        }

        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return new RemoteAccountPasswordChangeResult(
                "password_provider_unavailable",
                "PASSWORD_CHANGE_UNAVAILABLE",
                true);
        }

        EnsureProtocol(response);
        using var document = await ReadJsonAsync(response, cancellationToken);
        var root = document.RootElement;

        if (response.IsSuccessStatusCode)
        {
            if (RequiredString(root, "status") != "changed" ||
                !RequiredBoolean(root, "reauthentication_required"))
            {
                throw new InvalidDataException(
                    "Password-change success response drifted.");
            }

            return new RemoteAccountPasswordChangeResult("changed");
        }

        var error = OptionalString(root, "error");

        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            if (error == "INVALID_CREDENTIALS")
            {
                return new RemoteAccountPasswordChangeResult(
                    "invalid_credentials",
                    error);
            }

            if (error == "INVALID_TOKEN")
            {
                throw new UnauthorizedAccessException(
                    "BKE account session was rejected by password-change authority.");
            }

            throw new InvalidDataException(
                "Password-change unauthorized response drifted.");
        }

        if (response.StatusCode == HttpStatusCode.BadRequest)
        {
            return new RemoteAccountPasswordChangeResult(
                "invalid_input",
                error ?? "INVALID_INPUT");
        }

        if ((int)response.StatusCode == 429)
        {
            return new RemoteAccountPasswordChangeResult(
                "rate_limited",
                error ?? "RATE_LIMITED",
                true);
        }

        if (response.StatusCode == HttpStatusCode.ServiceUnavailable &&
            error == "PASSWORD_PROVIDER_UNAVAILABLE")
        {
            return new RemoteAccountPasswordChangeResult(
                "password_provider_unavailable",
                error,
                true);
        }

        throw new HttpRequestException(
            $"BKE password-change authority returned {(int)response.StatusCode}.",
            null,
            response.StatusCode);
    }

    private static void EnsureProtocol(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues(
                "x-bke-account-session-version",
                out var values))
        {
            throw new InvalidDataException(
                "Password-change response is missing its protocol version.");
        }

        var versions = values.ToArray();
        if (versions.Length != 1 ||
            versions[0] != AccountSessionRemote.ProtocolVersion)
        {
            throw new InvalidDataException(
                "Password-change protocol version drifted.");
        }
    }

    private static async Task<JsonDocument> ReadJsonAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        return await JsonDocument.ParseAsync(
            stream,
            cancellationToken: cancellationToken);
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

    private static string? OptionalString(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var value) ||
            value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        return value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
    }

    public void Dispose()
    {
        if (_ownsHttpClient)
        {
            _http.Dispose();
        }
    }
}
