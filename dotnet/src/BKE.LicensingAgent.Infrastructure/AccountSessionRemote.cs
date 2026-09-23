using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Infrastructure;

public sealed class AccountSessionRemote : IAccountSessionRemote, IDisposable
{
    public const string ProtocolVersion = "bke.account-session.v1";

    private static readonly HashSet<HttpStatusCode> RetryableStatuses = new()
    {
        HttpStatusCode.RequestTimeout,
        (HttpStatusCode)425,
        (HttpStatusCode)429,
        HttpStatusCode.InternalServerError,
        HttpStatusCode.BadGateway,
        HttpStatusCode.ServiceUnavailable,
        HttpStatusCode.GatewayTimeout,
    };

    private readonly string _platformBaseUrl;
    private readonly HttpClient _http;
    private readonly bool _ownsHttpClient;

    public AccountSessionRemote(HttpClient? httpClient = null, string? platformBaseUrl = null)
    {
        _platformBaseUrl = (
            platformBaseUrl ??
            Environment.GetEnvironmentVariable("BKE_PLATFORM_BASE_URL") ??
            "https://jl-bke.com"
        ).TrimEnd('/');
        ValidatePlatformBaseUrl(_platformBaseUrl);

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

    public async Task<RemoteAccountSessionStart> StartAsync(CancellationToken cancellationToken)
    {
        var identity = MachineIdentityProvider.Calculate();
        var payload = JsonSerializer.Serialize(new
        {
            device_id = identity.DeviceId,
            device_name = Environment.MachineName,
            platform = MachineIdentityProvider.ProtocolPlatform(identity.Platform),
            architecture = MachineIdentityProvider.ProtocolArchitecture(identity.Architecture),
        });

        using var response = await SendAsync(
            HttpMethod.Post,
            "/api/agent-sessions/device/start",
            payload,
            null,
            cancellationToken);

        using var document = await ReadJsonAsync(response, cancellationToken);
        var root = document.RootElement;
        return new RemoteAccountSessionStart(
            RequiredString(root, "device_code"),
            RequiredHttpsUrl(root, "verification_uri"),
            RequiredString(root, "user_code"),
            TimeSpan.FromSeconds(RequiredPositiveInt(root, "expires_in", 1800)),
            TimeSpan.FromSeconds(RequiredPositiveInt(root, "interval", 60)));
    }

    public Task<RemoteAccountSessionPoll> PollAsync(
        string deviceCode,
        CancellationToken cancellationToken) =>
        ExchangeAsync(deviceCode, null, cancellationToken);

    public Task<RemoteAccountSessionPoll> ExchangeNativeHandoffAsync(
        string handoffCode,
        string deviceId,
        CancellationToken cancellationToken) =>
        ExchangeAsync(handoffCode, deviceId, cancellationToken);

    private async Task<RemoteAccountSessionPoll> ExchangeAsync(
        string code,
        string? deviceId,
        CancellationToken cancellationToken)
    {
        var payload = deviceId is null
            ? JsonSerializer.Serialize(new { device_code = code })
            : JsonSerializer.Serialize(new
            {
                device_code = code,
                device_id = deviceId,
            });
        using var response = await SendAsync(
            HttpMethod.Post,
            "/api/agent-sessions/device/token",
            payload,
            null,
            cancellationToken);

        using var document = await ReadJsonAsync(response, cancellationToken);
        var root = document.RootElement;
        var status = RequiredString(root, "status");

        if (status is "authorization_pending" or "slow_down" or "access_denied" or "expired_token")
        {
            return new RemoteAccountSessionPoll(status);
        }

        if (status != "approved")
        {
            throw new InvalidDataException("Unknown BKE account-session token status");
        }

        return new RemoteAccountSessionPoll(
            status,
            RequiredString(root, "access_token"),
            RequiredString(root, "refresh_token"),
            RequiredString(root, "session_id"),
            TimeSpan.FromSeconds(RequiredPositiveInt(root, "expires_in", 86_400)),
            TimeSpan.FromSeconds(RequiredPositiveInt(root, "refresh_expires_in", 90 * 24 * 60 * 60)),
            ParseAccount(root));
    }

    public async Task<RemoteAccountSessionRefresh> RefreshAsync(
        string refreshToken,
        CancellationToken cancellationToken)
    {
        var payload = JsonSerializer.Serialize(new { refresh_token = refreshToken });
        using var response = await SendRawAsync(
            HttpMethod.Post,
            "/api/agent-sessions/refresh",
            payload,
            null,
            cancellationToken);

        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            using var denied = await ReadJsonUncheckedAsync(response, cancellationToken);
            var error = OptionalString(denied.RootElement, "error");
            return new RemoteAccountSessionRefresh(
                error == "REFRESH_TOKEN_REPLAY" ? "replay_detected" : "invalid_grant");
        }

        EnsureSuccess(response);
        using var document = await ReadJsonUncheckedAsync(response, cancellationToken);
        var root = document.RootElement;
        if (RequiredString(root, "status") != "refreshed")
        {
            throw new InvalidDataException("Invalid BKE account-session refresh status");
        }

        return new RemoteAccountSessionRefresh(
            "refreshed",
            RequiredString(root, "access_token"),
            RequiredString(root, "refresh_token"),
            RequiredString(root, "session_id"),
            TimeSpan.FromSeconds(RequiredPositiveInt(root, "expires_in", 86_400)),
            TimeSpan.FromSeconds(RequiredPositiveInt(root, "refresh_expires_in", 90 * 24 * 60 * 60)),
            ParseAccount(root));
    }

    public async Task AcknowledgeAsync(
        string accessToken,
        CancellationToken cancellationToken)
    {
        using var response = await SendAsync(
            HttpMethod.Post,
            "/api/agent-sessions/device/ack",
            "{}",
            accessToken,
            cancellationToken);
        using var document = await ReadJsonAsync(response, cancellationToken);
        if (RequiredString(document.RootElement, "status") != "acknowledged")
        {
            throw new InvalidDataException("Invalid BKE account-session acknowledgement");
        }
    }

    public async Task RevokeAsync(
        string? sessionId,
        string? refreshToken,
        string? deviceCode,
        CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(refreshToken))
        {
            var payload = JsonSerializer.Serialize(new { refresh_token = refreshToken });
            using var response = await SendAsync(
                HttpMethod.Post,
                "/api/agent-sessions/revoke",
                payload,
                null,
                cancellationToken);
            using var document = await ReadJsonAsync(response, cancellationToken);
            if (RequiredString(document.RootElement, "status") != "revoked")
            {
                throw new InvalidDataException("Invalid BKE account-session revoke response");
            }
            return;
        }

        if (!string.IsNullOrWhiteSpace(deviceCode))
        {
            var payload = JsonSerializer.Serialize(new { device_code = deviceCode });
            using var response = await SendAsync(
                HttpMethod.Post,
                "/api/agent-sessions/device/cancel",
                payload,
                null,
                cancellationToken);
            using var document = await ReadJsonAsync(response, cancellationToken);
            if (RequiredString(document.RootElement, "status") != "cancelled")
            {
                throw new InvalidDataException("Invalid BKE device-authorization cancel response");
            }
        }
    }

    private async Task<HttpResponseMessage> SendAsync(
        HttpMethod method,
        string path,
        string? json,
        string? bearerToken,
        CancellationToken cancellationToken)
    {
        var response = await SendRawAsync(method, path, json, bearerToken, cancellationToken);
        try
        {
            EnsureSuccess(response);
            return response;
        }
        catch
        {
            response.Dispose();
            throw;
        }
    }

    private async Task<HttpResponseMessage> SendRawAsync(
        HttpMethod method,
        string path,
        string? json,
        string? bearerToken,
        CancellationToken cancellationToken)
    {
        Exception? lastError = null;

        for (var attempt = 0; attempt <= 2; attempt++)
        {
            using var request = new HttpRequestMessage(method, $"{_platformBaseUrl}{path}");
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Headers.UserAgent.ParseAdd("bke-licensing-agent");
            request.Headers.TryAddWithoutValidation(
                "x-bke-account-session-version",
                ProtocolVersion);
            request.Headers.TryAddWithoutValidation("x-request-id", Guid.NewGuid().ToString());

            if (!string.IsNullOrWhiteSpace(bearerToken))
            {
                request.Headers.Authorization =
                    new AuthenticationHeaderValue("Bearer", bearerToken);
            }

            if (json is not null)
            {
                request.Content = new StringContent(json, Encoding.UTF8, "application/json");
            }

            try
            {
                var response = await _http.SendAsync(
                    request,
                    HttpCompletionOption.ResponseHeadersRead,
                    cancellationToken);

                if (IsRedirect(response.StatusCode))
                {
                    response.Dispose();
                    throw new HttpRequestException("BKE account-session endpoint redirected");
                }

                if (RetryableStatuses.Contains(response.StatusCode) && attempt < 2)
                {
                    response.Dispose();
                    await Task.Delay(
                        TimeSpan.FromSeconds(0.25 * Math.Pow(2, attempt)),
                        cancellationToken);
                    continue;
                }

                return response;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception error) when (
                attempt < 2 &&
                error is HttpRequestException or TaskCanceledException)
            {
                lastError = error;
                await Task.Delay(
                    TimeSpan.FromSeconds(0.25 * Math.Pow(2, attempt)),
                    cancellationToken);
            }
            catch (Exception error)
            {
                lastError = error;
                break;
            }
        }

        throw new HttpRequestException("BKE account-session request failed", lastError);
    }

    private static void EnsureSuccess(HttpResponseMessage response)
    {
        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException(
                $"BKE account-session platform returned {(int)response.StatusCode}",
                null,
                response.StatusCode);
        }

        if (!response.Headers.TryGetValues(
                "x-bke-account-session-version",
                out var values))
        {
            throw new InvalidDataException("BKE account-session protocol response is missing its version");
        }

        var versions = values.ToArray();
        if (versions.Length != 1 ||
            !string.Equals(versions[0], ProtocolVersion, StringComparison.Ordinal))
        {
            throw new InvalidDataException("BKE account-session protocol response drifted");
        }
    }

    private static async Task<JsonDocument> ReadJsonAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        EnsureSuccess(response);
        return await ReadJsonUncheckedAsync(response, cancellationToken);
    }

    private static async Task<JsonDocument> ReadJsonUncheckedAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        return await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
    }

    private static AccountSessionAccount ParseAccount(JsonElement root)
    {
        var accountType = RequiredString(root, "account_type");
        if (accountType is not ("INDIVIDUAL" or "ORGANIZATION"))
        {
            throw new InvalidDataException("Invalid BKE account-session account type");
        }

        return new AccountSessionAccount(
            RequiredString(root, "user_id"),
            RequiredString(root, "email"),
            RequiredString(root, "account_id"),
            accountType,
            RequiredString(root, "account_display_name"));
    }

    private static string RequiredString(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var value) ||
            value.ValueKind != JsonValueKind.String ||
            string.IsNullOrWhiteSpace(value.GetString()))
        {
            throw new InvalidDataException($"Missing or invalid {name}");
        }
        return value.GetString()!;
    }

    private static string RequiredHttpsUrl(JsonElement root, string name)
    {
        var value = RequiredString(root, name);
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttps ||
            string.IsNullOrWhiteSpace(uri.Host))
        {
            throw new InvalidDataException($"Invalid {name}");
        }
        return uri.ToString();
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

    private static int RequiredPositiveInt(JsonElement root, string name, int maximum)
    {
        if (!root.TryGetProperty(name, out var value) ||
            value.ValueKind != JsonValueKind.Number ||
            !value.TryGetInt32(out var result) ||
            result <= 0 ||
            result > maximum)
        {
            throw new InvalidDataException($"Missing or invalid {name}");
        }
        return result;
    }

    private static bool IsRedirect(HttpStatusCode status) =>
        (int)status is >= 300 and <= 399;

    private static void ValidatePlatformBaseUrl(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp) ||
            !string.IsNullOrEmpty(uri.Query) ||
            !string.IsNullOrEmpty(uri.Fragment))
        {
            throw new InvalidOperationException(
                "BKE_PLATFORM_BASE_URL must be an absolute HTTP(S) URL without query or fragment");
        }

        if (uri.Scheme == Uri.UriSchemeHttps)
        {
            return;
        }

        var allowLocal =
            Environment.GetEnvironmentVariable("BKE_AGENT_VNEXT_ALLOW_INSECURE_LOCAL") == "1";
        if (!allowLocal || !uri.IsLoopback)
        {
            throw new InvalidOperationException(
                "HTTPS is required outside isolated loopback Gen2 certification");
        }
    }

    public void Dispose()
    {
        if (_ownsHttpClient)
        {
            _http.Dispose();
        }
    }
}
