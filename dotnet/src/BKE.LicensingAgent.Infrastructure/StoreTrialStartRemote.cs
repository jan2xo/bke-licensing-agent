using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Infrastructure;

public sealed class StoreTrialStartRemote :
    IStoreTrialStartRemote,
    IDisposable
{
    private readonly Uri _platformBaseUri;
    private readonly HttpClient _http;
    private readonly bool _ownsHttpClient;

    public StoreTrialStartRemote(
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
                "Store trial-start authority requires HTTPS outside isolated loopback certification.");
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

    public async Task<RemoteStoreTrialStartResult> StartAsync(
        string accessToken,
        StoreTrialStartRequest request,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(accessToken) ||
            accessToken.Length > 8192)
        {
            throw new InvalidDataException(
                "Invalid Agent access token.");
        }

        using var message = new HttpRequestMessage(
            HttpMethod.Post,
            new Uri(
                _platformBaseUri,
                "/api/agent-sessions/store/trials/start"));
        message.Headers.Accept.Add(
            new MediaTypeWithQualityHeaderValue(
                "application/json"));
        message.Headers.UserAgent.ParseAdd(
            "bke-licensing-agent");
        message.Headers.Authorization =
            new AuthenticationHeaderValue(
                "Bearer",
                accessToken);
        message.Headers.TryAddWithoutValidation(
            "x-bke-account-session-version",
            AccountSessionRemote.ProtocolVersion);
        message.Headers.TryAddWithoutValidation(
            "x-request-id",
            request.CorrelationId);
        message.Content = new StringContent(
            JsonSerializer.Serialize(new
            {
                correlation_id = request.CorrelationId,
                edition_id = request.EditionId,
            }),
            Encoding.UTF8,
            "application/json");

        using var response = await _http.SendAsync(
            message,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);

        if ((int)response.StatusCode is >= 300 and <= 399)
        {
            throw new HttpRequestException(
                "BKE Store trial-start endpoint redirected.");
        }

        await using var stream =
            await response.Content.ReadAsStreamAsync(
                cancellationToken);
        using var document = await JsonDocument.ParseAsync(
            stream,
            new JsonDocumentOptions { MaxDepth = 8 },
            cancellationToken);
        var root = document.RootElement;

        EnsureProtocol(response);

        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            RequireObjectKeys(root, ["error"]);
            if (RequiredString(root, "error", 128) !=
                "INVALID_TOKEN")
            {
                throw new InvalidDataException(
                    "Trial-start authentication response drifted.");
            }

            throw new UnauthorizedAccessException(
                "BKE account session was rejected by trial-start authority.");
        }

        if (response.StatusCode == HttpStatusCode.Created)
        {
            RequireObjectKeys(root, [
                "status",
                "correlation_id",
                "trial_ends_at",
                "grace_ends_at",
            ]);

            if (RequiredString(root, "status", 32) !=
                "started")
            {
                throw new InvalidDataException(
                    "Trial-start success status drifted.");
            }

            var correlationId =
                RequiredString(root, "correlation_id", 128);
            var trialEndsAt =
                RequiredTimestamp(root, "trial_ends_at");
            var graceEndsAt =
                RequiredTimestamp(root, "grace_ends_at");

            return new RemoteStoreTrialStartResult(
                "started",
                correlationId,
                trialEndsAt,
                graceEndsAt);
        }

        if ((int)response.StatusCode is < 400 or > 599)
        {
            throw new InvalidDataException(
                "Trial-start authority returned an invalid status code.");
        }

        RequireObjectKeys(root, ["error"]);
        return new RemoteStoreTrialStartResult(
            "error",
            request.CorrelationId,
            ErrorCode: RequiredString(root, "error", 128));
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

    private static void EnsureProtocol(
        HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues(
                "x-bke-account-session-version",
                out var values))
        {
            throw new InvalidDataException(
                "Trial-start response is missing its protocol version.");
        }

        var versions = values.ToArray();
        if (versions.Length != 1 ||
            versions[0] != AccountSessionRemote.ProtocolVersion)
        {
            throw new InvalidDataException(
                "Trial-start protocol version drifted.");
        }
    }

    private static void RequireObjectKeys(
        JsonElement item,
        IReadOnlyCollection<string> expected)
    {
        if (item.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException(
                "Trial-start response shape is invalid.");
        }

        var keys = item.EnumerateObject()
            .Select(property => property.Name)
            .ToHashSet(StringComparer.Ordinal);
        if (!keys.SetEquals(expected))
        {
            throw new InvalidDataException(
                "Trial-start response shape drifted.");
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

    public void Dispose()
    {
        if (_ownsHttpClient)
        {
            _http.Dispose();
        }
    }
}
