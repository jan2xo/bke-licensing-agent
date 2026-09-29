using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using BKE.LicensingAgent.Application;

namespace BKE.LicensingAgent.Infrastructure;

public sealed class AccountPrivacyRemote : IAccountPrivacyRemote, IDisposable
{
    private const string Endpoint = "/api/agent-sessions/privacy/requests";

    private readonly Uri _platformBaseUri;
    private readonly HttpClient _http;
    private readonly bool _ownsHttpClient;

    public AccountPrivacyRemote(
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
                "Account privacy authority requires HTTPS outside isolated loopback certification.");
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

    public async Task<RemoteAccountPrivacyResult> ListAsync(
        string accessToken,
        int limit,
        CancellationToken cancellationToken)
    {
        if (!ValidSecret(accessToken, 8192) || limit is < 1 or > 100)
        {
            return new RemoteAccountPrivacyResult(
                "invalid_input",
                ErrorCode: "INVALID_INPUT");
        }

        using var response = await SendAsync(
            HttpMethod.Get,
            $"{Endpoint}?limit={limit}",
            null,
            accessToken,
            cancellationToken);

        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return new RemoteAccountPrivacyResult(
                "privacy_unavailable",
                ErrorCode: "PRIVACY_UNAVAILABLE",
                Retryable: true);
        }

        EnsureProtocol(response);
        using var document = await ReadJsonAsync(
            response,
            cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            return ErrorResult(response.StatusCode, document.RootElement);
        }

        var root = document.RootElement;
        if (RequiredString(root, "status") != "ok")
        {
            throw new InvalidDataException(
                "Account privacy list response drifted.");
        }

        _ = RequiredString(root, "account_id");
        var requestTypes = RequiredPrivacyTypeArray(
            root,
            "request_types");
        var items = RequiredItems(root, "requests");

        return new RemoteAccountPrivacyResult(
            "ok",
            RequestTypes: requestTypes,
            Items: items);
    }

    public async Task<RemoteAccountPrivacyResult> CreateAsync(
        string accessToken,
        string requestType,
        string summary,
        CancellationToken cancellationToken)
    {
        if (!ValidSecret(accessToken, 8192) ||
            !ValidPrivacyType(requestType) ||
            !ValidSummary(summary))
        {
            return new RemoteAccountPrivacyResult(
                "invalid_input",
                ErrorCode: "INVALID_INPUT");
        }

        using var response = await SendAsync(
            HttpMethod.Post,
            Endpoint,
            JsonSerializer.Serialize(new
            {
                request_type = requestType,
                summary,
            }),
            accessToken,
            cancellationToken);

        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return new RemoteAccountPrivacyResult(
                "privacy_unavailable",
                ErrorCode: "PRIVACY_UNAVAILABLE",
                Retryable: true);
        }

        EnsureProtocol(response);
        using var document = await ReadJsonAsync(
            response,
            cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            return ErrorResult(response.StatusCode, document.RootElement);
        }

        var root = document.RootElement;
        if (RequiredString(root, "status") != "created")
        {
            throw new InvalidDataException(
                "Account privacy create response drifted.");
        }

        _ = RequiredString(root, "account_id");
        if (!root.TryGetProperty("request", out var item) ||
            item.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException(
                "Account privacy create response is missing request metadata.");
        }

        return new RemoteAccountPrivacyResult(
            "created",
            RequestId: RequiredString(item, "id"),
            RequestType: RequiredPrivacyType(item, "request_type"),
            RequestStatus: RequiredStatus(item, "status"));
    }

    private async Task<HttpResponseMessage> SendAsync(
        HttpMethod method,
        string path,
        string? json,
        string accessToken,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(
            method,
            new Uri(_platformBaseUri, path));
        request.Headers.Accept.Add(
            new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.UserAgent.ParseAdd("bke-licensing-agent");
        request.Headers.Authorization =
            new AuthenticationHeaderValue("Bearer", accessToken);
        request.Headers.TryAddWithoutValidation(
            "x-bke-account-session-version",
            AccountSessionRemote.ProtocolVersion);
        request.Headers.TryAddWithoutValidation(
            "x-request-id",
            Guid.NewGuid().ToString("N"));

        if (json is not null)
        {
            request.Content = new StringContent(
                json,
                Encoding.UTF8,
                "application/json");
        }

        // Privacy create is deliberately single-attempt. Replaying an
        // ambiguous POST could create a duplicate data-subject request.
        var response = await _http.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);

        if ((int)response.StatusCode is >= 300 and <= 399)
        {
            response.Dispose();
            throw new HttpRequestException(
                "BKE account privacy authority redirected.");
        }

        return response;
    }

    private static RemoteAccountPrivacyResult ErrorResult(
        HttpStatusCode statusCode,
        JsonElement root)
    {
        var error = OptionalString(root, "error") ??
            "PRIVACY_UNAVAILABLE";

        if (statusCode == HttpStatusCode.Unauthorized &&
            error == "INVALID_TOKEN")
        {
            throw new UnauthorizedAccessException(
                "BKE account session was rejected by privacy authority.");
        }

        var normalized = error switch
        {
            "INVALID_INPUT" => "invalid_input",
            "RATE_LIMITED" => "rate_limited",
            "PRIVACY_UNAVAILABLE" => "privacy_unavailable",
            _ => error.ToLowerInvariant(),
        };

        return new RemoteAccountPrivacyResult(
            normalized,
            ErrorCode: error,
            Retryable:
                (int)statusCode == 429 ||
                statusCode == HttpStatusCode.ServiceUnavailable);
    }

    private static void EnsureProtocol(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues(
                "x-bke-account-session-version",
                out var values))
        {
            throw new InvalidDataException(
                "Account privacy response is missing its protocol version.");
        }

        var versions = values.ToArray();
        if (versions.Length != 1 ||
            versions[0] != AccountSessionRemote.ProtocolVersion)
        {
            throw new InvalidDataException(
                "Account privacy protocol version drifted.");
        }
    }

    private static async Task<JsonDocument> ReadJsonAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        await using var stream =
            await response.Content.ReadAsStreamAsync(cancellationToken);
        return await JsonDocument.ParseAsync(
            stream,
            cancellationToken: cancellationToken);
    }

    private static IReadOnlyList<string> RequiredPrivacyTypeArray(
        JsonElement root,
        string name)
    {
        if (!root.TryGetProperty(name, out var value) ||
            value.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException(
                $"Missing or invalid {name}.");
        }

        var values = value.EnumerateArray()
            .Select(item =>
                item.ValueKind == JsonValueKind.String &&
                ValidPrivacyType(item.GetString())
                    ? item.GetString()!
                    : throw new InvalidDataException(
                        $"Invalid {name} item."))
            .ToArray();

        if (values.Length is < 1 or > 32 ||
            values.Distinct(StringComparer.Ordinal).Count() !=
                values.Length)
        {
            throw new InvalidDataException(
                $"Invalid {name} length or duplicates.");
        }

        return values;
    }

    private static IReadOnlyList<RemoteAccountPrivacyItem> RequiredItems(
        JsonElement root,
        string name)
    {
        if (!root.TryGetProperty(name, out var value) ||
            value.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException(
                $"Missing or invalid {name}.");
        }

        var items = value.EnumerateArray()
            .Select(item =>
            {
                if (item.ValueKind != JsonValueKind.Object)
                {
                    throw new InvalidDataException(
                        $"Invalid {name} item.");
                }

                var scope = RequiredString(item, "scope");
                if (scope is not ("USER" or "ACCOUNT"))
                {
                    throw new InvalidDataException(
                        "Account privacy request scope drifted.");
                }

                var summary = RequiredString(item, "summary");
                if (!ValidSummary(summary))
                {
                    throw new InvalidDataException(
                        "Account privacy request summary drifted.");
                }

                return new RemoteAccountPrivacyItem(
                    RequiredString(item, "id"),
                    scope,
                    RequiredPrivacyType(item, "request_type"),
                    RequiredStatus(item, "status"),
                    summary,
                    OptionalBoundedString(
                        item,
                        "response_summary",
                        4_000),
                    OptionalTimestamp(item, "reviewed_at"),
                    OptionalTimestamp(item, "closed_at"),
                    RequiredTimestamp(item, "created_at"));
            })
            .ToArray();

        if (items.Length > 100)
        {
            throw new InvalidDataException(
                "Account privacy request list is too large.");
        }

        return items;
    }

    private static string RequiredPrivacyType(
        JsonElement root,
        string name)
    {
        var value = RequiredString(root, name);
        if (!ValidPrivacyType(value))
        {
            throw new InvalidDataException(
                $"Invalid {name}.");
        }
        return value;
    }

    private static string RequiredStatus(
        JsonElement root,
        string name)
    {
        var value = RequiredString(root, name);
        if (value.Length > 64 ||
            value.Any(character =>
                character is not (>= 'A' and <= 'Z') &&
                character != '_'))
        {
            throw new InvalidDataException(
                $"Invalid {name}.");
        }
        return value;
    }

    private static string RequiredTimestamp(
        JsonElement root,
        string name)
    {
        var value = RequiredString(root, name);
        if (!DateTimeOffset.TryParse(value, out _))
        {
            throw new InvalidDataException(
                $"Invalid {name} timestamp.");
        }
        return value;
    }

    private static string? OptionalTimestamp(
        JsonElement root,
        string name)
    {
        var value = OptionalString(root, name);
        if (value is null)
        {
            return null;
        }
        if (!DateTimeOffset.TryParse(value, out _))
        {
            throw new InvalidDataException(
                $"Invalid {name} timestamp.");
        }
        return value;
    }

    private static string? OptionalBoundedString(
        JsonElement root,
        string name,
        int maximum)
    {
        var value = OptionalString(root, name);
        if (value is null)
        {
            return null;
        }
        if (value.Length > maximum)
        {
            throw new InvalidDataException(
                $"Invalid {name} length.");
        }
        return value;
    }

    private static string RequiredString(
        JsonElement root,
        string name)
    {
        if (!root.TryGetProperty(name, out var value) ||
            value.ValueKind != JsonValueKind.String ||
            string.IsNullOrWhiteSpace(value.GetString()))
        {
            throw new InvalidDataException(
                $"Missing or invalid {name}.");
        }
        return value.GetString()!;
    }

    private static string? OptionalString(
        JsonElement root,
        string name)
    {
        if (!root.TryGetProperty(name, out var value) ||
            value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }
        return value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : throw new InvalidDataException(
                $"Invalid {name}.");
    }

    private static bool ValidPrivacyType(string? value) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length is >= 3 and <= 64 &&
        value.All(character =>
            character is >= 'A' and <= 'Z' ||
            character == '_');

    private static bool ValidSummary(string? value) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Trim().Length is >= 10 and <= 2_000 &&
        value.All(character =>
            character >= 32 ||
            character is '\r' or '\n' or '\t');

    private static bool ValidSecret(string value, int max) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length <= max;

    public void Dispose()
    {
        if (_ownsHttpClient)
        {
            _http.Dispose();
        }
    }
}
