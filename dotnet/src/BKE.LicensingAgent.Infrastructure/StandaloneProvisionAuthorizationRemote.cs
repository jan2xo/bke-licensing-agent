using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using BKE.LicensingAgent.Application;

namespace BKE.LicensingAgent.Infrastructure;

public sealed class StandaloneProvisionAuthorizationRemote :
    IStandaloneProvisionAuthorizationRemote,
    IDisposable
{
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

    private readonly Uri _platformBaseUri;
    private readonly HttpClient _http;
    private readonly bool _ownsHttpClient;

    public StandaloneProvisionAuthorizationRemote(
        HttpClient? httpClient = null,
        string? platformBaseUrl = null)
    {
        var rawBaseUrl = (
            platformBaseUrl ??
            Environment.GetEnvironmentVariable("BKE_PLATFORM_BASE_URL") ??
            "https://jl-bke.com"
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
                "Standalone provision authorization requires HTTPS outside isolated loopback certification.");
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

    public async Task<StandaloneProvisionAuthorizationResult> AuthorizeAsync(
        string accessToken,
        string productId,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(accessToken) || accessToken.Length > 8192)
        {
            throw new InvalidDataException("Invalid Agent access token.");
        }
        if (string.IsNullOrWhiteSpace(productId) || productId.Length > 128)
        {
            throw new InvalidDataException("Invalid product id.");
        }

        var identity = MachineIdentityProvider.Calculate();
        var body = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["product_id"] = productId,
            ["platform"] = MachineIdentityProvider.ProtocolPlatform(identity.Platform),
            ["architecture"] = MachineIdentityProvider.ProtocolArchitecture(identity.Architecture),
        };

        using var response = await SendAsync(
            "/api/agent-sessions/provision/standalone",
            accessToken,
            body,
            cancellationToken);

        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            throw new UnauthorizedAccessException(
                "BKE account session was rejected by the provision authority.");
        }

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var document = await JsonDocument.ParseAsync(
            stream,
            cancellationToken: cancellationToken);

        ValidateProtocol(response);

        if (response.IsSuccessStatusCode)
        {
            return ParseAuthorized(document.RootElement, productId);
        }

        return ParseRejected(document.RootElement, response.StatusCode);
    }

    private async Task<HttpResponseMessage> SendAsync(
        string path,
        string accessToken,
        IReadOnlyDictionary<string, string> body,
        CancellationToken cancellationToken)
    {
        Exception? lastError = null;

        for (var attempt = 0; attempt <= 2; attempt++)
        {
            using var request = new HttpRequestMessage(
                HttpMethod.Post,
                new Uri(_platformBaseUri, path));
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Headers.UserAgent.ParseAdd("bke-licensing-agent");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            request.Headers.TryAddWithoutValidation(
                "x-bke-account-session-version",
                AccountSessionRemote.ProtocolVersion);
            request.Headers.TryAddWithoutValidation(
                "x-request-id",
                Guid.NewGuid().ToString());
            request.Content = JsonContent.Create(body);

            try
            {
                var response = await _http.SendAsync(
                    request,
                    HttpCompletionOption.ResponseHeadersRead,
                    cancellationToken);

                if ((int)response.StatusCode is >= 300 and <= 399)
                {
                    response.Dispose();
                    throw new HttpRequestException(
                        "BKE standalone provision endpoint redirected.");
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

        throw new HttpRequestException(
            "BKE standalone provision authorization failed.",
            lastError);
    }

    private static StandaloneProvisionAuthorizationResult ParseAuthorized(
        JsonElement root,
        string requestedProductId)
    {
        if (root.ValueKind != JsonValueKind.Object ||
            !root.EnumerateObject()
                .Select(property => property.Name)
                .ToHashSet(StringComparer.Ordinal)
                .SetEquals(["status", "product_id", "version", "source"]))
        {
            throw new InvalidDataException(
                "BKE standalone provision authorization shape drifted.");
        }

        if (RequiredString(root, "status", 32) != "authorized")
        {
            throw new InvalidDataException(
                "BKE standalone provision authorization status drifted.");
        }

        var productId = RequiredString(root, "product_id", 128);
        if (!string.Equals(productId, requestedProductId, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "BKE standalone provision authorization product drifted.");
        }

        var version = RequiredString(root, "version", 128);

        if (!root.TryGetProperty("source", out var source) ||
            source.ValueKind != JsonValueKind.Object ||
            !source.EnumerateObject()
                .Select(property => property.Name)
                .ToHashSet(StringComparer.Ordinal)
                .SetEquals(["authority", "repository", "tag"]))
        {
            throw new InvalidDataException(
                "BKE standalone provision source shape drifted.");
        }

        if (RequiredString(source, "authority", 64) != "GITHUB_RELEASES")
        {
            throw new InvalidDataException(
                "BKE standalone provision source authority drifted.");
        }

        var repository = RequiredString(source, "repository", 256);
        if (!System.Text.RegularExpressions.Regex.IsMatch(
                repository,
                "^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$",
                System.Text.RegularExpressions.RegexOptions.CultureInvariant))
        {
            throw new InvalidDataException(
                "BKE standalone provision repository is invalid.");
        }

        var tag = RequiredString(source, "tag", 160);
        if (tag != "v" + version)
        {
            throw new InvalidDataException(
                "BKE standalone provision tag is not bound to the authorized version.");
        }

        return new StandaloneProvisionAuthorizationResult(
            "AUTHORIZED",
            new StandaloneProvisionAuthorization(
                productId,
                version,
                repository,
                tag));
    }

    private static StandaloneProvisionAuthorizationResult ParseRejected(
        JsonElement root,
        HttpStatusCode statusCode)
    {
        if (root.ValueKind != JsonValueKind.Object ||
            !root.TryGetProperty("status", out var status) ||
            status.ValueKind != JsonValueKind.String)
        {
            if (statusCode == HttpStatusCode.TooManyRequests ||
                (int)statusCode >= 500)
            {
                throw new HttpRequestException(
                    $"BKE provision authority returned {(int)statusCode}.",
                    null,
                    statusCode);
            }

            throw new InvalidDataException(
                "BKE standalone provision rejection shape drifted.");
        }

        var mapped = status.GetString() switch
        {
            "not_found" => "NOT_FOUND",
            "not_entitled" => "NOT_ENTITLED",
            "unsupported_execution_type" => "UNSUPPORTED_EXECUTION_TYPE",
            "release_unavailable" => "RELEASE_UNAVAILABLE",
            "distribution_unavailable" => "DISTRIBUTION_UNAVAILABLE",
            _ => throw new InvalidDataException(
                "BKE standalone provision rejection status drifted."),
        };

        return new StandaloneProvisionAuthorizationResult(mapped);
    }

    private static void ValidateProtocol(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues(
                "x-bke-account-session-version",
                out var versions))
        {
            throw new InvalidDataException(
                "BKE standalone provision response is missing its protocol version.");
        }

        var values = versions.ToArray();
        if (values.Length != 1 ||
            values[0] != AccountSessionRemote.ProtocolVersion)
        {
            throw new InvalidDataException(
                "BKE standalone provision protocol version drifted.");
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
            throw new InvalidDataException($"Missing or invalid {name}.");
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
