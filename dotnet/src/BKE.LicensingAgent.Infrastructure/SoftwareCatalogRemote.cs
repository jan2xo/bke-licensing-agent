using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using BKE.LicensingAgent.Application;

namespace BKE.LicensingAgent.Infrastructure;

public sealed class SoftwareCatalogRemote : ISoftwareCatalogRemote, IDisposable
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

    public SoftwareCatalogRemote(HttpClient? httpClient = null, string? platformBaseUrl = null)
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
                "Software catalog authority requires HTTPS outside isolated loopback certification.");
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

    public async Task<IReadOnlyList<RemoteSoftwareCatalogItem>> GetAsync(
        string accessToken,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(accessToken) || accessToken.Length > 8192)
        {
            throw new InvalidDataException("Invalid Agent access token.");
        }

        var identity = MachineIdentityProvider.Calculate();
        var platform = MachineIdentityProvider.ProtocolPlatform(identity.Platform);
        var architecture = MachineIdentityProvider.ProtocolArchitecture(identity.Architecture);
        var path =
            $"/api/agent-sessions/catalog?platform={Uri.EscapeDataString(platform)}&architecture={Uri.EscapeDataString(architecture)}";

        using var response = await SendAsync(path, accessToken, cancellationToken);
        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            throw new UnauthorizedAccessException("BKE account session was rejected by the catalog authority.");
        }

        EnsureSuccess(response);
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
        return Parse(document.RootElement);
    }

    private async Task<HttpResponseMessage> SendAsync(
        string path,
        string accessToken,
        CancellationToken cancellationToken)
    {
        Exception? lastError = null;

        for (var attempt = 0; attempt <= 2; attempt++)
        {
            using var request = new HttpRequestMessage(
                HttpMethod.Get,
                new Uri(_platformBaseUri, path));
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Headers.UserAgent.ParseAdd("bke-licensing-agent");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            request.Headers.TryAddWithoutValidation(
                "x-bke-account-session-version",
                AccountSessionRemote.ProtocolVersion);
            request.Headers.TryAddWithoutValidation("x-request-id", Guid.NewGuid().ToString());

            try
            {
                var response = await _http.SendAsync(
                    request,
                    HttpCompletionOption.ResponseHeadersRead,
                    cancellationToken);

                if ((int)response.StatusCode is >= 300 and <= 399)
                {
                    response.Dispose();
                    throw new HttpRequestException("BKE software catalog endpoint redirected.");
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

        throw new HttpRequestException("BKE software catalog request failed.", lastError);
    }

    private static void EnsureSuccess(HttpResponseMessage response)
    {
        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException(
                $"BKE software catalog authority returned {(int)response.StatusCode}.",
                null,
                response.StatusCode);
        }

        if (!response.Headers.TryGetValues(
                "x-bke-account-session-version",
                out var versions))
        {
            throw new InvalidDataException(
                "BKE software catalog response is missing its protocol version.");
        }

        var values = versions.ToArray();
        if (values.Length != 1 ||
            values[0] != AccountSessionRemote.ProtocolVersion)
        {
            throw new InvalidDataException(
                "BKE software catalog protocol version drifted.");
        }
    }

    private static IReadOnlyList<RemoteSoftwareCatalogItem> Parse(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException("BKE software catalog root is invalid.");
        }

        var rootKeys = root.EnumerateObject()
            .Select(property => property.Name)
            .ToHashSet(StringComparer.Ordinal);
        if (!rootKeys.SetEquals(["status", "account_id", "products"]) ||
            RequiredString(root, "status", 32) != "ok")
        {
            throw new InvalidDataException("BKE software catalog response shape drifted.");
        }

        _ = RequiredString(root, "account_id", 256);

        if (!root.TryGetProperty("products", out var products) ||
            products.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException("BKE software catalog products are invalid.");
        }

        var result = new List<RemoteSoftwareCatalogItem>();
        foreach (var item in products.EnumerateArray())
        {
            if (result.Count >= 1000 || item.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidDataException("BKE software catalog product count or shape is invalid.");
            }

            var keys = item.EnumerateObject()
                .Select(property => property.Name)
                .ToHashSet(StringComparer.Ordinal);
            if (!keys.SetEquals([
                    "product_id",
                    "display_name",
                    "summary",
                    "execution_type",
                    "entitled",
                    "installable",
                    "latest_version"]))
            {
                throw new InvalidDataException("BKE software catalog product shape drifted.");
            }

            var productId = RequiredString(item, "product_id", 128);
            var displayName = RequiredString(item, "display_name", 256);
            var summary = RequiredString(item, "summary", 4096);
            var executionType = OptionalExecutionType(item, "execution_type");
            var entitled = RequiredBoolean(item, "entitled");
            var installable = RequiredBoolean(item, "installable");
            var latestVersion = OptionalString(item, "latest_version", 128);

            if (installable &&
                (!entitled || executionType is null || latestVersion is null))
            {
                throw new InvalidDataException(
                    "BKE software catalog marked an incomplete product installable.");
            }

            result.Add(new RemoteSoftwareCatalogItem(
                productId,
                displayName,
                summary,
                executionType,
                entitled,
                installable,
                latestVersion));
        }

        return result;
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

    private static string? OptionalString(
        JsonElement root,
        string name,
        int maximumLength)
    {
        if (!root.TryGetProperty(name, out var value))
        {
            throw new InvalidDataException($"Missing {name}.");
        }

        if (value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        if (value.ValueKind != JsonValueKind.String ||
            string.IsNullOrWhiteSpace(value.GetString()) ||
            value.GetString()!.Length > maximumLength)
        {
            throw new InvalidDataException($"Invalid {name}.");
        }

        return value.GetString();
    }

    private static string? OptionalExecutionType(JsonElement root, string name)
    {
        var value = OptionalString(root, name, 32);
        if (value is null)
        {
            return null;
        }

        return value is "LAUNCHER_PLUGIN" or "STANDALONE"
            ? value
            : throw new InvalidDataException("Unknown BKE Launcher execution type.");
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

    public void Dispose()
    {
        if (_ownsHttpClient)
        {
            _http.Dispose();
        }
    }
}
