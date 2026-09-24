using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Infrastructure;

public sealed class StoreCheckoutStartRemote : IStoreCheckoutStartRemote, IDisposable
{
    private readonly Uri _platformBaseUri;
    private readonly HttpClient _http;
    private readonly bool _ownsHttpClient;
    private readonly bool _allowInsecureLocal;

    public StoreCheckoutStartRemote(
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

        _allowInsecureLocal =
            Environment.GetEnvironmentVariable("BKE_AGENT_VNEXT_ALLOW_INSECURE_LOCAL") == "1" &&
            baseUri.IsLoopback &&
            baseUri.Scheme == Uri.UriSchemeHttp;

        if (baseUri.Scheme != Uri.UriSchemeHttps && !_allowInsecureLocal)
        {
            throw new InvalidOperationException(
                "Store checkout-start authority requires HTTPS outside isolated loopback certification.");
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

    public async Task<RemoteStoreCheckoutStartResult> StartAsync(
        string accessToken,
        StoreCheckoutStartRequest request,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(accessToken) || accessToken.Length > 8192)
        {
            throw new InvalidDataException("Invalid Agent access token.");
        }

        using var message = new HttpRequestMessage(
            HttpMethod.Post,
            new Uri(_platformBaseUri, "/api/agent-sessions/store/checkout-start"));
        message.Headers.Accept.Add(
            new MediaTypeWithQualityHeaderValue("application/json"));
        message.Headers.UserAgent.ParseAdd("bke-licensing-agent");
        message.Headers.Authorization =
            new AuthenticationHeaderValue("Bearer", accessToken);
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
                purchase_plan_id = request.PurchasePlanId,
                purchase_mode = request.PurchaseMode,
                legal_version_ids = request.LegalVersionIds,
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
                "BKE Store checkout-start endpoint redirected.");
        }

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var document = await JsonDocument.ParseAsync(
            stream,
            new JsonDocumentOptions { MaxDepth = 12 },
            cancellationToken);
        var root = document.RootElement;

        EnsureProtocol(response);

        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            RequireObjectKeys(root, ["error"]);
            if (RequiredString(root, "error", 128) != "INVALID_TOKEN")
            {
                throw new InvalidDataException(
                    "Checkout-start authentication response drifted.");
            }

            throw new UnauthorizedAccessException(
                "BKE account session was rejected by checkout-start authority.");
        }

        if (response.StatusCode == HttpStatusCode.Created)
        {
            RequireObjectKeys(root, [
                "status",
                "correlation_id",
                "order_id",
                "checkout_url",
                "complimentary",
            ]);

            if (RequiredString(root, "status", 32) != "ready")
            {
                throw new InvalidDataException(
                    "Checkout-start success status drifted.");
            }

            var correlationId = RequiredString(root, "correlation_id", 128);
            var orderId = RequiredString(root, "order_id", 256);
            var checkoutUrl = RequiredCheckoutUrl(root, "checkout_url");
            var complimentary = RequiredBoolean(root, "complimentary");

            return new RemoteStoreCheckoutStartResult(
                "ready",
                correlationId,
                orderId,
                checkoutUrl,
                complimentary,
                null);
        }

        if ((int)response.StatusCode is < 400 or > 599)
        {
            throw new InvalidDataException(
                "Checkout-start authority returned an invalid status code.");
        }

        RequireObjectKeys(root, ["error"]);
        return new RemoteStoreCheckoutStartResult(
            "error",
            request.CorrelationId,
            null,
            null,
            null,
            RequiredString(root, "error", 128));
    }

    private string RequiredCheckoutUrl(JsonElement root, string name)
    {
        var raw = RequiredString(root, name, 4096);
        if (!Uri.TryCreate(raw, UriKind.Absolute, out var uri) ||
            !string.IsNullOrEmpty(uri.UserInfo) ||
            !string.IsNullOrEmpty(uri.Fragment))
        {
            throw new InvalidDataException("Checkout URL is invalid.");
        }

        var secure = uri.Scheme == Uri.UriSchemeHttps;
        var isolatedLocal =
            _allowInsecureLocal &&
            uri.IsLoopback &&
            uri.Scheme == Uri.UriSchemeHttp;
        if (!secure && !isolatedLocal)
        {
            throw new InvalidDataException(
                "Checkout URL must use HTTPS outside isolated loopback certification.");
        }

        return uri.ToString();
    }

    private static void EnsureProtocol(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues(
                "x-bke-account-session-version",
                out var values))
        {
            throw new InvalidDataException(
                "Checkout-start response is missing its protocol version.");
        }

        var versions = values.ToArray();
        if (versions.Length != 1 ||
            versions[0] != AccountSessionRemote.ProtocolVersion)
        {
            throw new InvalidDataException(
                "Checkout-start protocol version drifted.");
        }
    }

    private static void RequireObjectKeys(
        JsonElement item,
        IReadOnlyCollection<string> expected)
    {
        if (item.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException(
                "Checkout-start response shape is invalid.");
        }

        var keys = item.EnumerateObject()
            .Select(property => property.Name)
            .ToHashSet(StringComparer.Ordinal);
        if (!keys.SetEquals(expected))
        {
            throw new InvalidDataException(
                "Checkout-start response shape drifted.");
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

    public void Dispose()
    {
        if (_ownsHttpClient)
        {
            _http.Dispose();
        }
    }
}
