using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using BKE.LicensingAgent.Application;

namespace BKE.LicensingAgent.Infrastructure;

public sealed class StoreCheckoutStatusRemote : IStoreCheckoutStatusRemote, IDisposable
{
    private static readonly HashSet<string> PaymentStatuses =
    [
        "NOT_REQUIRED",
        "NOT_STARTED",
        "CREATING",
        "PENDING",
        "SETTLED",
        "FAILED",
        "CANCELLED",
    ];

    private readonly Uri _platformBaseUri;
    private readonly HttpClient _http;
    private readonly bool _ownsHttpClient;
    private readonly bool _allowInsecureLocal;

    public StoreCheckoutStatusRemote(
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
                "Store checkout-status authority requires HTTPS outside isolated loopback certification.");
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

    public async Task<RemoteStoreCheckoutStatusResult> CheckAsync(
        string accessToken,
        string correlationId,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(accessToken) || accessToken.Length > 8192)
        {
            throw new InvalidDataException("Invalid Agent access token.");
        }

        if (string.IsNullOrWhiteSpace(correlationId) || correlationId.Length > 128)
        {
            throw new InvalidDataException("Invalid checkout correlation identifier.");
        }

        var relative =
            "/api/agent-sessions/store/checkout-status?correlation_id=" +
            Uri.EscapeDataString(correlationId);
        using var message = new HttpRequestMessage(
            HttpMethod.Get,
            new Uri(_platformBaseUri, relative));
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
            correlationId);

        using var response = await _http.SendAsync(
            message,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);

        if ((int)response.StatusCode is >= 300 and <= 399)
        {
            throw new HttpRequestException(
                "BKE Store checkout-status endpoint redirected.");
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
                    "Checkout-status authentication response drifted.");
            }

            throw new UnauthorizedAccessException(
                "BKE account session was rejected by checkout-status authority.");
        }

        if (response.StatusCode == HttpStatusCode.OK)
        {
            var status = RequiredString(root, "status", 32);
            if (status == "not_found")
            {
                RequireObjectKeys(root, ["status", "correlation_id"]);
                return new RemoteStoreCheckoutStatusResult(
                    "not_found",
                    RequiredString(root, "correlation_id", 128),
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null);
            }

            if (status != "found")
            {
                throw new InvalidDataException(
                    "Checkout-status success state drifted.");
            }

            RequireObjectKeys(root, [
                "status",
                "correlation_id",
                "order_id",
                "order_number",
                "order_status",
                "fulfillment_mode",
                "payment_status",
                "checkout_url",
                "paid_at",
            ]);

            var paymentStatus = RequiredString(root, "payment_status", 32);
            if (!PaymentStatuses.Contains(paymentStatus))
            {
                throw new InvalidDataException(
                    "Checkout-status payment state drifted.");
            }

            return new RemoteStoreCheckoutStatusResult(
                "found",
                RequiredString(root, "correlation_id", 128),
                RequiredString(root, "order_id", 256),
                RequiredString(root, "order_number", 256),
                RequiredString(root, "order_status", 64),
                RequiredString(root, "fulfillment_mode", 64),
                paymentStatus,
                OptionalCheckoutUrl(root, "checkout_url"),
                OptionalTimestamp(root, "paid_at"),
                null);
        }

        if ((int)response.StatusCode is < 400 or > 599)
        {
            throw new InvalidDataException(
                "Checkout-status authority returned an invalid status code.");
        }

        RequireObjectKeys(root, ["error"]);
        return new RemoteStoreCheckoutStatusResult(
            "error",
            correlationId,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            RequiredString(root, "error", 128));
    }

    private string? OptionalCheckoutUrl(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var value))
        {
            throw new InvalidDataException($"Missing {name}.");
        }

        if (value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        if (value.ValueKind != JsonValueKind.String)
        {
            throw new InvalidDataException($"Invalid {name}.");
        }

        var raw = value.GetString();
        if (string.IsNullOrWhiteSpace(raw) || raw.Length > 4096 ||
            !Uri.TryCreate(raw, UriKind.Absolute, out var uri) ||
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

    private static string? OptionalTimestamp(JsonElement root, string name)
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
            value.GetString()!.Length > 128 ||
            !DateTimeOffset.TryParse(value.GetString(), out _))
        {
            throw new InvalidDataException($"Invalid {name}.");
        }

        return value.GetString();
    }

    private static void EnsureProtocol(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues(
                "x-bke-account-session-version",
                out var values))
        {
            throw new InvalidDataException(
                "Checkout-status response is missing its protocol version.");
        }

        var versions = values.ToArray();
        if (versions.Length != 1 ||
            versions[0] != AccountSessionRemote.ProtocolVersion)
        {
            throw new InvalidDataException(
                "Checkout-status protocol version drifted.");
        }
    }

    private static void RequireObjectKeys(
        JsonElement item,
        IReadOnlyCollection<string> expected)
    {
        if (item.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException(
                "Checkout-status response shape is invalid.");
        }

        var keys = item.EnumerateObject()
            .Select(property => property.Name)
            .ToHashSet(StringComparer.Ordinal);
        if (!keys.SetEquals(expected))
        {
            throw new InvalidDataException(
                "Checkout-status response shape drifted.");
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
