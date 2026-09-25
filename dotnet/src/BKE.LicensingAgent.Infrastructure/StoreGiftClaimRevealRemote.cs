using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using BKE.LicensingAgent.Application;

namespace BKE.LicensingAgent.Infrastructure;

public sealed class StoreGiftClaimRevealRemote : IStoreGiftClaimRevealRemote, IDisposable
{
    private readonly Uri _platformBaseUri;
    private readonly HttpClient _http;
    private readonly bool _ownsHttpClient;

    public StoreGiftClaimRevealRemote(
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
                "Store gift Claim Code authority requires HTTPS outside isolated loopback certification.");
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

    public async Task<RemoteStoreGiftClaimRevealResult> RevealAsync(
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

        using var message = new HttpRequestMessage(
            HttpMethod.Post,
            new Uri(_platformBaseUri, "/api/agent-sessions/store/gift-claim-code"));
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
        message.Content = new StringContent(
            JsonSerializer.Serialize(new
            {
                correlation_id = correlationId,
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
                "BKE Store gift Claim Code endpoint redirected.");
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
                    "Gift Claim Code authentication response drifted.");
            }

            throw new UnauthorizedAccessException(
                "BKE account session was rejected by gift Claim Code authority.");
        }

        if (response.StatusCode == HttpStatusCode.OK)
        {
            var status = RequiredString(root, "status", 64);
            if (status == "available")
            {
                RequireObjectKeys(root, [
                    "status",
                    "correlation_id",
                    "order_id",
                    "claim_code_id",
                    "claim_code",
                ]);
                return new RemoteStoreGiftClaimRevealResult(
                    status,
                    RequiredString(root, "correlation_id", 128),
                    RequiredString(root, "order_id", 256),
                    RequiredString(root, "claim_code_id", 256),
                    RequiredString(root, "claim_code", 128));
            }

            if (status == "not_found")
            {
                RequireObjectKeys(root, ["status", "correlation_id"]);
                return new RemoteStoreGiftClaimRevealResult(
                    status,
                    RequiredString(root, "correlation_id", 128));
            }

            if (status is "fulfillment_pending" or "not_ready" or "cancelled")
            {
                RequireObjectKeys(root, ["status", "correlation_id", "order_id"]);
                return new RemoteStoreGiftClaimRevealResult(
                    status,
                    RequiredString(root, "correlation_id", 128),
                    RequiredString(root, "order_id", 256));
            }

            throw new InvalidDataException(
                "Gift Claim Code success state drifted.");
        }

        if ((int)response.StatusCode is < 400 or > 599)
        {
            throw new InvalidDataException(
                "Gift Claim Code authority returned an invalid status code.");
        }

        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException(
                "Gift Claim Code error response shape is invalid.");
        }

        if (root.TryGetProperty("status", out _))
        {
            RequireObjectKeys(root, ["status"]);
            var status = RequiredString(root, "status", 128);
            if (status is not (
                "account_forbidden" or
                "account_not_found" or
                "account_not_active" or
                "suspended_account" or
                "closed_account" or
                "claim_code_not_found" or
                "claim_code_already_used" or
                "claim_code_revoked" or
                "claim_code_expired"))
            {
                throw new InvalidDataException(
                    "Gift Claim Code terminal status drifted.");
            }

            return new RemoteStoreGiftClaimRevealResult(
                status,
                correlationId);
        }

        RequireObjectKeys(root, ["error"]);
        var error = RequiredString(root, "error", 128);
        if (error is not (
            "RATE_LIMITED" or
            "COMMERCE_UNAVAILABLE" or
            "CLAIM_CODE_UNAVAILABLE" or
            "FORBIDDEN" or
            "NOT_GIFT_ORDER" or
            "CLAIM_CODE_CARDINALITY_CONFLICT" or
            "NOT_FOUND"))
        {
            throw new InvalidDataException(
                "Gift Claim Code error code drifted.");
        }

        return new RemoteStoreGiftClaimRevealResult(
            error,
            correlationId,
            ErrorCode: error);
    }

    private static void EnsureProtocol(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues(
                "x-bke-account-session-version",
                out var values))
        {
            throw new InvalidDataException(
                "Gift Claim Code response is missing its protocol version.");
        }

        var versions = values.ToArray();
        if (versions.Length != 1 ||
            versions[0] != AccountSessionRemote.ProtocolVersion)
        {
            throw new InvalidDataException(
                "Gift Claim Code protocol version drifted.");
        }
    }

    private static void RequireObjectKeys(
        JsonElement item,
        IReadOnlyCollection<string> expected)
    {
        if (item.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException(
                "Gift Claim Code response shape is invalid.");
        }

        var keys = item.EnumerateObject()
            .Select(property => property.Name)
            .ToHashSet(StringComparer.Ordinal);
        if (!keys.SetEquals(expected))
        {
            throw new InvalidDataException(
                "Gift Claim Code response shape drifted.");
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
