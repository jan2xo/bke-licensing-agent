using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using BKE.LicensingAgent.Application;

namespace BKE.LicensingAgent.Infrastructure;

public sealed class ClaimCodeRedemptionRemote : IClaimCodeRedemptionRemote, IDisposable
{
    private readonly Uri _platformBaseUri;
    private readonly HttpClient _http;
    private readonly bool _ownsHttpClient;

    public ClaimCodeRedemptionRemote(
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
                "Claim Code redemption authority requires HTTPS outside isolated loopback certification.");
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

    public async Task<RemoteClaimCodeRedemptionResult> RedeemAsync(
        string accessToken,
        string code,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(accessToken) || accessToken.Length > 8192)
        {
            throw new InvalidDataException("Invalid Agent access token.");
        }

        if (string.IsNullOrWhiteSpace(code) || code.Length > 128)
        {
            throw new InvalidDataException("Invalid Claim Code.");
        }

        var payload = JsonSerializer.Serialize(new { code = code.Trim() });
        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            new Uri(_platformBaseUri, "/api/agent-sessions/claims/redeem"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.UserAgent.ParseAdd("bke-licensing-agent");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        request.Headers.TryAddWithoutValidation(
            "x-bke-account-session-version",
            AccountSessionRemote.ProtocolVersion);
        request.Headers.TryAddWithoutValidation("x-request-id", Guid.NewGuid().ToString());
        request.Content = new StringContent(payload, Encoding.UTF8, "application/json");

        using var response = await _http.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);

        if ((int)response.StatusCode is >= 300 and <= 399)
        {
            throw new HttpRequestException(
                "BKE Claim Code redemption endpoint redirected.");
        }

        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            throw new UnauthorizedAccessException(
                "BKE account session was rejected by Claim Code redemption authority.");
        }

        if (response.StatusCode is HttpStatusCode.RequestTimeout or
            (HttpStatusCode)425 or
            (HttpStatusCode)429 or
            HttpStatusCode.InternalServerError or
            HttpStatusCode.BadGateway or
            HttpStatusCode.ServiceUnavailable or
            HttpStatusCode.GatewayTimeout)
        {
            throw new HttpRequestException(
                $"BKE Claim Code redemption authority returned {(int)response.StatusCode}.",
                null,
                response.StatusCode);
        }

        EnsureProtocol(response);

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var document = await JsonDocument.ParseAsync(
            stream,
            cancellationToken: cancellationToken);
        var root = document.RootElement;
        var status = RequiredString(root, "status", 64);

        if (response.StatusCode == HttpStatusCode.Created)
        {
            if (status != "claimed")
            {
                throw new InvalidDataException(
                    "Claim Code redemption success status drifted.");
            }

            return new RemoteClaimCodeRedemptionResult(
                status,
                RequiredString(root, "account_id", 256),
                RequiredString(root, "entitlement_id", 256));
        }

        if ((int)response.StatusCode is >= 400 and <= 499 &&
            status is
                "claim_code_not_found" or
                "claim_code_already_used" or
                "claim_code_revoked" or
                "claim_code_expired" or
                "account_forbidden" or
                "account_not_found" or
                "account_not_active" or
                "suspended_account" or
                "closed_account")
        {
            return new RemoteClaimCodeRedemptionResult(status);
        }

        throw new InvalidDataException(
            "Claim Code redemption authority returned an invalid response.");
    }

    private static void EnsureProtocol(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues(
                "x-bke-account-session-version",
                out var values))
        {
            throw new InvalidDataException(
                "Claim Code redemption response is missing its protocol version.");
        }

        var versions = values.ToArray();
        if (versions.Length != 1 ||
            versions[0] != AccountSessionRemote.ProtocolVersion)
        {
            throw new InvalidDataException(
                "Claim Code redemption protocol version drifted.");
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
