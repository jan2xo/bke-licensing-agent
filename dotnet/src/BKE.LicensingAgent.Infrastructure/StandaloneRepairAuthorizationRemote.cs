using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using BKE.LicensingAgent.Application;

namespace BKE.LicensingAgent.Infrastructure;

public sealed class StandaloneRepairAuthorizationRemote :
    IStandaloneRepairAuthorizationRemote,
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

    private static readonly HashSet<string> PolicyFields = new(StringComparer.Ordinal)
    {
        "schema","product_id","repair_version","channel","platform","architecture",
        "source_authority","repository","tag","issued_at","expires_at",
        "signing_key_id","algorithm","signature",
    };

    private readonly Uri _platformBaseUri;
    private readonly HttpClient _http;
    private readonly bool _ownsHttpClient;

    public StandaloneRepairAuthorizationRemote(
        HttpClient? httpClient = null,
        string? platformBaseUrl = null)
    {
        var raw = (platformBaseUrl ??
            Environment.GetEnvironmentVariable("BKE_PLATFORM_BASE_URL") ??
            "https://jl-bke.com").TrimEnd('/');
        if (!Uri.TryCreate(raw, UriKind.Absolute, out var baseUri))
            throw new InvalidOperationException("BKE_PLATFORM_BASE_URL is invalid.");
        var allowLocal =
            Environment.GetEnvironmentVariable("BKE_AGENT_VNEXT_ALLOW_INSECURE_LOCAL") == "1" &&
            baseUri.IsLoopback &&
            baseUri.Scheme == Uri.UriSchemeHttp;
        if (baseUri.Scheme != Uri.UriSchemeHttps && !allowLocal)
            throw new InvalidOperationException(
                "Standalone Repair authorization requires HTTPS outside isolated loopback certification.");
        if (!string.IsNullOrEmpty(baseUri.Query) || !string.IsNullOrEmpty(baseUri.Fragment))
            throw new InvalidOperationException("BKE_PLATFORM_BASE_URL must not contain query or fragment.");

        _platformBaseUri = baseUri;
        _http = httpClient ?? new HttpClient(new HttpClientHandler
        {
            AllowAutoRedirect = false,
        })
        {
            Timeout = TimeSpan.FromSeconds(20),
        };
        _ownsHttpClient = httpClient is null;
    }

    public async Task<StandaloneRepairAuthorizationResult> AuthorizeAsync(
        string accessToken,
        string productId,
        string currentVersion,
        CancellationToken cancellationToken)
    {
        var identity = MachineIdentityProvider.Calculate();
        var body = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["product_id"] = productId,
            ["current_version"] = currentVersion,
            ["channel"] = "stable",
            ["platform"] = MachineIdentityProvider.ProtocolPlatform(identity.Platform),
            ["architecture"] = MachineIdentityProvider.ProtocolArchitecture(identity.Architecture),
        };

        using var response = await SendAsync(accessToken, body, cancellationToken);
        if (response.StatusCode == HttpStatusCode.Unauthorized)
            throw new UnauthorizedAccessException(
                "BKE account session was rejected by the Repair authority.");

        await using var stream =
            await response.Content.ReadAsStreamAsync(cancellationToken);
        using var document =
            await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
        ValidateProtocol(response);

        if (response.IsSuccessStatusCode)
        {
            return ParseSuccess(
                document.RootElement,
                productId,
                currentVersion,
                body["platform"],
                body["architecture"]);
        }

        return ParseRejected(document.RootElement, response.StatusCode);
    }

    private async Task<HttpResponseMessage> SendAsync(
        string accessToken,
        IReadOnlyDictionary<string, string> body,
        CancellationToken cancellationToken)
    {
        Exception? last = null;
        for (var attempt = 0; attempt <= 2; attempt++)
        {
            using var request = new HttpRequestMessage(
                HttpMethod.Post,
                new Uri(_platformBaseUri, "/api/agent-sessions/repair/standalone"));
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
                        "BKE standalone Repair endpoint redirected.");
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
            catch (OperationCanceledException)
                when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
                when (attempt < 2 &&
                      exception is HttpRequestException or TaskCanceledException)
            {
                last = exception;
                await Task.Delay(
                    TimeSpan.FromSeconds(0.25 * Math.Pow(2, attempt)),
                    cancellationToken);
            }
            catch (Exception exception)
            {
                last = exception;
                break;
            }
        }

        throw new HttpRequestException(
            "BKE standalone Repair authorization failed.",
            last);
    }

    private static StandaloneRepairAuthorizationResult ParseSuccess(
        JsonElement root,
        string productId,
        string currentVersion,
        string platform,
        string architecture)
    {
        if (RequiredString(root, "status", 64) != "repair_authorized" ||
            !root.EnumerateObject()
                .Select(property => property.Name)
                .ToHashSet(StringComparer.Ordinal)
                .SetEquals(["status", "policy"]) ||
            !root.TryGetProperty("policy", out var policy) ||
            policy.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException(
                "BKE Repair authorization shape drifted.");
        }

        if (!policy.EnumerateObject()
                .Select(property => property.Name)
                .ToHashSet(StringComparer.Ordinal)
                .SetEquals(PolicyFields) ||
            RequiredString(policy, "schema", 64) != "bke.repair-policy.v1" ||
            RequiredString(policy, "product_id", 128) != productId ||
            RequiredString(policy, "repair_version", 64) != currentVersion ||
            RequiredString(policy, "channel", 32) != "stable" ||
            RequiredString(policy, "platform", 32) != platform ||
            RequiredString(policy, "architecture", 32) != architecture ||
            RequiredString(policy, "source_authority", 64) != "GITHUB_RELEASES" ||
            RequiredString(policy, "algorithm", 32) != "Ed25519")
        {
            throw new InvalidDataException(
                "BKE Repair policy context drifted.");
        }

        var repository = RequiredString(policy, "repository", 256);
        if (!Regex.IsMatch(
                repository,
                "^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$",
                RegexOptions.CultureInvariant) ||
            RequiredString(policy, "tag", 160) != "v" + currentVersion)
        {
            throw new InvalidDataException(
                "BKE Repair policy release source drifted.");
        }

        _ = RequiredString(policy, "issued_at", 64);
        _ = RequiredString(policy, "expires_at", 64);
        _ = RequiredString(policy, "signing_key_id", 128);
        _ = RequiredString(policy, "signature", 4096);

        return new StandaloneRepairAuthorizationResult(
            "REPAIR_AUTHORIZED",
            new StandaloneRepairAuthorization(
                productId,
                currentVersion,
                repository,
                "v" + currentVersion,
                policy.GetRawText()));
    }

    private static StandaloneRepairAuthorizationResult ParseRejected(
        JsonElement root,
        HttpStatusCode code)
    {
        if (root.ValueKind != JsonValueKind.Object ||
            !root.TryGetProperty("status", out var status) ||
            status.ValueKind != JsonValueKind.String)
        {
            if (code == HttpStatusCode.TooManyRequests || (int)code >= 500)
                throw new HttpRequestException(
                    $"BKE Repair authority returned {(int)code}.",
                    null,
                    code);
            throw new InvalidDataException(
                "BKE standalone Repair rejection shape drifted.");
        }

        return new StandaloneRepairAuthorizationResult(
            status.GetString() switch
            {
                "not_entitled" => "NOT_ENTITLED",
                "unsupported_execution_type" => "UNSUPPORTED_EXECUTION_TYPE",
                "distribution_unavailable" => "DISTRIBUTION_UNAVAILABLE",
                "not_found" => "NOT_FOUND",
                _ => throw new InvalidDataException(
                    "BKE standalone Repair rejection status drifted."),
            });
    }

    private static void ValidateProtocol(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues(
                "x-bke-account-session-version",
                out var values) ||
            values.SingleOrDefault() != AccountSessionRemote.ProtocolVersion)
        {
            throw new InvalidDataException(
                "BKE Repair authority protocol drifted.");
        }
    }

    private static string RequiredString(
        JsonElement root,
        string name,
        int maximum)
    {
        if (!root.TryGetProperty(name, out var value) ||
            value.ValueKind != JsonValueKind.String ||
            string.IsNullOrWhiteSpace(value.GetString()) ||
            value.GetString()!.Length > maximum)
        {
            throw new InvalidDataException(
                $"BKE Repair authority field is invalid: {name}.");
        }

        return value.GetString()!;
    }

    public void Dispose()
    {
        if (_ownsHttpClient)
            _http.Dispose();
    }
}
