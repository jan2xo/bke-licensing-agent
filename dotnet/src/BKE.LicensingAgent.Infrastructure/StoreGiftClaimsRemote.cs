using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Infrastructure;

public sealed class StoreGiftClaimsRemote :
    IStoreGiftClaimsRemote,
    IDisposable
{
    private static readonly HashSet<HttpStatusCode>
        RetryableListStatuses = new()
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

    public StoreGiftClaimsRemote(
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
                "Persistent Gift Claim Code authority requires HTTPS outside isolated loopback certification.");
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

    public async Task<RemoteStoreGiftClaimsListResult> ListAsync(
        string accessToken,
        string correlationId,
        CancellationToken cancellationToken)
    {
        ValidateAccessToken(accessToken);
        ValidateCorrelationId(correlationId);

        using var response = await SendListAsync(
            accessToken,
            correlationId,
            cancellationToken);

        using var document = await ReadJsonAsync(
            response,
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
                    "Gift Claim Code list authentication response drifted.");
            }

            throw new UnauthorizedAccessException(
                "BKE account session was rejected by Gift Claim Code list authority.");
        }

        if (response.StatusCode == HttpStatusCode.OK)
        {
            RequireObjectKeys(root, [
                "status",
                "correlation_id",
                "account_lifecycle_state",
                "claims",
            ]);
            if (RequiredString(root, "status", 64) != "ready")
            {
                throw new InvalidDataException(
                    "Gift Claim Code list status drifted.");
            }

            var returnedCorrelation =
                RequiredString(root, "correlation_id", 128);
            var lifecycle = RequiredUpperToken(
                root,
                "account_lifecycle_state",
                64);

            if (!root.TryGetProperty("claims", out var claims) ||
                claims.ValueKind != JsonValueKind.Array)
            {
                throw new InvalidDataException(
                    "Gift Claim Code list claims are invalid.");
            }

            var parsed = new List<StoreGiftClaimItem>();
            foreach (var item in claims.EnumerateArray())
            {
                if (parsed.Count >= 100)
                {
                    throw new InvalidDataException(
                        "Gift Claim Code list exceeded its bounded projection.");
                }
                parsed.Add(ParseClaim(item));
            }

            return new RemoteStoreGiftClaimsListResult(
                "ready",
                returnedCorrelation,
                lifecycle,
                parsed);
        }

        if (root.ValueKind == JsonValueKind.Object &&
            root.TryGetProperty("status", out _))
        {
            RequireObjectKeys(root, ["status"]);
            var status = RequiredString(root, "status", 128);
            if (status is not (
                "account_forbidden" or
                "account_not_found" or
                "account_not_active" or
                "suspended_account" or
                "closed_account"))
            {
                throw new InvalidDataException(
                    "Gift Claim Code list terminal status drifted.");
            }

            return new RemoteStoreGiftClaimsListResult(
                status,
                correlationId);
        }

        RequireObjectKeys(root, ["error"]);
        var error = RequiredString(root, "error", 128);
        var normalized = error switch
        {
            "LEGAL_REACCEPTANCE_REQUIRED" =>
                "legal_reacceptance_required",
            "RATE_LIMITED" => "rate_limited",
            "FORBIDDEN" or "ACCOUNT_ROLE_FORBIDDEN" =>
                "account_forbidden",
            "ACCOUNT_NOT_FOUND" => "account_not_found",
            _ => throw new InvalidDataException(
                "Gift Claim Code list error code drifted."),
        };

        return new RemoteStoreGiftClaimsListResult(
            normalized,
            correlationId,
            ErrorCode: error,
            Retryable:
                response.StatusCode == (HttpStatusCode)429 ||
                response.StatusCode ==
                    HttpStatusCode.ServiceUnavailable);
    }

    public async Task<RemoteStoreGiftClaimPersistentRevealResult>
        RevealAsync(
            string accessToken,
            string correlationId,
            string giftClaimHandle,
            CancellationToken cancellationToken)
    {
        ValidateAccessToken(accessToken);
        ValidateCorrelationId(correlationId);
        if (!ValidGiftClaimHandle(giftClaimHandle))
        {
            throw new InvalidDataException(
                "Invalid Gift Claim Code handle.");
        }

        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            new Uri(
                _platformBaseUri,
                "/api/agent-sessions/store/gift-claim-codes/reveal"));
        request.Headers.Accept.Add(
            new MediaTypeWithQualityHeaderValue(
                "application/json"));
        request.Headers.UserAgent.ParseAdd(
            "bke-licensing-agent");
        request.Headers.Authorization =
            new AuthenticationHeaderValue(
                "Bearer",
                accessToken);
        request.Headers.TryAddWithoutValidation(
            "x-bke-account-session-version",
            AccountSessionRemote.ProtocolVersion);
        request.Headers.TryAddWithoutValidation(
            "x-request-id",
            correlationId);
        request.Content = new StringContent(
            JsonSerializer.Serialize(new
            {
                correlation_id = correlationId,
                gift_claim_handle = giftClaimHandle,
            }),
            Encoding.UTF8,
            "application/json");

        using var response = await _http.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);

        if ((int)response.StatusCode is >= 300 and <= 399)
        {
            throw new HttpRequestException(
                "BKE Gift Claim Code reveal endpoint redirected.");
        }

        using var document = await ReadJsonAsync(
            response,
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
                    "Gift Claim Code reveal authentication response drifted.");
            }

            throw new UnauthorizedAccessException(
                "BKE account session was rejected by Gift Claim Code reveal authority.");
        }

        if (response.StatusCode == HttpStatusCode.OK)
        {
            RequireObjectKeys(root, [
                "status",
                "correlation_id",
                "gift_claim_handle",
                "claim_code",
            ]);
            if (RequiredString(root, "status", 64) != "available")
            {
                throw new InvalidDataException(
                    "Gift Claim Code reveal success status drifted.");
            }

            var returnedHandle =
                RequiredString(root, "gift_claim_handle", 128);
            if (!ValidGiftClaimHandle(returnedHandle))
            {
                throw new InvalidDataException(
                    "Gift Claim Code reveal returned an invalid handle.");
            }

            return new RemoteStoreGiftClaimPersistentRevealResult(
                "available",
                RequiredString(root, "correlation_id", 128),
                returnedHandle,
                RequiredClaimCode(root, "claim_code"));
        }

        if (root.ValueKind == JsonValueKind.Object &&
            root.TryGetProperty("status", out _))
        {
            var status = RequiredString(root, "status", 128);
            if (status == "recent_auth_required")
            {
                RequireObjectKeys(root, [
                    "status",
                    "correlation_id",
                ]);
                return new RemoteStoreGiftClaimPersistentRevealResult(
                    status,
                    RequiredString(
                        root,
                        "correlation_id",
                        128));
            }

            if (status == "claim_code_not_found" &&
                root.EnumerateObject().Count() == 2 &&
                root.TryGetProperty("correlation_id", out _))
            {
                RequireObjectKeys(root, [
                    "status",
                    "correlation_id",
                ]);
                return new RemoteStoreGiftClaimPersistentRevealResult(
                    status,
                    RequiredString(
                        root,
                        "correlation_id",
                        128));
            }

            RequireObjectKeys(root, ["status"]);
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
                    "Gift Claim Code reveal terminal status drifted.");
            }

            return new RemoteStoreGiftClaimPersistentRevealResult(
                status,
                correlationId);
        }

        RequireObjectKeys(root, ["error"]);
        var error = RequiredString(root, "error", 128);
        var normalized = error switch
        {
            "LEGAL_REACCEPTANCE_REQUIRED" =>
                "legal_reacceptance_required",
            "RATE_LIMITED" => "rate_limited",
            "CLAIM_CODE_UNAVAILABLE" =>
                "claim_code_unavailable",
            "INVALID_INPUT" => "invalid_input",
            "FORBIDDEN" or "ACCOUNT_ROLE_FORBIDDEN" =>
                "account_forbidden",
            "ACCOUNT_NOT_FOUND" => "account_not_found",
            _ => throw new InvalidDataException(
                "Gift Claim Code reveal error code drifted."),
        };

        return new RemoteStoreGiftClaimPersistentRevealResult(
            normalized,
            correlationId,
            ErrorCode: error,
            Retryable:
                response.StatusCode == (HttpStatusCode)429 ||
                response.StatusCode ==
                    HttpStatusCode.ServiceUnavailable);
    }

    private async Task<HttpResponseMessage> SendListAsync(
        string accessToken,
        string correlationId,
        CancellationToken cancellationToken)
    {
        Exception? lastError = null;

        for (var attempt = 0; attempt <= 2; attempt++)
        {
            using var request = new HttpRequestMessage(
                HttpMethod.Post,
                new Uri(
                    _platformBaseUri,
                    "/api/agent-sessions/store/gift-claim-codes"));
            request.Headers.Accept.Add(
                new MediaTypeWithQualityHeaderValue(
                    "application/json"));
            request.Headers.UserAgent.ParseAdd(
                "bke-licensing-agent");
            request.Headers.Authorization =
                new AuthenticationHeaderValue(
                    "Bearer",
                    accessToken);
            request.Headers.TryAddWithoutValidation(
                "x-bke-account-session-version",
                AccountSessionRemote.ProtocolVersion);
            request.Headers.TryAddWithoutValidation(
                "x-request-id",
                correlationId);
            request.Content = new StringContent(
                JsonSerializer.Serialize(new
                {
                    correlation_id = correlationId,
                }),
                Encoding.UTF8,
                "application/json");

            try
            {
                var response = await _http.SendAsync(
                    request,
                    HttpCompletionOption.ResponseHeadersRead,
                    cancellationToken);

                if ((int)response.StatusCode is >= 300 and <= 399)
                {
                    response.Dispose();
                    throw new InvalidDataException(
                        "BKE Gift Claim Code list endpoint redirected.");
                }

                if (RetryableListStatuses.Contains(
                        response.StatusCode) &&
                    attempt < 2)
                {
                    response.Dispose();
                    await Task.Delay(
                        TimeSpan.FromSeconds(
                            0.25 * Math.Pow(2, attempt)),
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
            catch (Exception error) when (
                attempt < 2 &&
                error is HttpRequestException or TaskCanceledException)
            {
                lastError = error;
                await Task.Delay(
                    TimeSpan.FromSeconds(
                        0.25 * Math.Pow(2, attempt)),
                    cancellationToken);
            }
            catch (Exception error)
            {
                lastError = error;
                break;
            }
        }

        throw new HttpRequestException(
            "BKE Gift Claim Code list request failed.",
            lastError);
    }

    private static StoreGiftClaimItem ParseClaim(
        JsonElement item)
    {
        RequireObjectKeys(item, [
            "gift_claim_handle",
            "order_number",
            "product_name",
            "edition_name",
            "plan_name",
            "last_four",
            "status",
            "created_at",
            "expires_at",
        ]);

        var handle =
            RequiredString(item, "gift_claim_handle", 128);
        if (!ValidGiftClaimHandle(handle))
        {
            throw new InvalidDataException(
                "Gift Claim Code list returned an invalid handle.");
        }

        var status = RequiredString(item, "status", 32);
        if (status is not (
            "AVAILABLE" or "CLAIMED" or
            "REVOKED" or "EXPIRED"))
        {
            throw new InvalidDataException(
                "Gift Claim Code status drifted.");
        }

        return new StoreGiftClaimItem(
            handle,
            RequiredString(item, "order_number", 256),
            RequiredString(item, "product_name", 256),
            OptionalString(item, "edition_name", 256),
            OptionalString(item, "plan_name", 256),
            RequiredString(item, "last_four", 16),
            status,
            RequiredTimestamp(item, "created_at"),
            OptionalTimestamp(item, "expires_at"));
    }

    private static async Task<JsonDocument> ReadJsonAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        await using var stream =
            await response.Content.ReadAsStreamAsync(
                cancellationToken);
        return await JsonDocument.ParseAsync(
            stream,
            new JsonDocumentOptions { MaxDepth = 12 },
            cancellationToken);
    }

    private static void EnsureProtocol(
        HttpResponseMessage response)
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

    private static string? OptionalString(
        JsonElement root,
        string name,
        int maximumLength)
    {
        if (!root.TryGetProperty(name, out var value))
        {
            throw new InvalidDataException(
                $"Missing {name}.");
        }

        if (value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        if (value.ValueKind != JsonValueKind.String ||
            string.IsNullOrWhiteSpace(value.GetString()) ||
            value.GetString()!.Length > maximumLength)
        {
            throw new InvalidDataException(
                $"Invalid {name}.");
        }

        return value.GetString();
    }

    private static string RequiredUpperToken(
        JsonElement root,
        string name,
        int maximumLength)
    {
        var value = RequiredString(
            root,
            name,
            maximumLength);
        if (value.Any(character =>
            !(character is >= 'A' and <= 'Z' ||
              character == '_')))
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
        var value = RequiredString(root, name, 128);
        if (!DateTimeOffset.TryParse(value, out _))
        {
            throw new InvalidDataException(
                $"Invalid {name}.");
        }
        return value;
    }

    private static string? OptionalTimestamp(
        JsonElement root,
        string name)
    {
        var value = OptionalString(root, name, 128);
        if (value is not null &&
            !DateTimeOffset.TryParse(value, out _))
        {
            throw new InvalidDataException(
                $"Invalid {name}.");
        }
        return value;
    }

    private static string RequiredClaimCode(
        JsonElement root,
        string name)
    {
        var value = RequiredString(root, name, 128);
        if (!value.StartsWith(
                "BKE-CLM-",
                StringComparison.OrdinalIgnoreCase) ||
            value.Length != 43)
        {
            throw new InvalidDataException(
                "Invalid Claim Code.");
        }
        return value;
    }

    private static bool ValidGiftClaimHandle(
        string? value)
    {
        const string prefix = "bke-gift-claim-v1_";
        if (string.IsNullOrWhiteSpace(value) ||
            !value.StartsWith(
                prefix,
                StringComparison.Ordinal) ||
            value.Length != prefix.Length + 64)
        {
            return false;
        }

        return value[prefix.Length..].All(character =>
            character is >= '0' and <= '9' ||
            character is >= 'a' and <= 'f');
    }

    private static void ValidateAccessToken(
        string accessToken)
    {
        if (string.IsNullOrWhiteSpace(accessToken) ||
            accessToken.Length > 8192)
        {
            throw new InvalidDataException(
                "Invalid Agent access token.");
        }
    }

    private static void ValidateCorrelationId(
        string correlationId)
    {
        if (string.IsNullOrWhiteSpace(correlationId) ||
            correlationId.Length > 128)
        {
            throw new InvalidDataException(
                "Invalid correlation identifier.");
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
