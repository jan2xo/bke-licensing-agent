using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Infrastructure;

public sealed class StoreCheckoutReviewRemote : IStoreCheckoutReviewRemote, IDisposable
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

    public StoreCheckoutReviewRemote(
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
                "Store checkout-review authority requires HTTPS outside isolated loopback certification.");
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

    public async Task<RemoteStoreCheckoutReviewResult> ReviewAsync(
        string accessToken,
        string purchasePlanId,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(accessToken) || accessToken.Length > 8192)
        {
            throw new InvalidDataException("Invalid Agent access token.");
        }

        if (string.IsNullOrWhiteSpace(purchasePlanId) ||
            purchasePlanId.Length > 256)
        {
            throw new InvalidDataException("Invalid purchase plan identifier.");
        }

        using var response = await SendAsync(
            accessToken,
            purchasePlanId,
            cancellationToken);

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var document = await JsonDocument.ParseAsync(
            stream,
            new JsonDocumentOptions { MaxDepth = 16 },
            cancellationToken);
        var root = document.RootElement;

        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            RequireObjectKeys(root, ["error"]);
            if (RequiredString(root, "error", 64) != "INVALID_TOKEN")
            {
                throw new InvalidDataException(
                    "Purchase-review authentication response drifted.");
            }

            throw new UnauthorizedAccessException(
                "BKE account session was rejected by purchase-review authority.");
        }

        EnsureProtocol(response);

        if (response.StatusCode == (HttpStatusCode)429)
        {
            RequireObjectKeys(root, ["error"]);
            if (RequiredString(root, "error", 64) != "RATE_LIMITED")
            {
                throw new InvalidDataException(
                    "Purchase-review rate-limit response drifted.");
            }

            return Empty("rate_limited");
        }

        var status = RequiredString(root, "status", 64);
        return status switch
        {
            "ready" => ParseReady(response, root),
            "legal_reacceptance_required" =>
                ParseLegalReacceptance(response, root),
            "plan_not_available" when
                response.StatusCode is HttpStatusCode.NotFound or
                HttpStatusCode.UnprocessableEntity =>
                ParseSimple(root, status),
            "account_forbidden" when
                response.StatusCode == HttpStatusCode.Forbidden =>
                ParseSimple(root, status),
            "account_not_found" or "account_not_active" when
                response.StatusCode == HttpStatusCode.Conflict =>
                ParseSimple(root, status),
            "legal_acceptance_required" when
                response.StatusCode == HttpStatusCode.Conflict =>
                ParseSimple(root, status),
            "identity_unavailable" or
            "account_unavailable" or
            "legal_unavailable" or
            "commerce_unavailable" or
            "catalog_unavailable" when
                response.StatusCode == HttpStatusCode.ServiceUnavailable =>
                ParseSimple(root, status),
            _ => throw new InvalidDataException(
                "Purchase-review authority returned an invalid response."),
        };
    }

    private async Task<HttpResponseMessage> SendAsync(
        string accessToken,
        string purchasePlanId,
        CancellationToken cancellationToken)
    {
        Exception? lastError = null;

        for (var attempt = 0; attempt <= 2; attempt++)
        {
            var encodedPlan = Uri.EscapeDataString(purchasePlanId);
            using var request = new HttpRequestMessage(
                HttpMethod.Get,
                new Uri(
                    _platformBaseUri,
                    $"/api/agent-sessions/store/checkout-review?purchase_plan_id={encodedPlan}"));
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
                        "BKE Store checkout-review endpoint redirected.");
                }

                if (RetryableStatuses.Contains(response.StatusCode) &&
                    attempt < 2)
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
            "BKE Store checkout-review request failed.",
            lastError);
    }

    private static RemoteStoreCheckoutReviewResult ParseReady(
        HttpResponseMessage response,
        JsonElement root)
    {
        if (response.StatusCode != HttpStatusCode.OK)
        {
            throw new InvalidDataException(
                "Purchase-review success status code drifted.");
        }

        RequireObjectKeys(root, [
            "status",
            "purchase_modes",
            "product",
            "edition",
            "plan",
            "legal_documents",
        ]);

        var purchaseModes = ParsePurchaseModes(root);
        var product = ParseProduct(RequiredObject(root, "product"));
        var edition = ParseEdition(RequiredObject(root, "edition"));
        var plan = ParsePlan(RequiredObject(root, "plan"));
        var legalDocuments = ParseLegalDocuments(root);

        return new RemoteStoreCheckoutReviewResult(
            "ready",
            purchaseModes,
            product,
            edition,
            plan,
            legalDocuments,
            []);
    }

    private static RemoteStoreCheckoutReviewResult ParseLegalReacceptance(
        HttpResponseMessage response,
        JsonElement root)
    {
        if (response.StatusCode != HttpStatusCode.Conflict)
        {
            throw new InvalidDataException(
                "Legal reacceptance status code drifted.");
        }

        RequireObjectKeys(root, ["status", "pending_legal"]);
        if (!root.TryGetProperty("pending_legal", out var pending) ||
            pending.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException(
                "Purchase-review pending Legal documents are invalid.");
        }

        var result = new List<StoreCheckoutReviewPendingLegalDocument>();
        foreach (var item in pending.EnumerateArray())
        {
            if (result.Count >= 64)
            {
                throw new InvalidDataException(
                    "Purchase-review pending Legal document count is invalid.");
            }

            RequireObjectKeys(item, [
                "document_type",
                "title",
                "slug",
                "document_version_id",
                "version",
            ]);
            result.Add(new StoreCheckoutReviewPendingLegalDocument(
                RequiredString(item, "document_type", 128),
                RequiredString(item, "title", 512),
                RequiredString(item, "slug", 256),
                RequiredString(item, "document_version_id", 256),
                RequiredString(item, "version", 128)));
        }

        if (result.Count == 0)
        {
            throw new InvalidDataException(
                "Purchase-review Legal reacceptance omitted pending documents.");
        }

        return new RemoteStoreCheckoutReviewResult(
            "legal_reacceptance_required",
            [],
            null,
            null,
            null,
            [],
            result);
    }

    private static RemoteStoreCheckoutReviewResult ParseSimple(
        JsonElement root,
        string status)
    {
        RequireObjectKeys(root, ["status"]);
        return Empty(status);
    }

    private static RemoteStoreCheckoutReviewResult Empty(string status) =>
        new(
            status,
            [],
            null,
            null,
            null,
            [],
            []);

    private static IReadOnlyList<string> ParsePurchaseModes(JsonElement root)
    {
        if (!root.TryGetProperty("purchase_modes", out var modes) ||
            modes.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException(
                "Purchase-review purchase modes are invalid.");
        }

        var result = new List<string>();
        foreach (var mode in modes.EnumerateArray())
        {
            if (result.Count >= 2 ||
                mode.ValueKind != JsonValueKind.String)
            {
                throw new InvalidDataException(
                    "Purchase-review purchase mode is invalid.");
            }

            var value = mode.GetString();
            if (value is not ("SELF" or "GIFT") ||
                result.Contains(value, StringComparer.Ordinal))
            {
                throw new InvalidDataException(
                    "Purchase-review purchase mode drifted.");
            }

            result.Add(value);
        }

        if (result.Count == 0 ||
            !result.Contains("SELF", StringComparer.Ordinal))
        {
            throw new InvalidDataException(
                "Purchase-review SELF mode is missing.");
        }

        return result;
    }

    private static StoreCheckoutReviewProduct ParseProduct(JsonElement item)
    {
        RequireObjectKeys(item, [
            "product_id",
            "slug",
            "display_name",
            "summary",
        ]);

        return new StoreCheckoutReviewProduct(
            RequiredString(item, "product_id", 128),
            RequiredString(item, "slug", 256),
            RequiredString(item, "display_name", 256),
            RequiredString(item, "summary", 4096));
    }

    private static StoreCheckoutReviewEdition ParseEdition(JsonElement item)
    {
        RequireObjectKeys(item, [
            "edition_id",
            "slug",
            "name",
            "max_users",
            "max_devices_per_user",
            "update_policy",
        ]);

        return new StoreCheckoutReviewEdition(
            RequiredString(item, "edition_id", 256),
            RequiredString(item, "slug", 256),
            RequiredString(item, "name", 256),
            RequiredPositiveInt(item, "max_users"),
            RequiredPositiveInt(item, "max_devices_per_user"),
            RequiredString(item, "update_policy", 64));
    }

    private static StoreCatalogPlan ParsePlan(JsonElement item)
    {
        RequireObjectKeys(item, [
            "purchase_plan_id",
            "type",
            "currency",
            "amount_minor",
            "billing_type",
            "interval_unit",
            "interval_count",
            "renewal_behavior",
            "savings_minor",
            "effective_monthly_minor",
        ]);

        var type = RequiredString(item, "type", 32);
        if (type is not ("PERPETUAL" or "MONTHLY" or "ANNUAL"))
        {
            throw new InvalidDataException(
                "Purchase-review plan type drifted.");
        }

        var billingType = RequiredString(item, "billing_type", 32);
        if (billingType is not ("ONE_TIME" or "SUBSCRIPTION"))
        {
            throw new InvalidDataException(
                "Purchase-review billing type drifted.");
        }

        var intervalUnit = OptionalString(item, "interval_unit", 16);
        if (intervalUnit is not null &&
            intervalUnit is not ("MONTH" or "YEAR"))
        {
            throw new InvalidDataException(
                "Purchase-review interval unit drifted.");
        }

        var intervalCount = OptionalPositiveInt(item, "interval_count");
        if (billingType == "ONE_TIME" &&
            (intervalUnit is not null || intervalCount is not null))
        {
            throw new InvalidDataException(
                "Purchase-review one-time plan exposed a billing interval.");
        }

        if (billingType == "SUBSCRIPTION" &&
            (intervalUnit is null || intervalCount is null))
        {
            throw new InvalidDataException(
                "Purchase-review subscription plan omitted its billing interval.");
        }

        var renewalBehavior = RequiredString(
            item,
            "renewal_behavior",
            32);
        if (renewalBehavior is not ("NONE" or "CUSTOMER_AUTHORIZED"))
        {
            throw new InvalidDataException(
                "Purchase-review renewal behavior drifted.");
        }

        var currency = RequiredString(item, "currency", 3);
        if (currency.Length != 3 ||
            currency.Any(character => character is < 'A' or > 'Z'))
        {
            throw new InvalidDataException(
                "Purchase-review currency is invalid.");
        }

        return new StoreCatalogPlan(
            RequiredString(item, "purchase_plan_id", 256),
            type,
            currency,
            RequiredPositiveLong(item, "amount_minor"),
            billingType,
            intervalUnit,
            intervalCount,
            renewalBehavior,
            RequiredNonNegativeLong(item, "savings_minor"),
            OptionalPositiveLong(item, "effective_monthly_minor"));
    }

    private static IReadOnlyList<StoreCheckoutReviewLegalDocument> ParseLegalDocuments(
        JsonElement root)
    {
        if (!root.TryGetProperty("legal_documents", out var documents) ||
            documents.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException(
                "Purchase-review Legal documents are invalid.");
        }

        var result = new List<StoreCheckoutReviewLegalDocument>();
        foreach (var item in documents.EnumerateArray())
        {
            if (result.Count >= 64)
            {
                throw new InvalidDataException(
                    "Purchase-review Legal document count is invalid.");
            }

            RequireObjectKeys(item, [
                "document_type",
                "title",
                "slug",
                "document_version_id",
                "version",
                "sla_version",
                "requires_reacceptance",
            ]);

            result.Add(new StoreCheckoutReviewLegalDocument(
                RequiredString(item, "document_type", 128),
                RequiredString(item, "title", 512),
                RequiredString(item, "slug", 256),
                RequiredString(item, "document_version_id", 256),
                RequiredString(item, "version", 128),
                OptionalString(item, "sla_version", 128),
                RequiredBoolean(item, "requires_reacceptance")));
        }

        return result;
    }

    private static JsonElement RequiredObject(
        JsonElement root,
        string name)
    {
        if (!root.TryGetProperty(name, out var value) ||
            value.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException(
                $"Missing or invalid {name}.");
        }

        return value;
    }

    private static void EnsureProtocol(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues(
                "x-bke-account-session-version",
                out var values))
        {
            throw new InvalidDataException(
                "Purchase-review response is missing its protocol version.");
        }

        var versions = values.ToArray();
        if (versions.Length != 1 ||
            versions[0] != AccountSessionRemote.ProtocolVersion)
        {
            throw new InvalidDataException(
                "Purchase-review protocol version drifted.");
        }
    }

    private static void RequireObjectKeys(
        JsonElement item,
        IReadOnlyCollection<string> expected)
    {
        if (item.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException(
                "Purchase-review response shape is invalid.");
        }

        var keys = item.EnumerateObject()
            .Select(property => property.Name)
            .ToHashSet(StringComparer.Ordinal);
        if (!keys.SetEquals(expected))
        {
            throw new InvalidDataException(
                "Purchase-review response shape drifted.");
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

    private static int RequiredPositiveInt(
        JsonElement root,
        string name)
    {
        if (!root.TryGetProperty(name, out var value) ||
            !value.TryGetInt32(out var result) ||
            result <= 0)
        {
            throw new InvalidDataException(
                $"Missing or invalid {name}.");
        }

        return result;
    }

    private static int? OptionalPositiveInt(
        JsonElement root,
        string name)
    {
        if (!root.TryGetProperty(name, out var value))
        {
            throw new InvalidDataException($"Missing {name}.");
        }

        if (value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        if (!value.TryGetInt32(out var result) || result <= 0)
        {
            throw new InvalidDataException($"Invalid {name}.");
        }

        return result;
    }

    private static long RequiredPositiveLong(
        JsonElement root,
        string name)
    {
        if (!root.TryGetProperty(name, out var value) ||
            !value.TryGetInt64(out var result) ||
            result <= 0)
        {
            throw new InvalidDataException(
                $"Missing or invalid {name}.");
        }

        return result;
    }

    private static long RequiredNonNegativeLong(
        JsonElement root,
        string name)
    {
        if (!root.TryGetProperty(name, out var value) ||
            !value.TryGetInt64(out var result) ||
            result < 0)
        {
            throw new InvalidDataException(
                $"Missing or invalid {name}.");
        }

        return result;
    }

    private static long? OptionalPositiveLong(
        JsonElement root,
        string name)
    {
        if (!root.TryGetProperty(name, out var value))
        {
            throw new InvalidDataException($"Missing {name}.");
        }

        if (value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        if (!value.TryGetInt64(out var result) || result <= 0)
        {
            throw new InvalidDataException($"Invalid {name}.");
        }

        return result;
    }

    public void Dispose()
    {
        if (_ownsHttpClient)
        {
            _http.Dispose();
        }
    }
}
