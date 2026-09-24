using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Infrastructure;

public sealed class StoreCatalogRemote : IStoreCatalogRemote, IDisposable
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

    public StoreCatalogRemote(
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
                "Store catalog authority requires HTTPS outside isolated loopback certification.");
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

    public async Task<RemoteStoreCatalogSnapshot> GetAsync(
        string accessToken,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(accessToken) || accessToken.Length > 8192)
        {
            throw new InvalidDataException("Invalid Agent access token.");
        }

        using var response = await SendAsync(accessToken, cancellationToken);
        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            throw new UnauthorizedAccessException(
                "BKE account session was rejected by the Store authority.");
        }

        EnsureSuccess(response);
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var document = await JsonDocument.ParseAsync(
            stream,
            cancellationToken: cancellationToken);
        return Parse(document.RootElement);
    }

    private async Task<HttpResponseMessage> SendAsync(
        string accessToken,
        CancellationToken cancellationToken)
    {
        Exception? lastError = null;

        for (var attempt = 0; attempt <= 2; attempt++)
        {
            using var request = new HttpRequestMessage(
                HttpMethod.Get,
                new Uri(_platformBaseUri, "/api/agent-sessions/store"));
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
                        "BKE Store endpoint redirected.");
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
            "BKE Store request failed.",
            lastError);
    }

    private static void EnsureSuccess(HttpResponseMessage response)
    {
        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException(
                $"BKE Store authority returned {(int)response.StatusCode}.",
                null,
                response.StatusCode);
        }

        if (!response.Headers.TryGetValues(
                "x-bke-account-session-version",
                out var values))
        {
            throw new InvalidDataException(
                "BKE Store response is missing its protocol version.");
        }

        var versions = values.ToArray();
        if (versions.Length != 1 ||
            versions[0] != AccountSessionRemote.ProtocolVersion)
        {
            throw new InvalidDataException(
                "BKE Store protocol version drifted.");
        }
    }

    private static RemoteStoreCatalogSnapshot Parse(JsonElement root)
    {
        RequireObjectKeys(root, [
            "status",
            "account_id",
            "gift_checkout_enabled",
            "products",
        ]);

        if (RequiredString(root, "status", 32) != "ok")
        {
            throw new InvalidDataException("BKE Store status drifted.");
        }

        _ = RequiredString(root, "account_id", 256);
        var giftCheckoutEnabled = RequiredBoolean(
            root,
            "gift_checkout_enabled");

        if (!root.TryGetProperty("products", out var products) ||
            products.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException(
                "BKE Store products are invalid.");
        }

        var result = new List<StoreCatalogProduct>();
        foreach (var product in products.EnumerateArray())
        {
            if (result.Count >= 500)
            {
                throw new InvalidDataException(
                    "BKE Store product count is invalid.");
            }
            result.Add(ParseProduct(product));
        }

        return new RemoteStoreCatalogSnapshot(
            giftCheckoutEnabled,
            result);
    }

    private static StoreCatalogProduct ParseProduct(JsonElement item)
    {
        RequireObjectKeys(item, [
            "product_id",
            "slug",
            "display_name",
            "summary",
            "description",
            "product_type",
            "execution_type",
            "editions",
        ]);

        var executionType = OptionalString(
            item,
            "execution_type",
            32);
        if (executionType is not null &&
            executionType is not ("LAUNCHER_PLUGIN" or "STANDALONE"))
        {
            throw new InvalidDataException(
                "BKE Store execution type drifted.");
        }

        if (!item.TryGetProperty("editions", out var editions) ||
            editions.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException(
                "BKE Store editions are invalid.");
        }

        var parsedEditions = new List<StoreCatalogEdition>();
        foreach (var edition in editions.EnumerateArray())
        {
            if (parsedEditions.Count >= 50)
            {
                throw new InvalidDataException(
                    "BKE Store edition count is invalid.");
            }
            parsedEditions.Add(ParseEdition(edition));
        }

        if (parsedEditions.Count == 0)
        {
            throw new InvalidDataException(
                "BKE Store product has no purchasable editions.");
        }

        return new StoreCatalogProduct(
            RequiredString(item, "product_id", 128),
            RequiredString(item, "slug", 256),
            RequiredString(item, "display_name", 256),
            RequiredString(item, "summary", 4096),
            RequiredString(item, "description", 16_384),
            RequiredString(item, "product_type", 64),
            executionType,
            parsedEditions);
    }

    private static StoreCatalogEdition ParseEdition(JsonElement item)
    {
        RequireObjectKeys(item, [
            "edition_id",
            "slug",
            "name",
            "description",
            "features",
            "max_users",
            "max_devices_per_user",
            "update_policy",
            "plans",
        ]);

        if (!item.TryGetProperty("features", out var features) ||
            features.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException(
                "BKE Store edition features are invalid.");
        }

        var parsedFeatures = new List<string>();
        foreach (var feature in features.EnumerateArray())
        {
            if (parsedFeatures.Count >= 256 ||
                feature.ValueKind != JsonValueKind.String ||
                string.IsNullOrWhiteSpace(feature.GetString()) ||
                feature.GetString()!.Length > 1024)
            {
                throw new InvalidDataException(
                    "BKE Store edition feature is invalid.");
            }
            parsedFeatures.Add(feature.GetString()!);
        }

        if (!item.TryGetProperty("plans", out var plans) ||
            plans.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException(
                "BKE Store plans are invalid.");
        }

        var parsedPlans = new List<StoreCatalogPlan>();
        foreach (var plan in plans.EnumerateArray())
        {
            if (parsedPlans.Count >= 10)
            {
                throw new InvalidDataException(
                    "BKE Store plan count is invalid.");
            }
            parsedPlans.Add(ParsePlan(plan));
        }

        if (parsedPlans.Count == 0)
        {
            throw new InvalidDataException(
                "BKE Store edition has no purchasable plans.");
        }

        return new StoreCatalogEdition(
            RequiredString(item, "edition_id", 256),
            RequiredString(item, "slug", 256),
            RequiredString(item, "name", 256),
            OptionalString(item, "description", 4096),
            parsedFeatures,
            RequiredPositiveInt(item, "max_users"),
            RequiredPositiveInt(item, "max_devices_per_user"),
            RequiredString(item, "update_policy", 64),
            parsedPlans);
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
                "BKE Store plan type drifted.");
        }

        var billingType = RequiredString(
            item,
            "billing_type",
            32);
        if (billingType is not ("ONE_TIME" or "SUBSCRIPTION"))
        {
            throw new InvalidDataException(
                "BKE Store billing type drifted.");
        }

        var intervalUnit = OptionalString(
            item,
            "interval_unit",
            16);
        if (intervalUnit is not null &&
            intervalUnit is not ("MONTH" or "YEAR"))
        {
            throw new InvalidDataException(
                "BKE Store interval unit drifted.");
        }

        var intervalCount = OptionalPositiveInt(
            item,
            "interval_count");
        if (billingType == "ONE_TIME" &&
            (intervalUnit is not null || intervalCount is not null))
        {
            throw new InvalidDataException(
                "BKE Store one-time plan exposed a billing interval.");
        }
        if (billingType == "SUBSCRIPTION" &&
            (intervalUnit is null || intervalCount is null))
        {
            throw new InvalidDataException(
                "BKE Store subscription plan omitted its billing interval.");
        }

        var renewalBehavior = RequiredString(
            item,
            "renewal_behavior",
            32);
        if (renewalBehavior is not ("NONE" or "CUSTOMER_AUTHORIZED"))
        {
            throw new InvalidDataException(
                "BKE Store renewal behavior drifted.");
        }

        var currency = RequiredString(item, "currency", 3);
        if (currency.Length != 3 ||
            currency.Any(character => character is < 'A' or > 'Z'))
        {
            throw new InvalidDataException(
                "BKE Store currency is invalid.");
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

    private static void RequireObjectKeys(
        JsonElement item,
        IReadOnlyCollection<string> expected)
    {
        if (item.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException(
                "BKE Store response shape is invalid.");
        }

        var keys = item.EnumerateObject()
            .Select(property => property.Name)
            .ToHashSet(StringComparer.Ordinal);
        if (!keys.SetEquals(expected))
        {
            throw new InvalidDataException(
                "BKE Store response shape drifted.");
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
