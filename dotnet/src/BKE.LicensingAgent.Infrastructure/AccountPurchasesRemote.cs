using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Infrastructure;

public sealed class AccountPurchasesRemote :
    IAccountPurchasesRemote,
    IDisposable
{
    private const string Endpoint =
        "/api/agent-sessions/account/purchases";
    private const int MaximumItems = 50;
    private const int MaximumOrderItems = 100;

    private readonly Uri _platformBaseUri;
    private readonly HttpClient _http;
    private readonly bool _ownsHttpClient;

    public AccountPurchasesRemote(
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
                "Account purchases authority requires HTTPS outside isolated loopback certification.");
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

    public async Task<RemoteAccountPurchasesResult> GetAsync(
        string accessToken,
        CancellationToken cancellationToken)
    {
        if (!ValidSecret(accessToken, 8192))
        {
            return new RemoteAccountPurchasesResult(
                "invalid_input",
                ErrorCode: "INVALID_INPUT");
        }

        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            new Uri(_platformBaseUri, Endpoint));
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
            Guid.NewGuid().ToString("N"));

        using var response = await _http.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);

        if ((int)response.StatusCode is >= 300 and <= 399)
        {
            throw new HttpRequestException(
                "BKE account purchases authority redirected.");
        }

        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return new RemoteAccountPurchasesResult(
                "purchases_unavailable",
                ErrorCode: "ACCOUNT_PURCHASES_UNAVAILABLE",
                Retryable: true);
        }

        EnsureProtocol(response);
        using var document = await ReadJsonAsync(
            response,
            cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            return ErrorResult(
                response.StatusCode,
                document.RootElement);
        }

        var root = document.RootElement;
        if (RequiredString(root, "status") != "ready")
        {
            throw new InvalidDataException(
                "Account purchases response drifted.");
        }

        var accountRoot = RequiredObject(root, "account");
        var account = new AccountPurchasesAccount(
            RequiredAccountType(accountRoot, "type"),
            RequiredBoundedString(
                accountRoot,
                "display_name",
                1,
                120),
            RequiredStatus(accountRoot, "lifecycle_state"),
            RequiredRole(accountRoot, "role"));

        var permissionsRoot =
            RequiredObject(root, "permissions");
        var permissions = new AccountPurchasesPermissions(
            RequiredBoolean(
                permissionsRoot,
                "view_orders"),
            RequiredBoolean(
                permissionsRoot,
                "view_subscriptions"),
            RequiredBoolean(
                permissionsRoot,
                "view_all_licenses"),
            RequiredBoolean(
                permissionsRoot,
                "manage_license_seats"),
            RequiredBoolean(
                permissionsRoot,
                "manage_devices"),
            RequiredBoolean(
                permissionsRoot,
                "continue_pending_orders"),
            RequiredBoolean(
                permissionsRoot,
                "cancel_pending_orders"));

        var licenses = RequiredLicenses(root);
        var subscriptions = RequiredSubscriptions(root);
        var orders = RequiredOrders(root, permissions);

        return new RemoteAccountPurchasesResult(
            "ready",
            account,
            permissions,
            licenses,
            subscriptions,
            orders);
    }

    private static RemoteAccountPurchasesResult ErrorResult(
        HttpStatusCode statusCode,
        JsonElement root)
    {
        var error = OptionalString(root, "error") ??
            "ACCOUNT_PURCHASES_UNAVAILABLE";

        if (statusCode == HttpStatusCode.Unauthorized &&
            error == "INVALID_TOKEN")
        {
            throw new UnauthorizedAccessException(
                "BKE account session was rejected by purchases authority.");
        }

        var normalized = error switch
        {
            "ACCOUNT_FORBIDDEN" => "account_forbidden",
            "RATE_LIMITED" => "rate_limited",
            "ACCOUNT_PURCHASES_UNAVAILABLE" =>
                "purchases_unavailable",
            _ => error.ToLowerInvariant(),
        };

        return new RemoteAccountPurchasesResult(
            normalized,
            ErrorCode: error,
            Retryable:
                (int)statusCode == 429 ||
                statusCode == HttpStatusCode.ServiceUnavailable);
    }

    private static void EnsureProtocol(
        HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues(
                "x-bke-account-session-version",
                out var values))
        {
            throw new InvalidDataException(
                "Account purchases response is missing its protocol version.");
        }

        var versions = values.ToArray();
        if (versions.Length != 1 ||
            versions[0] != AccountSessionRemote.ProtocolVersion)
        {
            throw new InvalidDataException(
                "Account purchases protocol version drifted.");
        }
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
            cancellationToken: cancellationToken);
    }

    private static IReadOnlyList<AccountPurchasesLicense>
        RequiredLicenses(JsonElement root)
    {
        var array = RequiredArray(root, "licenses");
        var items = array.EnumerateArray()
            .Select(item =>
            {
                RequireObjectItem(item, "licenses");
                var maxDevices =
                    RequiredNonNegativeInt(
                        item,
                        "max_devices");
                var activeDevices =
                    RequiredNonNegativeInt(
                        item,
                        "active_devices");
                if (activeDevices > maxDevices)
                {
                    throw new InvalidDataException(
                        "Active devices exceed licensed capacity.");
                }

                var maxSeats =
                    RequiredNonNegativeInt(
                        item,
                        "max_seats");
                var assignedSeats =
                    RequiredNonNegativeInt(
                        item,
                        "assigned_seats");
                if (assignedSeats > maxSeats)
                {
                    throw new InvalidDataException(
                        "Assigned seats exceed licensed capacity.");
                }

                return new AccountPurchasesLicense(
                    RequiredBoundedString(
                        item,
                        "product_name",
                        1,
                        200),
                    OptionalBoundedString(
                        item,
                        "edition_name",
                        120),
                    OptionalPlanType(item, "plan_type"),
                    RequiredStatus(item, "status"),
                    RequiredLastFour(
                        item,
                        "key_last_four"),
                    OptionalTimestamp(
                        item,
                        "expires_at"),
                    maxDevices,
                    activeDevices,
                    maxSeats,
                    assignedSeats,
                    OptionalLicenseSeatManagementHandle(
                        item,
                        "seat_management_handle"),
                    OptionalLicenseDeviceManagementHandle(
                        item,
                        "device_management_handle"));
            })
            .ToArray();

        if (items.Length > MaximumItems)
        {
            throw new InvalidDataException(
                "Account purchases license list is too large.");
        }

        return items;
    }

    private static IReadOnlyList<AccountPurchasesSubscription>
        RequiredSubscriptions(JsonElement root)
    {
        var array = RequiredArray(root, "subscriptions");
        var items = array.EnumerateArray()
            .Select(item =>
            {
                RequireObjectItem(item, "subscriptions");
                return new AccountPurchasesSubscription(
                RequiredBoundedString(
                    item,
                    "product_name",
                    1,
                    200),
                OptionalBoundedString(
                    item,
                    "edition_name",
                    120),
                OptionalPlanType(item, "plan_type"),
                RequiredStatus(item, "status"),
                RequiredPositiveInt(item, "seats"),
                RequiredTimestamp(
                    item,
                    "current_period_end"));
            })
            .ToArray();

        if (items.Length > MaximumItems)
        {
            throw new InvalidDataException(
                "Account purchases subscription list is too large.");
        }

        return items;
    }

    private static IReadOnlyList<AccountPurchasesOrder>
        RequiredOrders(
            JsonElement root,
            AccountPurchasesPermissions permissions)
    {
        var array = RequiredArray(root, "orders");
        var items = array.EnumerateArray()
            .Select(item =>
            {
                RequireObjectItem(item, "orders");
                var status = RequiredStatus(item, "status");
                var continueHandle =
                    OptionalOrderContinueHandle(
                        item,
                        "continue_handle");
                var cancelHandle =
                    OptionalOrderCancelHandle(
                        item,
                        "cancel_handle");

                if (status != "PENDING" &&
                    (continueHandle is not null ||
                     cancelHandle is not null))
                {
                    throw new InvalidDataException(
                        "Non-pending order exposed a management handle.");
                }

                if ((!permissions.ContinuePendingOrders &&
                     continueHandle is not null) ||
                    (!permissions.CancelPendingOrders &&
                     cancelHandle is not null))
                {
                    throw new InvalidDataException(
                        "Order management handle exceeded account permissions.");
                }

                if ((status == "PENDING" &&
                     permissions.ContinuePendingOrders &&
                     continueHandle is null) ||
                    (status == "PENDING" &&
                     permissions.CancelPendingOrders &&
                     cancelHandle is null))
                {
                    throw new InvalidDataException(
                        "Pending order management handle is missing.");
                }

                return new AccountPurchasesOrder(
                RequiredBoundedString(
                    item,
                    "number",
                    1,
                    120),
                status,
                RequiredNonNegativeInt(
                    item,
                    "total_minor"),
                RequiredCurrency(item, "currency"),
                RequiredTimestamp(item, "created_at"),
                RequiredBoolean(
                    item,
                    "invoice_available"),
                continueHandle,
                cancelHandle,
                RequiredOrderItems(item));
            })
            .ToArray();

        if (items.Length > MaximumItems)
        {
            throw new InvalidDataException(
                "Account purchases order list is too large.");
        }

        return items;
    }

    private static IReadOnlyList<AccountPurchasesOrderItem>
        RequiredOrderItems(JsonElement order)
    {
        var array = RequiredArray(order, "items");
        var items = array.EnumerateArray()
            .Select(item =>
            {
                RequireObjectItem(item, "order.items");
                return new AccountPurchasesOrderItem(
                RequiredBoundedString(
                    item,
                    "product_name",
                    1,
                    200),
                OptionalBoundedString(
                    item,
                    "edition_name",
                    120),
                OptionalBoundedString(
                    item,
                    "plan_name",
                    120));
            })
            .ToArray();

        if (items.Length > MaximumOrderItems)
        {
            throw new InvalidDataException(
                "Account purchases order item list is too large.");
        }

        return items;
    }

    private static void RequireObjectItem(
        JsonElement item,
        string name)
    {
        if (item.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException(
                $"Invalid {name} item.");
        }
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

    private static JsonElement RequiredArray(
        JsonElement root,
        string name)
    {
        if (!root.TryGetProperty(name, out var value) ||
            value.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException(
                $"Missing or invalid {name}.");
        }

        return value;
    }

    private static string RequiredAccountType(
        JsonElement root,
        string name)
    {
        var value = RequiredString(root, name);
        return value is "INDIVIDUAL" or "ORGANIZATION"
            ? value
            : throw new InvalidDataException(
                $"Invalid {name}.");
    }

    private static string RequiredRole(
        JsonElement root,
        string name)
    {
        var value = RequiredString(root, name);
        return value is "OWNER" or "BILLING" or
            "LICENSE_MANAGER" or "MEMBER"
            ? value
            : throw new InvalidDataException(
                $"Invalid {name}.");
    }

    private static string? OptionalPlanType(
        JsonElement root,
        string name)
    {
        var value = OptionalString(root, name);
        if (value is null)
        {
            return null;
        }

        return value is "PERPETUAL" or "MONTHLY" or "ANNUAL"
            ? value
            : throw new InvalidDataException(
                $"Invalid {name}.");
    }

    private static string RequiredStatus(
        JsonElement root,
        string name)
    {
        var value = RequiredString(root, name);
        if (value.Length > 64 ||
            value.Any(character =>
                character is not (>= 'A' and <= 'Z') &&
                character != '_'))
        {
            throw new InvalidDataException(
                $"Invalid {name}.");
        }

        return value;
    }

    private static string RequiredCurrency(
        JsonElement root,
        string name)
    {
        var value = RequiredString(root, name);
        if (value.Length != 3 ||
            value.Any(character =>
                character is not (>= 'A' and <= 'Z')))
        {
            throw new InvalidDataException(
                $"Invalid {name}.");
        }

        return value;
    }

    private static string RequiredLastFour(
        JsonElement root,
        string name)
    {
        var value = RequiredString(root, name);
        if (value.Length != 4 ||
            value.Any(character => character < 32))
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
        var value = RequiredString(root, name);
        if (!DateTimeOffset.TryParse(value, out _))
        {
            throw new InvalidDataException(
                $"Invalid {name} timestamp.");
        }

        return value;
    }

    private static string? OptionalTimestamp(
        JsonElement root,
        string name)
    {
        var value = OptionalString(root, name);
        if (value is null)
        {
            return null;
        }

        if (!DateTimeOffset.TryParse(value, out _))
        {
            throw new InvalidDataException(
                $"Invalid {name} timestamp.");
        }

        return value;
    }

    private static string RequiredBoundedString(
        JsonElement root,
        string name,
        int minimum,
        int maximum)
    {
        var value = RequiredString(root, name);
        if (value.Length < minimum ||
            value.Length > maximum ||
            value.Any(character => character < 32))
        {
            throw new InvalidDataException(
                $"Invalid {name}.");
        }

        return value;
    }

    private static string? OptionalBoundedString(
        JsonElement root,
        string name,
        int maximum)
    {
        var value = OptionalString(root, name);
        if (value is null)
        {
            return null;
        }

        if (value.Length > maximum ||
            value.Any(character => character < 32))
        {
            throw new InvalidDataException(
                $"Invalid {name}.");
        }

        return value;
    }

    private static string RequiredString(
        JsonElement root,
        string name)
    {
        if (!root.TryGetProperty(name, out var value) ||
            value.ValueKind != JsonValueKind.String ||
            string.IsNullOrWhiteSpace(value.GetString()))
        {
            throw new InvalidDataException(
                $"Missing or invalid {name}.");
        }

        return value.GetString()!;
    }

    private static string? OptionalString(
        JsonElement root,
        string name)
    {
        if (!root.TryGetProperty(name, out var value) ||
            value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        return value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : throw new InvalidDataException(
                $"Invalid {name}.");
    }

    private static string? OptionalOrderContinueHandle(
        JsonElement root,
        string name)
    {
        var value = OptionalString(root, name);
        if (value is null)
        {
            return null;
        }

        if (!System.Text.RegularExpressions.Regex.IsMatch(
                value,
                "^bke-order-continue-v1_[0-9a-f]{64}$",
                System.Text.RegularExpressions.RegexOptions.CultureInvariant))
        {
            throw new InvalidDataException(
                $"Invalid {name}.");
        }

        return value;
    }

    private static string? OptionalOrderCancelHandle(
        JsonElement root,
        string name)
    {
        var value = OptionalString(root, name);
        if (value is null)
        {
            return null;
        }

        if (!System.Text.RegularExpressions.Regex.IsMatch(
                value,
                "^bke-order-cancel-v1_[0-9a-f]{64}$",
                System.Text.RegularExpressions.RegexOptions.CultureInvariant))
        {
            throw new InvalidDataException(
                $"Invalid {name}.");
        }

        return value;
    }

    private static string? OptionalLicenseSeatManagementHandle(
        JsonElement root,
        string name)
    {
        var value = OptionalString(root, name);
        if (value is null)
        {
            return null;
        }

        if (!System.Text.RegularExpressions.Regex.IsMatch(
                value,
                "^bke-license-seat-v1_[0-9a-f]{64}$",
                System.Text.RegularExpressions.RegexOptions.CultureInvariant))
        {
            throw new InvalidDataException(
                $"Invalid {name}.");
        }

        return value;
    }

    private static string? OptionalLicenseDeviceManagementHandle(
        JsonElement root,
        string name)
    {
        var value = OptionalString(root, name);
        if (value is null)
        {
            return null;
        }

        if (!System.Text.RegularExpressions.Regex.IsMatch(
                value,
                "^bke-license-device-v1_[0-9a-f]{64}$",
                System.Text.RegularExpressions.RegexOptions.CultureInvariant))
        {
            throw new InvalidDataException(
                $"Invalid {name}.");
        }

        return value;
    }

    private static bool RequiredBoolean(
        JsonElement root,
        string name)
    {
        if (!root.TryGetProperty(name, out var value) ||
            value.ValueKind is not (
                JsonValueKind.True or
                JsonValueKind.False))
        {
            throw new InvalidDataException(
                $"Missing or invalid {name}.");
        }

        return value.GetBoolean();
    }

    private static int RequiredNonNegativeInt(
        JsonElement root,
        string name)
    {
        if (!root.TryGetProperty(name, out var value) ||
            !value.TryGetInt32(out var parsed) ||
            parsed < 0)
        {
            throw new InvalidDataException(
                $"Missing or invalid {name}.");
        }

        return parsed;
    }

    private static int RequiredPositiveInt(
        JsonElement root,
        string name)
    {
        var value = RequiredNonNegativeInt(root, name);
        if (value < 1)
        {
            throw new InvalidDataException(
                $"Invalid {name}.");
        }

        return value;
    }

    private static bool ValidSecret(
        string value,
        int maximum) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length <= maximum;

    public void Dispose()
    {
        if (_ownsHttpClient)
        {
            _http.Dispose();
        }
    }
}
