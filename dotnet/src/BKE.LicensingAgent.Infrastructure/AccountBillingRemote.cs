using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Infrastructure;

public sealed class AccountBillingRemote :
    IAccountBillingRemote,
    IDisposable
{
    private const string Endpoint =
        "/api/agent-sessions/account/billing";
    private const int MaximumItems = 50;
    private const int MaximumInvoiceLines = 100;

    private readonly Uri _platformBaseUri;
    private readonly HttpClient _http;
    private readonly bool _ownsHttpClient;

    public AccountBillingRemote(
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
                "Account billing authority requires HTTPS outside isolated loopback certification.");
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

    public async Task<RemoteAccountBillingResult> GetAsync(
        string accessToken,
        CancellationToken cancellationToken)
    {
        if (!ValidSecret(accessToken, 8192))
        {
            return new RemoteAccountBillingResult(
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
                "BKE account billing authority redirected.");
        }

        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return new RemoteAccountBillingResult(
                "billing_unavailable",
                ErrorCode: "ACCOUNT_BILLING_UNAVAILABLE",
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
                "Account billing response drifted.");
        }

        var accountRoot = RequiredObject(root, "account");
        var account = new AccountBillingAccount(
            RequiredAccountType(accountRoot, "type"),
            RequiredBoundedString(
                accountRoot,
                "display_name",
                1,
                120),
            RequiredBoundedString(
                accountRoot,
                "lifecycle_state",
                1,
                40),
            RequiredRole(accountRoot, "role"));

        var permissionsRoot =
            RequiredObject(root, "permissions");
        var permissions = new AccountBillingPermissions(
            RequiredBoolean(
                permissionsRoot,
                "view_invoices"),
            RequiredBoolean(
                permissionsRoot,
                "view_payments"));

        var invoices = RequiredInvoices(root);
        var payments = RequiredPayments(root);

        if (!permissions.ViewInvoices &&
            invoices.Count != 0)
        {
            throw new InvalidDataException(
                "Billing response exposed invoices without permission.");
        }

        if (!permissions.ViewPayments &&
            payments.Count != 0)
        {
            throw new InvalidDataException(
                "Billing response exposed payments without permission.");
        }

        return new RemoteAccountBillingResult(
            "ready",
            account,
            permissions,
            invoices,
            payments);
    }

    private static RemoteAccountBillingResult ErrorResult(
        HttpStatusCode statusCode,
        JsonElement root)
    {
        var error = OptionalString(root, "error") ??
            "ACCOUNT_BILLING_UNAVAILABLE";

        if (statusCode == HttpStatusCode.Unauthorized &&
            error == "INVALID_TOKEN")
        {
            throw new UnauthorizedAccessException(
                "BKE account session was rejected by billing authority.");
        }

        var normalized = error switch
        {
            "ACCOUNT_FORBIDDEN" => "account_forbidden",
            "RATE_LIMITED" => "rate_limited",
            "ACCOUNT_BILLING_UNAVAILABLE" =>
                "billing_unavailable",
            _ => error.ToLowerInvariant(),
        };

        return new RemoteAccountBillingResult(
            normalized,
            ErrorCode: error,
            Retryable:
                (int)statusCode == 429 ||
                statusCode == HttpStatusCode.ServiceUnavailable);
    }

    private static IReadOnlyList<AccountBillingInvoice>
        RequiredInvoices(JsonElement root)
    {
        var array = RequiredArray(root, "invoices");
        var items = array.EnumerateArray()
            .Select(item =>
            {
                RequireObjectItem(item, "invoices");
                var lines = RequiredInvoiceLines(item);
                return new AccountBillingInvoice(
                    RequiredBoundedString(
                        item,
                        "number",
                        1,
                        120),
                    RequiredInvoiceStatus(
                        item,
                        "status"),
                    RequiredBoundedString(
                        item,
                        "order_number",
                        1,
                        120),
                    RequiredCurrency(
                        item,
                        "currency"),
                    RequiredNonNegativeInt(
                        item,
                        "subtotal_minor"),
                    RequiredNonNegativeInt(
                        item,
                        "tax_minor"),
                    RequiredNonNegativeInt(
                        item,
                        "total_minor"),
                    OptionalTimestamp(
                        item,
                        "issued_at"),
                    RequiredTimestamp(
                        item,
                        "created_at"),
                    lines);
            })
            .ToArray();

        if (items.Length > MaximumItems)
        {
            throw new InvalidDataException(
                "Account billing invoice list is too large.");
        }

        return items;
    }

    private static IReadOnlyList<AccountBillingInvoiceLine>
        RequiredInvoiceLines(JsonElement root)
    {
        var array = RequiredArray(root, "lines");
        var items = array.EnumerateArray()
            .Select(item =>
            {
                RequireObjectItem(item, "invoice lines");
                return new AccountBillingInvoiceLine(
                    RequiredBoundedString(
                        item,
                        "description",
                        1,
                        500),
                    RequiredPositiveInt(
                        item,
                        "quantity"),
                    RequiredNonNegativeInt(
                        item,
                        "unit_amount_minor"),
                    RequiredNonNegativeInt(
                        item,
                        "total_minor"));
            })
            .ToArray();

        if (items.Length > MaximumInvoiceLines)
        {
            throw new InvalidDataException(
                "Account billing invoice line list is too large.");
        }

        return items;
    }

    private static IReadOnlyList<AccountBillingPayment>
        RequiredPayments(JsonElement root)
    {
        var array = RequiredArray(root, "payments");
        var items = array.EnumerateArray()
            .Select(item =>
            {
                RequireObjectItem(item, "payments");
                return new AccountBillingPayment(
                    RequiredBoundedString(
                        item,
                        "order_number",
                        1,
                        120),
                    RequiredPaymentStatus(
                        item,
                        "status"),
                    RequiredNonNegativeInt(
                        item,
                        "amount_minor"),
                    RequiredCurrency(
                        item,
                        "currency"),
                    OptionalTimestamp(
                        item,
                        "paid_at"),
                    RequiredTimestamp(
                        item,
                        "created_at"));
            })
            .ToArray();

        if (items.Length > MaximumItems)
        {
            throw new InvalidDataException(
                "Account billing payment list is too large.");
        }

        return items;
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
        return value is
            "OWNER" or
            "BILLING" or
            "LICENSE_MANAGER" or
            "MEMBER"
            ? value
            : throw new InvalidDataException(
                $"Invalid {name}.");
    }

    private static string RequiredInvoiceStatus(
        JsonElement root,
        string name)
    {
        var value = RequiredString(root, name);
        return value is "DRAFT" or "FINAL" or "VOID"
            ? value
            : throw new InvalidDataException(
                $"Invalid {name}.");
    }

    private static string RequiredPaymentStatus(
        JsonElement root,
        string name)
    {
        var value = RequiredString(root, name);
        return value is
            "PENDING" or
            "PAID" or
            "FAILED" or
            "REFUNDED" or
            "PARTIALLY_REFUNDED"
            ? value
            : throw new InvalidDataException(
                $"Invalid {name}.");
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

    private static string RequiredTimestamp(
        JsonElement root,
        string name)
    {
        var value = RequiredString(root, name);
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
        var value = OptionalString(root, name);
        if (value is not null &&
            !DateTimeOffset.TryParse(value, out _))
        {
            throw new InvalidDataException(
                $"Invalid {name}.");
        }

        return value;
    }

    private static int RequiredNonNegativeInt(
        JsonElement root,
        string name)
    {
        if (!root.TryGetProperty(name, out var value) ||
            !value.TryGetInt32(out var result) ||
            result < 0)
        {
            throw new InvalidDataException(
                $"Invalid {name}.");
        }

        return result;
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
                $"Invalid {name}.");
        }

        return value.GetBoolean();
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

    private static void RequireObjectItem(
        JsonElement value,
        string name)
    {
        if (value.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException(
                $"Invalid {name} item.");
        }
    }

    private static string RequiredBoundedString(
        JsonElement root,
        string name,
        int minimum,
        int maximum)
    {
        var value = RequiredString(root, name);
        if (value.Length < minimum ||
            value.Length > maximum)
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

    private static bool ValidSecret(
        string value,
        int maximum) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length <= maximum;

    private static void EnsureProtocol(
        HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues(
                "x-bke-account-session-version",
                out var values))
        {
            throw new InvalidDataException(
                "Account billing response is missing its protocol version.");
        }

        var versions = values.ToArray();
        if (versions.Length != 1 ||
            versions[0] != AccountSessionRemote.ProtocolVersion)
        {
            throw new InvalidDataException(
                "Account billing protocol version drifted.");
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
            new JsonDocumentOptions { MaxDepth = 12 },
            cancellationToken);
    }

    public void Dispose()
    {
        if (_ownsHttpClient)
        {
            _http.Dispose();
        }
    }
}
