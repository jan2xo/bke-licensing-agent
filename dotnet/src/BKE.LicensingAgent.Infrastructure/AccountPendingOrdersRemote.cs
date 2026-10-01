using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using BKE.LicensingAgent.Application;

namespace BKE.LicensingAgent.Infrastructure;

public sealed class AccountPendingOrdersRemote :
    IAccountPendingOrdersRemote,
    IDisposable
{
    private const string ContinueEndpoint =
        "/api/agent-sessions/account/orders/continue";
    private const string CancelEndpoint =
        "/api/agent-sessions/account/orders/cancel";

    private readonly Uri _platformBaseUri;
    private readonly HttpClient _http;
    private readonly bool _ownsHttpClient;
    private readonly bool _allowInsecureLocal;

    public AccountPendingOrdersRemote(
        HttpClient? httpClient = null,
        string? platformBaseUrl = null)
    {
        var rawBaseUrl = (
            platformBaseUrl ??
            Environment.GetEnvironmentVariable(
                "BKE_PLATFORM_BASE_URL") ??
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

        _allowInsecureLocal =
            Environment.GetEnvironmentVariable(
                "BKE_AGENT_VNEXT_ALLOW_INSECURE_LOCAL") == "1" &&
            baseUri.IsLoopback &&
            baseUri.Scheme == Uri.UriSchemeHttp;

        if (baseUri.Scheme != Uri.UriSchemeHttps &&
            !_allowInsecureLocal)
        {
            throw new InvalidOperationException(
                "Pending-order authority requires HTTPS outside isolated loopback certification.");
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
                new HttpClientHandler
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

    public async Task<RemoteAccountPendingOrderContinueResult>
        ContinueAsync(
            string accessToken,
            string orderContinueHandle,
            CancellationToken cancellationToken)
    {
        if (!ValidSecret(accessToken, 8192) ||
            !ValidContinueHandle(orderContinueHandle))
        {
            return new RemoteAccountPendingOrderContinueResult(
                "invalid_input",
                ErrorCode: "INVALID_INPUT");
        }

        using var request = Request(
            ContinueEndpoint,
            accessToken,
            new
            {
                order_continue_handle =
                    orderContinueHandle,
            });

        using var response = await _http.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);

        RejectRedirect(response);
        if (response.StatusCode == HttpStatusCode.NotFound &&
            !HasProtocol(response))
        {
            return new RemoteAccountPendingOrderContinueResult(
                "authority_unavailable",
                ErrorCode: "ORDER_CONTINUE_UNAVAILABLE",
                Retryable: true);
        }

        EnsureProtocol(response);
        using var document = await ReadJsonAsync(
            response,
            cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            var error = ErrorResult(
                response.StatusCode,
                document.RootElement,
                "ORDER_CONTINUE_UNAVAILABLE");
            return new RemoteAccountPendingOrderContinueResult(
                error.Status,
                ErrorCode: error.ErrorCode,
                Retryable: error.Retryable);
        }

        if (RequiredString(
                document.RootElement,
                "status") != "continued")
        {
            throw new InvalidDataException(
                "Pending-order continuation status drifted.");
        }

        return new RemoteAccountPendingOrderContinueResult(
            "continued",
            RequiredCheckoutUrl(
                document.RootElement,
                "checkout_url"));
    }

    public async Task<RemoteAccountPendingOrderCancelResult>
        CancelAsync(
            string accessToken,
            string orderCancelHandle,
            CancellationToken cancellationToken)
    {
        if (!ValidSecret(accessToken, 8192) ||
            !ValidCancelHandle(orderCancelHandle))
        {
            return new RemoteAccountPendingOrderCancelResult(
                "invalid_input",
                ErrorCode: "INVALID_INPUT");
        }

        using var request = Request(
            CancelEndpoint,
            accessToken,
            new
            {
                order_cancel_handle =
                    orderCancelHandle,
            });

        using var response = await _http.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);

        RejectRedirect(response);
        if (response.StatusCode == HttpStatusCode.NotFound &&
            !HasProtocol(response))
        {
            return new RemoteAccountPendingOrderCancelResult(
                "authority_unavailable",
                ErrorCode: "ORDER_CANCEL_UNAVAILABLE",
                Retryable: true);
        }

        EnsureProtocol(response);
        using var document = await ReadJsonAsync(
            response,
            cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            var error = ErrorResult(
                response.StatusCode,
                document.RootElement,
                "ORDER_CANCEL_UNAVAILABLE");
            return new RemoteAccountPendingOrderCancelResult(
                error.Status,
                ErrorCode: error.ErrorCode,
                Retryable: error.Retryable);
        }

        if (RequiredString(
                document.RootElement,
                "status") != "cancelled")
        {
            throw new InvalidDataException(
                "Pending-order cancellation status drifted.");
        }

        return new RemoteAccountPendingOrderCancelResult(
            "cancelled");
    }

    private HttpRequestMessage Request(
        string endpoint,
        string accessToken,
        object body)
    {
        var request = new HttpRequestMessage(
            HttpMethod.Post,
            new Uri(_platformBaseUri, endpoint));
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
            Guid.NewGuid().ToString("N"));
        request.Content = JsonContent.Create(body);
        return request;
    }

    private static (
        string Status,
        string ErrorCode,
        bool Retryable)
        ErrorResult(
            HttpStatusCode statusCode,
            JsonElement root,
            string fallbackCode)
    {
        var error = OptionalString(root, "error") ??
            fallbackCode;

        if (statusCode == HttpStatusCode.Unauthorized &&
            error == "INVALID_TOKEN")
        {
            throw new UnauthorizedAccessException(
                "BKE account session was rejected by pending-order authority.");
        }

        var normalized = error switch
        {
            "ACCOUNT_FORBIDDEN" => "account_forbidden",
            "ORDER_NOT_FOUND" => "order_not_found",
            "ACCOUNT_NOT_ACTIVE" => "account_not_active",
            "CHECKOUT_CREATION_IN_PROGRESS" =>
                "checkout_creation_in_progress",
            "LEGAL_ACCEPTANCE_REQUIRED" =>
                "legal_acceptance_required",
            "LEGAL_REACCEPTANCE_REQUIRED" =>
                "legal_reacceptance_required",
            "INVALID_INPUT" => "invalid_input",
            "RATE_LIMITED" => "rate_limited",
            "ORDER_CONTINUE_UNAVAILABLE" =>
                "authority_unavailable",
            "ORDER_CANCEL_UNAVAILABLE" =>
                "authority_unavailable",
            _ => error.ToLowerInvariant(),
        };

        return (
            normalized,
            error,
            (int)statusCode == 429);
    }

    private string RequiredCheckoutUrl(
        JsonElement root,
        string name)
    {
        var value = RequiredString(root, name);
        if (!Uri.TryCreate(
                value,
                UriKind.Absolute,
                out var uri) ||
            uri.Scheme != Uri.UriSchemeHttps &&
            !(_allowInsecureLocal &&
              uri.Scheme == Uri.UriSchemeHttp &&
              uri.IsLoopback) ||
            !string.IsNullOrEmpty(uri.UserInfo))
        {
            throw new InvalidDataException(
                $"Invalid {name}.");
        }

        return uri.AbsoluteUri;
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

    private static bool ValidContinueHandle(string value) =>
        Regex.IsMatch(
            value,
            "^bke-order-continue-v1_[0-9a-f]{64}$",
            RegexOptions.CultureInvariant);

    private static bool ValidCancelHandle(string value) =>
        Regex.IsMatch(
            value,
            "^bke-order-cancel-v1_[0-9a-f]{64}$",
            RegexOptions.CultureInvariant);

    private static bool ValidSecret(
        string value,
        int maximum) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length <= maximum;

    private static bool HasProtocol(
        HttpResponseMessage response) =>
        response.Headers.TryGetValues(
            "x-bke-account-session-version",
            out var values) &&
        values.SingleOrDefault() ==
            AccountSessionRemote.ProtocolVersion;

    private static void EnsureProtocol(
        HttpResponseMessage response)
    {
        if (!HasProtocol(response))
        {
            throw new InvalidDataException(
                "Pending-order authority protocol version drifted.");
        }
    }

    private static void RejectRedirect(
        HttpResponseMessage response)
    {
        if ((int)response.StatusCode is >= 300 and <= 399)
        {
            throw new HttpRequestException(
                "BKE pending-order authority redirected.");
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
            new JsonDocumentOptions { MaxDepth = 8 },
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
