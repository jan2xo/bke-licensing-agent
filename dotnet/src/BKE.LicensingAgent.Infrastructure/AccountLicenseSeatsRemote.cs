using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Infrastructure;

public sealed class AccountLicenseSeatsRemote :
    IAccountLicenseSeatsRemote,
    IDisposable
{
    private const string ReadEndpoint =
        "/api/agent-sessions/account/license-seats";
    private const string ManageEndpoint =
        "/api/agent-sessions/account/license-seats/manage";
    private const int MaximumTargets = 500;

    private readonly Uri _platformBaseUri;
    private readonly HttpClient _http;
    private readonly bool _ownsHttpClient;

    public AccountLicenseSeatsRemote(
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
                "Account license seat authority requires HTTPS outside isolated loopback certification.");
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

    public async Task<RemoteAccountLicenseSeatsResult> GetAsync(
        string accessToken,
        string licenseManagementHandle,
        CancellationToken cancellationToken)
    {
        if (!ValidSecret(accessToken, 8192) ||
            !ValidLicenseHandle(licenseManagementHandle))
        {
            return new RemoteAccountLicenseSeatsResult(
                "invalid_input",
                ErrorCode: "INVALID_INPUT");
        }

        using var request = Request(
            ReadEndpoint,
            accessToken,
            new
            {
                management_handle =
                    licenseManagementHandle,
            });

        using var response = await _http.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);

        RejectRedirect(response);
        if (response.StatusCode == HttpStatusCode.NotFound &&
            !HasProtocol(response))
        {
            return new RemoteAccountLicenseSeatsResult(
                "seats_unavailable",
                ErrorCode: "LICENSE_SEATS_UNAVAILABLE",
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
                document.RootElement);
            return new RemoteAccountLicenseSeatsResult(
                error.Status,
                ErrorCode: error.ErrorCode,
                Retryable: error.Retryable);
        }

        var root = document.RootElement;
        if (RequiredString(root, "status") != "ready")
        {
            throw new InvalidDataException(
                "Account license seat response drifted.");
        }

        var licenseRoot = RequiredObject(root, "license");
        var maxSeats = RequiredNonNegativeInt(
            licenseRoot,
            "max_seats");
        var assignedSeats = RequiredNonNegativeInt(
            licenseRoot,
            "assigned_seats");
        var availableSeats = RequiredNonNegativeInt(
            licenseRoot,
            "available_seats");
        if (assignedSeats > maxSeats ||
            availableSeats !=
                Math.Max(0, maxSeats - assignedSeats))
        {
            throw new InvalidDataException(
                "Account license seat capacity drifted.");
        }

        var license = new AccountLicenseSeatInfo(
            RequiredBoundedString(
                licenseRoot,
                "product_name",
                1,
                200),
            OptionalBoundedString(
                licenseRoot,
                "edition_name",
                120),
            RequiredLastFour(
                licenseRoot,
                "key_last_four"),
            maxSeats,
            assignedSeats,
            availableSeats);

        var targets = RequiredTargets(root);

        return new RemoteAccountLicenseSeatsResult(
            "ready",
            license,
            targets);
    }

    public async Task<RemoteAccountLicenseSeatsManageResult>
        ManageAsync(
            string accessToken,
            string action,
            string licenseManagementHandle,
            string targetManagementHandle,
            CancellationToken cancellationToken)
    {
        if (!ValidSecret(accessToken, 8192) ||
            action is not ("ASSIGN" or "REMOVE") ||
            !ValidLicenseHandle(licenseManagementHandle) ||
            !ValidTargetHandle(targetManagementHandle))
        {
            return new RemoteAccountLicenseSeatsManageResult(
                "invalid_input",
                ErrorCode: "INVALID_INPUT");
        }

        using var request = Request(
            ManageEndpoint,
            accessToken,
            new
            {
                action = action.ToLowerInvariant(),
                license_management_handle =
                    licenseManagementHandle,
                target_management_handle =
                    targetManagementHandle,
            });

        using var response = await _http.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);

        RejectRedirect(response);
        if (response.StatusCode == HttpStatusCode.NotFound &&
            !HasProtocol(response))
        {
            return new RemoteAccountLicenseSeatsManageResult(
                "seats_unavailable",
                ErrorCode: "LICENSE_SEAT_MANAGE_UNAVAILABLE",
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
                document.RootElement);
            return new RemoteAccountLicenseSeatsManageResult(
                error.Status,
                ErrorCode: error.ErrorCode,
                Retryable: error.Retryable);
        }

        var status = RequiredString(
            document.RootElement,
            "status");
        if (status is not (
            "assigned" or
            "existing" or
            "removed" or
            "not_assigned"))
        {
            throw new InvalidDataException(
                "Account license seat mutation status drifted.");
        }

        return new RemoteAccountLicenseSeatsManageResult(status);
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
        request.Content = JsonContent.Create(body);
        return request;
    }

    private static (
        string Status,
        string ErrorCode,
        bool Retryable)
        ErrorResult(
            HttpStatusCode statusCode,
            JsonElement root)
    {
        var error = OptionalString(root, "error") ??
            "LICENSE_SEATS_UNAVAILABLE";

        if (statusCode == HttpStatusCode.Unauthorized &&
            error == "INVALID_TOKEN")
        {
            throw new UnauthorizedAccessException(
                "BKE account session was rejected by license seat authority.");
        }

        var normalized = error switch
        {
            "ACCOUNT_FORBIDDEN" => "account_forbidden",
            "LICENSE_NOT_FOUND" => "license_not_found",
            "TARGET_NOT_FOUND" => "target_not_found",
            "ACCOUNT_NOT_ACTIVE" => "account_not_active",
            "LICENSE_NOT_ACTIVE" => "license_not_active",
            "TARGET_NOT_ACCOUNT_MEMBER" =>
                "target_not_account_member",
            "LICENSE_SEAT_LIMIT" => "license_seat_limit",
            "INVALID_INPUT" => "invalid_input",
            "RATE_LIMITED" => "rate_limited",
            "LICENSE_SEATS_UNAVAILABLE" =>
                "seats_unavailable",
            _ => error.ToLowerInvariant(),
        };

        return (
            normalized,
            error,
            (int)statusCode == 429 ||
            statusCode == HttpStatusCode.ServiceUnavailable);
    }

    private static IReadOnlyList<AccountLicenseSeatTarget>
        RequiredTargets(JsonElement root)
    {
        if (!root.TryGetProperty(
                "targets",
                out var value) ||
            value.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException(
                "Invalid license seat targets.");
        }

        var targets = value.EnumerateArray()
            .Select(item =>
            {
                if (item.ValueKind != JsonValueKind.Object)
                {
                    throw new InvalidDataException(
                        "Invalid license seat target item.");
                }

                return new AccountLicenseSeatTarget(
                    RequiredBoundedString(
                        item,
                        "email",
                        1,
                        320),
                    OptionalBoundedString(
                        item,
                        "name",
                        160),
                    RequiredBoolean(
                        item,
                        "assigned"),
                    RequiredBoolean(
                        item,
                        "eligible"),
                    RequiredTargetHandle(
                        item,
                        "management_handle"));
            })
            .ToArray();

        if (targets.Length > MaximumTargets)
        {
            throw new InvalidDataException(
                "License seat target list is too large.");
        }

        return targets;
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

    private static string RequiredTargetHandle(
        JsonElement root,
        string name)
    {
        var value = RequiredString(root, name);
        if (!ValidTargetHandle(value))
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

    private static bool ValidLicenseHandle(string value) =>
        System.Text.RegularExpressions.Regex.IsMatch(
            value,
            "^bke-license-seat-v1_[0-9a-f]{64}$",
            System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    private static bool ValidTargetHandle(string value) =>
        System.Text.RegularExpressions.Regex.IsMatch(
            value,
            "^bke-license-seat-user-v1_[0-9a-f]{64}$",
            System.Text.RegularExpressions.RegexOptions.CultureInvariant);

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
                "Account license seat protocol version drifted.");
        }
    }

    private static void RejectRedirect(
        HttpResponseMessage response)
    {
        if ((int)response.StatusCode is >= 300 and <= 399)
        {
            throw new HttpRequestException(
                "BKE account license seat authority redirected.");
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

    public void Dispose()
    {
        if (_ownsHttpClient)
        {
            _http.Dispose();
        }
    }
}
