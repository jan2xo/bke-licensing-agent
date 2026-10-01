using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Infrastructure;

public sealed class AccountLicenseDevicesRemote :
    IAccountLicenseDevicesRemote,
    IDisposable
{
    private const string ReadEndpoint =
        "/api/agent-sessions/account/license-devices";
    private const string ManageEndpoint =
        "/api/agent-sessions/account/license-devices/manage";
    private const int MaximumDevices = 100;

    private readonly Uri _platformBaseUri;
    private readonly HttpClient _http;
    private readonly bool _ownsHttpClient;

    public AccountLicenseDevicesRemote(
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
                "Account authorized-device authority requires HTTPS outside isolated loopback certification.");
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

    public async Task<RemoteAccountLicenseDevicesResult> GetAsync(
        string accessToken,
        string licenseManagementHandle,
        CancellationToken cancellationToken)
    {
        if (!ValidSecret(accessToken, 8192) ||
            !ValidLicenseHandle(licenseManagementHandle))
        {
            return new RemoteAccountLicenseDevicesResult(
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
            return new RemoteAccountLicenseDevicesResult(
                "devices_unavailable",
                ErrorCode: "LICENSE_DEVICES_UNAVAILABLE",
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
            return new RemoteAccountLicenseDevicesResult(
                error.Status,
                ErrorCode: error.ErrorCode,
                Retryable: error.Retryable);
        }

        var root = document.RootElement;
        if (RequiredString(root, "status") != "ready")
        {
            throw new InvalidDataException(
                "Account authorized-device response drifted.");
        }

        var licenseRoot = RequiredObject(root, "license");
        var maxDevices = RequiredNonNegativeInt(
            licenseRoot,
            "max_devices");
        var activeDevices = RequiredNonNegativeInt(
            licenseRoot,
            "active_devices");
        if (activeDevices > maxDevices)
        {
            throw new InvalidDataException(
                "Active device count exceeds licensed capacity.");
        }

        var license = new AccountLicenseDeviceInfo(
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
            maxDevices,
            activeDevices);

        return new RemoteAccountLicenseDevicesResult(
            "ready",
            license,
            RequiredDevices(root));
    }

    public async Task<RemoteAccountLicenseDeviceDeactivateResult>
        DeactivateAsync(
            string accessToken,
            string licenseManagementHandle,
            string deviceManagementHandle,
            CancellationToken cancellationToken)
    {
        if (!ValidSecret(accessToken, 8192) ||
            !ValidLicenseHandle(licenseManagementHandle) ||
            !ValidDeviceHandle(deviceManagementHandle))
        {
            return new RemoteAccountLicenseDeviceDeactivateResult(
                "invalid_input",
                ErrorCode: "INVALID_INPUT");
        }

        using var request = Request(
            ManageEndpoint,
            accessToken,
            new
            {
                license_management_handle =
                    licenseManagementHandle,
                device_management_handle =
                    deviceManagementHandle,
            });

        using var response = await _http.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);

        RejectRedirect(response);
        if (response.StatusCode == HttpStatusCode.NotFound &&
            !HasProtocol(response))
        {
            return new RemoteAccountLicenseDeviceDeactivateResult(
                "devices_unavailable",
                ErrorCode:
                    "LICENSE_DEVICE_DEACTIVATE_UNAVAILABLE",
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
            return new RemoteAccountLicenseDeviceDeactivateResult(
                error.Status,
                ErrorCode: error.ErrorCode,
                Retryable: error.Retryable);
        }

        if (RequiredString(
                document.RootElement,
                "status") != "deactivated")
        {
            throw new InvalidDataException(
                "Account authorized-device deactivation status drifted.");
        }

        return new RemoteAccountLicenseDeviceDeactivateResult(
            "deactivated");
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
            "LICENSE_DEVICES_UNAVAILABLE";

        if (statusCode == HttpStatusCode.Unauthorized &&
            error == "INVALID_TOKEN")
        {
            throw new UnauthorizedAccessException(
                "BKE account session was rejected by authorized-device authority.");
        }

        var normalized = error switch
        {
            "ACCOUNT_FORBIDDEN" => "account_forbidden",
            "LICENSE_NOT_FOUND" => "license_not_found",
            "DEVICE_NOT_FOUND" => "device_not_found",
            "ACCOUNT_NOT_ACTIVE" => "account_not_active",
            "INVALID_INPUT" => "invalid_input",
            "RATE_LIMITED" => "rate_limited",
            "LICENSE_DEVICES_UNAVAILABLE" =>
                "devices_unavailable",
            "LICENSE_DEVICE_DEACTIVATE_UNAVAILABLE" =>
                "devices_unavailable",
            _ => error.ToLowerInvariant(),
        };

        return (
            normalized,
            error,
            (int)statusCode == 429 ||
            statusCode == HttpStatusCode.ServiceUnavailable);
    }

    private static IReadOnlyList<AccountAuthorizedDevice>
        RequiredDevices(JsonElement root)
    {
        if (!root.TryGetProperty(
                "devices",
                out var value) ||
            value.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException(
                "Invalid authorized-device list.");
        }

        var devices = value.EnumerateArray()
            .Select(item =>
            {
                if (item.ValueKind != JsonValueKind.Object)
                {
                    throw new InvalidDataException(
                        "Invalid authorized-device item.");
                }

                var active = RequiredBoolean(item, "active");
                var handle = OptionalDeviceHandle(
                    item,
                    "management_handle");

                if (active && handle is null ||
                    !active && handle is not null)
                {
                    throw new InvalidDataException(
                        "Authorized-device management-handle state drifted.");
                }

                return new AccountAuthorizedDevice(
                    OptionalBoundedString(
                        item,
                        "label",
                        200),
                    OptionalBoundedString(
                        item,
                        "operating_system",
                        120),
                    OptionalBoundedString(
                        item,
                        "architecture",
                        80),
                    RequiredTimestamp(
                        item,
                        "last_seen_at"),
                    RequiredTimestamp(
                        item,
                        "activated_at"),
                    active,
                    handle);
            })
            .ToArray();

        if (devices.Length > MaximumDevices)
        {
            throw new InvalidDataException(
                "Authorized-device list is too large.");
        }

        return devices;
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

    private static string? OptionalDeviceHandle(
        JsonElement root,
        string name)
    {
        var value = OptionalString(root, name);
        if (value is null)
        {
            return null;
        }

        if (!ValidDeviceHandle(value))
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
        Regex.IsMatch(
            value,
            "^bke-license-device-v1_[0-9a-f]{64}$",
            RegexOptions.CultureInvariant);

    private static bool ValidDeviceHandle(string value) =>
        Regex.IsMatch(
            value,
            "^bke-license-device-target-v1_[0-9a-f]{64}$",
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
                "Account authorized-device protocol version drifted.");
        }
    }

    private static void RejectRedirect(
        HttpResponseMessage response)
    {
        if ((int)response.StatusCode is >= 300 and <= 399)
        {
            throw new HttpRequestException(
                "BKE authorized-device authority redirected.");
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
