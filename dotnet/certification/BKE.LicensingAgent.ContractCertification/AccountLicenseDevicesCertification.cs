using System.Net;
using System.Text;
using System.Text.Json;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;
using BKE.LicensingAgent.Infrastructure;

static class AccountLicenseDevicesCertification
{
    private const string ExpectedDigitalSolutionsSource =
        "511bd3309244a5dc8170558b5410fbf831facc9f";

    private static readonly string LicenseHandle =
        "bke-license-device-v1_" + new string('a', 64);
    private static readonly string DeviceHandle =
        "bke-license-device-target-v1_" + new string('b', 64);

    public static async Task RunAsync()
    {
        CertifyStaticBoundaries();
        await CertifyServiceBoundaryAsync();
        await CertifyRemoteTransportAsync();
    }

    private static void CertifyStaticBoundaries()
    {
        Require(
            File.ReadAllText(
                Path.Combine(
                    "eng",
                    "digital-solutions-source.sha")).Trim() ==
                ExpectedDigitalSolutionsSource,
            "Agent is not pinned to the security-fixed Digital Solutions authorized-device authority.");

        Require(
            LocalAgentContract.AccountLicenseDevicesCapabilityId ==
                "bke.account-license-devices" &&
            LocalAgentContract.AccountLicenseDevicesContractVersion == 1 &&
            LocalAgentContract.AccountLicenseDevicesPath ==
                "/v1/account/license-devices" &&
            LocalAgentContract.AccountLicenseDevicesManagePath ==
                "/v1/account/license-devices/manage",
            "account authorized-device local capability drifted");

        Require(
            typeof(AccountLicenseDevicesRequest)
                .GetProperties()
                .Select(property => property.Name)
                .SequenceEqual([
                    "CorrelationId",
                    "LicenseManagementHandle",
                ]),
            "account authorized-device read request widened");

        Require(
            typeof(AccountLicenseDeviceDeactivateRequest)
                .GetProperties()
                .Select(property => property.Name)
                .SequenceEqual([
                    "CorrelationId",
                    "LicenseManagementHandle",
                    "DeviceManagementHandle",
                ]),
            "account authorized-device mutation request widened");

        foreach (var type in new[]
        {
            typeof(AccountLicenseDevicesResponse),
            typeof(AccountLicenseDeviceDeactivateResponse),
            typeof(AccountLicenseDeviceInfo),
            typeof(AccountAuthorizedDevice),
            typeof(AccountLicenseDevicesError),
        })
        {
            Require(
                type.GetProperties().All(property =>
                    !property.Name.Contains(
                        "AccessToken",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Contains(
                        "RefreshToken",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Contains(
                        "Handoff",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Equals(
                        "AccountId",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Equals(
                        "LicenseId",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Equals(
                        "DeviceId",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Equals(
                        "ActivationId",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Equals(
                        "ProductId",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Contains(
                        "DeviceHash",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Contains(
                        "MachineId",
                        StringComparison.OrdinalIgnoreCase)),
                $"account authorized-device response {type.Name} exposes authority identifiers or machine secrets");
        }

        var hostSource = File.ReadAllText(
            Path.Combine(
                "dotnet",
                "src",
                "BKE.LicensingAgent.Host",
                "Program.cs"));
        var remoteSource = File.ReadAllText(
            Path.Combine(
                "dotnet",
                "src",
                "BKE.LicensingAgent.Infrastructure",
                "AccountLicenseDevicesRemote.cs"));
        var serviceSource = File.ReadAllText(
            Path.Combine(
                "dotnet",
                "src",
                "BKE.LicensingAgent.Application",
                "AccountLicenseDevicesService.cs"));

        Require(
            hostSource.Contains(
                "app.MapPost(LocalAgentContract.AccountLicenseDevicesPath",
                StringComparison.Ordinal) &&
            hostSource.Contains(
                "app.MapPost(LocalAgentContract.AccountLicenseDevicesManagePath",
                StringComparison.Ordinal) &&
            hostSource.Contains(
                "AddSingleton<IAccountLicenseDevicesService>",
                StringComparison.Ordinal) &&
            hostSource.Contains(
                "AddSingleton<IAccountLicenseDevicesRemote>",
                StringComparison.Ordinal),
            "Agent Host authorized-device mediation wiring drifted");

        Require(
            remoteSource.Contains(
                "/api/agent-sessions/account/license-devices",
                StringComparison.Ordinal) &&
            remoteSource.Contains(
                "/api/agent-sessions/account/license-devices/manage",
                StringComparison.Ordinal) &&
            remoteSource.Contains(
                "new AuthenticationHeaderValue(\"Bearer\", accessToken)",
                StringComparison.Ordinal) &&
            remoteSource.Contains(
                "\"x-bke-account-session-version\"",
                StringComparison.Ordinal) &&
            remoteSource.Contains(
                "AllowAutoRedirect = false",
                StringComparison.Ordinal) &&
            !remoteSource.Contains(
                "for (var attempt",
                StringComparison.Ordinal),
            "Agent authorized-device remote lost bearer/protocol/single-attempt/redirect mediation");

        Require(
            !remoteSource.Contains(
                "device_hash",
                StringComparison.OrdinalIgnoreCase) &&
            !remoteSource.Contains(
                "machine_id",
                StringComparison.OrdinalIgnoreCase) &&
            !remoteSource.Contains("Console.", StringComparison.Ordinal) &&
            !serviceSource.Contains("Console.", StringComparison.Ordinal) &&
            !serviceSource.Contains("AgentDatabase", StringComparison.Ordinal) &&
            !serviceSource.Contains("File.", StringComparison.Ordinal),
            "Agent authorized-device mediation introduced machine-secret handling, logging, or local persistence");
    }

    private static async Task CertifyServiceBoundaryAsync()
    {
        var account = new AccountSessionAccount(
            "device-user",
            "device@example.test",
            "cloud-account-must-not-leak",
            "ORGANIZATION",
            "Device Organization");

        var store = DeviceCertStore.Active(account);
        var remote = new DeviceCertRemote(
            ReadyRemoteResult(),
            new RemoteAccountLicenseDeviceDeactivateResult(
                "deactivated"));

        var service = new AccountLicenseDevicesService(
            new DeviceCertAuthenticatedSessionService(account),
            store,
            remote);

        var read = await service.GetAsync(
            new AccountLicenseDevicesRequest(
                "device-read-cert",
                LicenseHandle),
            CancellationToken.None);

        Require(
            read.Status == "READY" &&
            read.License?.ProductName == "Render Dock" &&
            read.License.MaxDevices == 4 &&
            read.License.ActiveDevices == 1 &&
            read.Devices.Count == 2 &&
            read.Devices[0].ManagementHandle == DeviceHandle &&
            read.Devices[0].Active &&
            read.Devices[1].ManagementHandle is null &&
            !read.Devices[1].Active &&
            remote.ReadCalls == 1 &&
            remote.LastAccessToken == "device-access-secret" &&
            remote.LastLicenseHandle == LicenseHandle,
            "account authorized-device read mediation drifted");

        var deactivated = await service.DeactivateAsync(
            new AccountLicenseDeviceDeactivateRequest(
                "device-deactivate-cert",
                LicenseHandle,
                DeviceHandle),
            CancellationToken.None);

        Require(
            deactivated.Status == "DEACTIVATED" &&
            remote.DeactivateCalls == 1 &&
            remote.LastDeviceHandle == DeviceHandle,
            "account authorized-device deactivation mediation drifted");

        var wire = JsonSerializer.Serialize(new
        {
            read,
            deactivated,
        });
        foreach (var forbidden in new[]
        {
            "device-access-secret",
            "device-refresh-secret",
            "cloud-account-must-not-leak",
            "raw-license-id-must-not-leak",
            "raw-device-id-must-not-leak",
            "raw-device-hash-must-not-leak",
            "raw-machine-id-must-not-leak",
        })
        {
            Require(
                !wire.Contains(
                    forbidden,
                    StringComparison.Ordinal),
                "account authorized-device response leaked Agent/cloud/machine authority material");
        }

        var unauthenticatedRemote = new DeviceCertRemote(
            ReadyRemoteResult(),
            new RemoteAccountLicenseDeviceDeactivateResult(
                "deactivated"));
        var unauthenticatedService =
            new AccountLicenseDevicesService(
                new DeviceCertUnauthenticatedSessionService(),
                DeviceCertStore.Active(account),
                unauthenticatedRemote);
        var unauthenticated =
            await unauthenticatedService.GetAsync(
                new AccountLicenseDevicesRequest(
                    "device-signed-out",
                    LicenseHandle),
                CancellationToken.None);
        Require(
            unauthenticated.Status == "AUTH_REQUIRED" &&
            unauthenticatedRemote.ReadCalls == 0 &&
            unauthenticatedRemote.DeactivateCalls == 0,
            "signed-out authorized-device flow reached cloud authority");

        var invalidStore = DeviceCertStore.Active(account);
        var invalidService = new AccountLicenseDevicesService(
            new DeviceCertAuthenticatedSessionService(account),
            invalidStore,
            new DeviceCertThrowingRemote(
                readError: new UnauthorizedAccessException(
                    "certified invalid bearer")));
        var invalid = await invalidService.GetAsync(
            new AccountLicenseDevicesRequest(
                "device-invalid-token",
                LicenseHandle),
            CancellationToken.None);
        Require(
            invalid.Status == "AUTH_REQUIRED" &&
            invalid.Error?.Code == "SESSION_INVALID" &&
            invalidStore.State is null,
            "invalid bearer did not clear durable Agent session custody");

        var readFailureStore = DeviceCertStore.Active(account);
        var readFailure = await new AccountLicenseDevicesService(
            new DeviceCertAuthenticatedSessionService(account),
            readFailureStore,
            new DeviceCertThrowingRemote(
                readError: new HttpRequestException(
                    "certified transient device read")))
            .GetAsync(
                new AccountLicenseDevicesRequest(
                    "device-read-failure",
                    LicenseHandle),
                CancellationToken.None);
        Require(
            readFailure.Status == "FAILED" &&
            readFailure.Error?.Code ==
                "LICENSE_DEVICES_UNAVAILABLE" &&
            readFailure.Error.Retryable &&
            readFailureStore.State is ActiveAccountSessionState,
            "transient authorized-device read failure did not preserve valid Agent custody");

        var ambiguousStore = DeviceCertStore.Active(account);
        var ambiguous = await new AccountLicenseDevicesService(
            new DeviceCertAuthenticatedSessionService(account),
            ambiguousStore,
            new DeviceCertThrowingRemote(
                deactivateError: new HttpRequestException(
                    "certified ambiguous device mutation")))
            .DeactivateAsync(
                new AccountLicenseDeviceDeactivateRequest(
                    "device-ambiguous",
                    LicenseHandle,
                    DeviceHandle),
                CancellationToken.None);
        Require(
            ambiguous.Status == "OUTCOME_UNKNOWN" &&
            ambiguous.Error?.Code ==
                "LICENSE_DEVICE_DEACTIVATE_OUTCOME_UNKNOWN" &&
            !ambiguous.Error.Retryable &&
            ambiguousStore.State is ActiveAccountSessionState,
            "ambiguous device mutation was made retryable or damaged valid Agent custody");

        var forbidden = await new AccountLicenseDevicesService(
            new DeviceCertAuthenticatedSessionService(account),
            DeviceCertStore.Active(account),
            new DeviceCertRemote(
                new RemoteAccountLicenseDevicesResult(
                    "account_forbidden",
                    ErrorCode: "ACCOUNT_FORBIDDEN"),
                new RemoteAccountLicenseDeviceDeactivateResult(
                    "account_forbidden",
                    ErrorCode: "ACCOUNT_FORBIDDEN")))
            .GetAsync(
                new AccountLicenseDevicesRequest(
                    "device-forbidden",
                    LicenseHandle),
                CancellationToken.None);
        Require(
            forbidden.Status == "FORBIDDEN" &&
            forbidden.Error?.Code == "ACCOUNT_FORBIDDEN" &&
            !forbidden.Error.Retryable,
            "authorized-device selected-account denial drifted");
    }

    private static async Task CertifyRemoteTransportAsync()
    {
        const string token = "device-transport-secret";

        var readHandler = new DeviceReadTransportHandler(
            HttpStatusCode.OK,
            """
            {
              "status":"ready",
              "license":{
                "product_name":"Render Dock",
                "edition_name":"Pro",
                "key_last_four":"ABCD",
                "max_devices":4,
                "active_devices":1,
                "license_id":"raw-license-id-must-not-leak"
              },
              "devices":[
                {
                  "label":"Studio workstation",
                  "operating_system":"Windows 11",
                  "architecture":"ARM64",
                  "last_seen_at":"2026-09-30T12:00:00.000Z",
                  "activated_at":"2026-09-29T12:00:00.000Z",
                  "active":true,
                  "management_handle":"bke-license-device-target-v1_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                  "device_id":"raw-device-id-must-not-leak",
                  "device_hash":"raw-device-hash-must-not-leak",
                  "machine_id_hint":"raw-machine-id-must-not-leak"
                },
                {
                  "label":"Retired workstation",
                  "operating_system":"Windows 11",
                  "architecture":"x64",
                  "last_seen_at":"2026-09-28T11:00:00.000Z",
                  "activated_at":"2026-09-20T12:00:00.000Z",
                  "active":false,
                  "management_handle":null
                }
              ]
            }
            """);

        using (var client = new HttpClient(readHandler))
        using (var remote = new AccountLicenseDevicesRemote(
            client,
            "https://devices-cert.example.test"))
        {
            var result = await remote.GetAsync(
                token,
                LicenseHandle,
                CancellationToken.None);
            Require(
                result.Status == "ready" &&
                result.License?.ActiveDevices == 1 &&
                result.Devices?.Count == 2 &&
                result.Devices[0].ManagementHandle == DeviceHandle &&
                readHandler.RequestCount == 1 &&
                readHandler.SawBearer &&
                readHandler.SawProtocol &&
                readHandler.SawExactIntent,
                "authorized-device remote read transport drifted");

            var wire = JsonSerializer.Serialize(result);
            Require(
                !wire.Contains(
                    "raw-device-hash-must-not-leak",
                    StringComparison.Ordinal) &&
                !wire.Contains(
                    "raw-machine-id-must-not-leak",
                    StringComparison.Ordinal) &&
                !wire.Contains(
                    "raw-device-id-must-not-leak",
                    StringComparison.Ordinal) &&
                !wire.Contains(
                    "raw-license-id-must-not-leak",
                    StringComparison.Ordinal),
                "authorized-device remote leaked ignored cloud authority fields");
        }

        var deactivateHandler =
            new DeviceDeactivateTransportHandler(
                HttpStatusCode.OK,
                """{"status":"deactivated"}""");
        using (var client = new HttpClient(deactivateHandler))
        using (var remote = new AccountLicenseDevicesRemote(
            client,
            "https://devices-cert.example.test"))
        {
            var result = await remote.DeactivateAsync(
                token,
                LicenseHandle,
                DeviceHandle,
                CancellationToken.None);
            Require(
                result.Status == "deactivated" &&
                deactivateHandler.RequestCount == 1 &&
                deactivateHandler.SawBearer &&
                deactivateHandler.SawProtocol &&
                deactivateHandler.SawExactIntent,
                "authorized-device remote mutation transport drifted");
        }

        var malformedHandle = new DeviceReadTransportHandler(
            HttpStatusCode.OK,
            """
            {
              "status":"ready",
              "license":{
                "product_name":"Render Dock",
                "edition_name":"Pro",
                "key_last_four":"ABCD",
                "max_devices":4,
                "active_devices":1
              },
              "devices":[
                {
                  "label":"Studio",
                  "operating_system":"Windows 11",
                  "architecture":"ARM64",
                  "last_seen_at":"2026-09-30T12:00:00.000Z",
                  "activated_at":"2026-09-29T12:00:00.000Z",
                  "active":true,
                  "management_handle":null
                }
              ]
            }
            """);
        using (var client = new HttpClient(malformedHandle))
        using (var remote = new AccountLicenseDevicesRemote(
            client,
            "https://devices-cert.example.test"))
        {
            await RequireThrowsAsync<InvalidDataException>(
                () => remote.GetAsync(
                    token,
                    LicenseHandle,
                    CancellationToken.None),
                "active authorized device without opaque management handle was accepted");
        }

        var redirect = new DeviceReadTransportHandler(
            HttpStatusCode.Redirect,
            "{}");
        using (var client = new HttpClient(redirect))
        using (var remote = new AccountLicenseDevicesRemote(
            client,
            "https://devices-cert.example.test"))
        {
            await RequireThrowsAsync<HttpRequestException>(
                () => remote.GetAsync(
                    token,
                    LicenseHandle,
                    CancellationToken.None),
                "authorized-device read redirect was accepted");
            Require(
                redirect.RequestCount == 1,
                "authorized-device read redirect was replayed");
        }

        var missingProtocol = new DeviceReadTransportHandler(
            HttpStatusCode.OK,
            """{"status":"ready"}""",
            includeProtocol: false);
        using (var client = new HttpClient(missingProtocol))
        using (var remote = new AccountLicenseDevicesRemote(
            client,
            "https://devices-cert.example.test"))
        {
            await RequireThrowsAsync<InvalidDataException>(
                () => remote.GetAsync(
                    token,
                    LicenseHandle,
                    CancellationToken.None),
                "authorized-device response without protocol version was accepted");
        }
    }

    private static RemoteAccountLicenseDevicesResult ReadyRemoteResult() =>
        new(
            "ready",
            new AccountLicenseDeviceInfo(
                "Render Dock",
                "Pro",
                "ABCD",
                4,
                1),
            [
                new AccountAuthorizedDevice(
                    "Studio workstation",
                    "Windows 11",
                    "ARM64",
                    "2026-09-30T12:00:00.000Z",
                    "2026-09-29T12:00:00.000Z",
                    true,
                    DeviceHandle),
                new AccountAuthorizedDevice(
                    "Retired workstation",
                    "Windows 11",
                    "x64",
                    "2026-09-28T11:00:00.000Z",
                    "2026-09-20T12:00:00.000Z",
                    false,
                    null),
            ]);

    private static async Task RequireThrowsAsync<TException>(
        Func<Task> action,
        string message)
        where TException : Exception
    {
        try
        {
            await action();
        }
        catch (TException)
        {
            return;
        }

        throw new InvalidOperationException(message);
    }

    private static void Require(
        bool condition,
        string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }
}

sealed class DeviceCertStore : IAccountSessionSecretStore
{
    public AccountSessionStoredState? State { get; private set; }

    private DeviceCertStore(AccountSessionStoredState? state)
    {
        State = state;
    }

    public static DeviceCertStore Active(
        AccountSessionAccount account) =>
        new(new ActiveAccountSessionState(
            "device-access-secret",
            "device-refresh-secret",
            "device-session",
            DateTimeOffset.UtcNow.AddMinutes(15),
            DateTimeOffset.UtcNow.AddDays(30),
            account));

    public Task<AccountSessionStoredState?> ReadAsync(
        CancellationToken cancellationToken) =>
        Task.FromResult(State);

    public Task WriteAsync(
        AccountSessionStoredState state,
        CancellationToken cancellationToken)
    {
        State = state;
        return Task.CompletedTask;
    }

    public Task ClearAsync(
        CancellationToken cancellationToken)
    {
        State = null;
        return Task.CompletedTask;
    }
}

sealed class DeviceCertAuthenticatedSessionService(
    AccountSessionAccount account) : IAccountSessionService
{
    public Task<AccountSessionStatusResponse> StatusAsync(
        AccountSessionStatusRequest request,
        CancellationToken cancellationToken) =>
        Task.FromResult(new AccountSessionStatusResponse(
            LocalAgentContract.AccountSessionCapabilityId,
            LocalAgentContract.AccountSessionContractVersion,
            "AUTHENTICATED",
            account,
            null));

    public Task<AccountSessionCompleteResponse> CompleteAsync(
        AccountSessionCompleteRequest request,
        CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task<AccountSessionStartResponse> StartAsync(
        AccountSessionStartRequest request,
        CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task<AccountSessionLogoutResponse> LogoutAsync(
        AccountSessionLogoutRequest request,
        CancellationToken cancellationToken) =>
        throw new NotSupportedException();
}

sealed class DeviceCertUnauthenticatedSessionService :
    IAccountSessionService
{
    public Task<AccountSessionStatusResponse> StatusAsync(
        AccountSessionStatusRequest request,
        CancellationToken cancellationToken) =>
        Task.FromResult(new AccountSessionStatusResponse(
            LocalAgentContract.AccountSessionCapabilityId,
            LocalAgentContract.AccountSessionContractVersion,
            "SIGNED_OUT",
            null,
            null));

    public Task<AccountSessionCompleteResponse> CompleteAsync(
        AccountSessionCompleteRequest request,
        CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task<AccountSessionStartResponse> StartAsync(
        AccountSessionStartRequest request,
        CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task<AccountSessionLogoutResponse> LogoutAsync(
        AccountSessionLogoutRequest request,
        CancellationToken cancellationToken) =>
        throw new NotSupportedException();
}

sealed class DeviceCertRemote(
    RemoteAccountLicenseDevicesResult readResult,
    RemoteAccountLicenseDeviceDeactivateResult deactivateResult) :
    IAccountLicenseDevicesRemote
{
    public int ReadCalls { get; private set; }
    public int DeactivateCalls { get; private set; }
    public string? LastAccessToken { get; private set; }
    public string? LastLicenseHandle { get; private set; }
    public string? LastDeviceHandle { get; private set; }

    public Task<RemoteAccountLicenseDevicesResult> GetAsync(
        string accessToken,
        string licenseManagementHandle,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ReadCalls += 1;
        LastAccessToken = accessToken;
        LastLicenseHandle = licenseManagementHandle;
        return Task.FromResult(readResult);
    }

    public Task<RemoteAccountLicenseDeviceDeactivateResult>
        DeactivateAsync(
            string accessToken,
            string licenseManagementHandle,
            string deviceManagementHandle,
            CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        DeactivateCalls += 1;
        LastAccessToken = accessToken;
        LastLicenseHandle = licenseManagementHandle;
        LastDeviceHandle = deviceManagementHandle;
        return Task.FromResult(deactivateResult);
    }
}

sealed class DeviceCertThrowingRemote(
    Exception? readError = null,
    Exception? deactivateError = null) :
    IAccountLicenseDevicesRemote
{
    public Task<RemoteAccountLicenseDevicesResult> GetAsync(
        string accessToken,
        string licenseManagementHandle,
        CancellationToken cancellationToken) =>
        Task.FromException<RemoteAccountLicenseDevicesResult>(
            readError ??
            new InvalidOperationException(
                "Device read error not configured."));

    public Task<RemoteAccountLicenseDeviceDeactivateResult>
        DeactivateAsync(
            string accessToken,
            string licenseManagementHandle,
            string deviceManagementHandle,
            CancellationToken cancellationToken) =>
        Task.FromException<RemoteAccountLicenseDeviceDeactivateResult>(
            deactivateError ??
            new InvalidOperationException(
                "Device deactivate error not configured."));
}

sealed class DeviceReadTransportHandler(
    HttpStatusCode statusCode,
    string json,
    bool includeProtocol = true) : HttpMessageHandler
{
    public int RequestCount { get; private set; }
    public bool SawBearer { get; private set; }
    public bool SawProtocol { get; private set; }
    public bool SawExactIntent { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        RequestCount += 1;
        SawBearer =
            request.Headers.Authorization?.Scheme == "Bearer" &&
            request.Headers.Authorization.Parameter ==
                "device-transport-secret";
        SawProtocol =
            request.Headers.TryGetValues(
                "x-bke-account-session-version",
                out var versions) &&
            versions.SingleOrDefault() ==
                AccountSessionRemote.ProtocolVersion;

        if (request.Content is not null)
        {
            var body = await request.Content.ReadAsStringAsync(
                cancellationToken);
            using var document = JsonDocument.Parse(body);
            var root = document.RootElement;
            var keys = root.EnumerateObject()
                .Select(property => property.Name)
                .ToHashSet(StringComparer.Ordinal);
            SawExactIntent =
                request.Method == HttpMethod.Post &&
                request.RequestUri?.AbsolutePath ==
                    "/api/agent-sessions/account/license-devices" &&
                keys.SetEquals(["management_handle"]) &&
                root.GetProperty(
                    "management_handle").GetString() ==
                    AccountLicenseDevicesCertificationAccessor.LicenseHandle;
        }

        var response = new HttpResponseMessage(statusCode)
        {
            Content = new StringContent(
                json,
                Encoding.UTF8,
                "application/json"),
        };
        if (includeProtocol &&
            (int)statusCode is not (>= 300 and <= 399))
        {
            response.Headers.TryAddWithoutValidation(
                "x-bke-account-session-version",
                AccountSessionRemote.ProtocolVersion);
        }

        return response;
    }
}

sealed class DeviceDeactivateTransportHandler(
    HttpStatusCode statusCode,
    string json) : HttpMessageHandler
{
    public int RequestCount { get; private set; }
    public bool SawBearer { get; private set; }
    public bool SawProtocol { get; private set; }
    public bool SawExactIntent { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        RequestCount += 1;
        SawBearer =
            request.Headers.Authorization?.Scheme == "Bearer" &&
            request.Headers.Authorization.Parameter ==
                "device-transport-secret";
        SawProtocol =
            request.Headers.TryGetValues(
                "x-bke-account-session-version",
                out var versions) &&
            versions.SingleOrDefault() ==
                AccountSessionRemote.ProtocolVersion;

        if (request.Content is not null)
        {
            var body = await request.Content.ReadAsStringAsync(
                cancellationToken);
            using var document = JsonDocument.Parse(body);
            var root = document.RootElement;
            var keys = root.EnumerateObject()
                .Select(property => property.Name)
                .ToHashSet(StringComparer.Ordinal);
            SawExactIntent =
                request.Method == HttpMethod.Post &&
                request.RequestUri?.AbsolutePath ==
                    "/api/agent-sessions/account/license-devices/manage" &&
                keys.SetEquals([
                    "license_management_handle",
                    "device_management_handle",
                ]) &&
                root.GetProperty(
                    "license_management_handle").GetString() ==
                    AccountLicenseDevicesCertificationAccessor.LicenseHandle &&
                root.GetProperty(
                    "device_management_handle").GetString() ==
                    AccountLicenseDevicesCertificationAccessor.DeviceHandle;
        }

        var response = new HttpResponseMessage(statusCode)
        {
            Content = new StringContent(
                json,
                Encoding.UTF8,
                "application/json"),
        };
        if ((int)statusCode is not (>= 300 and <= 399))
        {
            response.Headers.TryAddWithoutValidation(
                "x-bke-account-session-version",
                AccountSessionRemote.ProtocolVersion);
        }

        return response;
    }
}

static class AccountLicenseDevicesCertificationAccessor
{
    public static string LicenseHandle =>
        "bke-license-device-v1_" + new string('a', 64);

    public static string DeviceHandle =>
        "bke-license-device-target-v1_" + new string('b', 64);
}
