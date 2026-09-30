using System.Net;
using System.Text;
using System.Text.Json;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;
using BKE.LicensingAgent.Infrastructure;

static class AccountLicenseSeatsCertification
{
    private const string ExpectedDigitalSolutionsSource =
        "01035e8d57d4600b8b7199cee046fe45de3fb569";

    private static readonly string LicenseHandle =
        "bke-license-seat-v1_" + new string('a', 64);
    private static readonly string TargetHandle =
        "bke-license-seat-user-v1_" + new string('b', 64);

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
            "Agent is not pinned to the merged Digital Solutions license-seat authority.");

        Require(
            LocalAgentContract.AccountLicenseSeatsCapabilityId ==
                "bke.account-license-seats" &&
            LocalAgentContract.AccountLicenseSeatsContractVersion == 1 &&
            LocalAgentContract.AccountLicenseSeatsPath ==
                "/v1/account/license-seats" &&
            LocalAgentContract.AccountLicenseSeatsManagePath ==
                "/v1/account/license-seats/manage",
            "account license seat local capability drifted");

        Require(
            typeof(AccountLicenseSeatsRequest)
                .GetProperties()
                .Select(property => property.Name)
                .SequenceEqual([
                    "CorrelationId",
                    "LicenseManagementHandle",
                ]),
            "account license seat read request widened");

        Require(
            typeof(AccountLicenseSeatsManageRequest)
                .GetProperties()
                .Select(property => property.Name)
                .SequenceEqual([
                    "CorrelationId",
                    "Action",
                    "LicenseManagementHandle",
                    "TargetManagementHandle",
                ]),
            "account license seat mutation request widened");

        foreach (var type in new[]
        {
            typeof(AccountLicenseSeatsResponse),
            typeof(AccountLicenseSeatsManageResponse),
            typeof(AccountLicenseSeatInfo),
            typeof(AccountLicenseSeatTarget),
            typeof(AccountLicenseSeatsError),
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
                        "UserId",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Equals(
                        "LicenseId",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Equals(
                        "AssignmentId",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Equals(
                        "ProductId",
                        StringComparison.OrdinalIgnoreCase)),
                $"account license seat response {type.Name} exposes authority identifiers or secrets");
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
                "AccountLicenseSeatsRemote.cs"));
        var serviceSource = File.ReadAllText(
            Path.Combine(
                "dotnet",
                "src",
                "BKE.LicensingAgent.Application",
                "AccountLicenseSeatsService.cs"));

        Require(
            hostSource.Contains(
                "app.MapPost(LocalAgentContract.AccountLicenseSeatsPath",
                StringComparison.Ordinal) &&
            hostSource.Contains(
                "app.MapPost(LocalAgentContract.AccountLicenseSeatsManagePath",
                StringComparison.Ordinal) &&
            hostSource.Contains(
                "AddSingleton<IAccountLicenseSeatsService>",
                StringComparison.Ordinal) &&
            hostSource.Contains(
                "AddSingleton<IAccountLicenseSeatsRemote>",
                StringComparison.Ordinal),
            "Agent Host account license seat mediation wiring drifted");

        Require(
            remoteSource.Contains(
                "/api/agent-sessions/account/license-seats",
                StringComparison.Ordinal) &&
            remoteSource.Contains(
                "/api/agent-sessions/account/license-seats/manage",
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
            "Agent license seat remote lost bearer/protocol/single-attempt/redirect mediation");

        Require(
            !remoteSource.Contains("Console.", StringComparison.Ordinal) &&
            !serviceSource.Contains("Console.", StringComparison.Ordinal) &&
            !serviceSource.Contains("AgentDatabase", StringComparison.Ordinal) &&
            !serviceSource.Contains("File.", StringComparison.Ordinal),
            "Agent license seat mediation introduced logging or local persistence");
    }

    private static async Task CertifyServiceBoundaryAsync()
    {
        var account = new AccountSessionAccount(
            "seat-user",
            "seat@example.test",
            "cloud-account-must-not-leak",
            "ORGANIZATION",
            "Seat Organization");

        var store = SeatCertStore.Active(account);
        var remote = new SeatCertRemote(
            new RemoteAccountLicenseSeatsResult(
                "ready",
                new AccountLicenseSeatInfo(
                    "Render Dock",
                    "Pro",
                    "ABCD",
                    3,
                    2,
                    1),
                [
                    new AccountLicenseSeatTarget(
                        "member@example.test",
                        "Member",
                        true,
                        true,
                        TargetHandle),
                ]),
            new RemoteAccountLicenseSeatsManageResult(
                "assigned"));

        var service = new AccountLicenseSeatsService(
            new SeatCertAuthenticatedSessionService(account),
            store,
            remote);

        var read = await service.GetAsync(
            new AccountLicenseSeatsRequest(
                "seat-read-cert",
                LicenseHandle),
            CancellationToken.None);

        Require(
            read.Status == "READY" &&
            read.License?.ProductName == "Render Dock" &&
            read.License.MaxSeats == 3 &&
            read.License.AssignedSeats == 2 &&
            read.License.AvailableSeats == 1 &&
            read.Targets.Count == 1 &&
            read.Targets[0].ManagementHandle == TargetHandle &&
            remote.ReadCalls == 1 &&
            remote.LastAccessToken == "seat-access-secret" &&
            remote.LastLicenseHandle == LicenseHandle,
            "account license seat read mediation drifted");

        var managed = await service.ManageAsync(
            new AccountLicenseSeatsManageRequest(
                "seat-manage-cert",
                "ASSIGN",
                LicenseHandle,
                TargetHandle),
            CancellationToken.None);

        Require(
            managed.Status == "ASSIGNED" &&
            remote.ManageCalls == 1 &&
            remote.LastAction == "ASSIGN" &&
            remote.LastTargetHandle == TargetHandle,
            "account license seat mutation mediation drifted");

        var wire = JsonSerializer.Serialize(new
        {
            read,
            managed,
        });
        foreach (var forbidden in new[]
        {
            "seat-access-secret",
            "seat-refresh-secret",
            "cloud-account-must-not-leak",
            "raw-license-id-must-not-leak",
            "raw-user-id-must-not-leak",
        })
        {
            Require(
                !wire.Contains(
                    forbidden,
                    StringComparison.Ordinal),
                "account license seat response leaked Agent/cloud authority material");
        }

        var unauthenticatedRemote = new SeatCertRemote(
            new RemoteAccountLicenseSeatsResult("ready"),
            new RemoteAccountLicenseSeatsManageResult(
                "assigned"));
        var unauthenticated = new AccountLicenseSeatsService(
            new SeatCertUnauthenticatedSessionService(),
            SeatCertStore.Active(account),
            unauthenticatedRemote);

        var denied = await unauthenticated.GetAsync(
            new AccountLicenseSeatsRequest(
                "seat-auth-cert",
                LicenseHandle),
            CancellationToken.None);
        Require(
            denied.Status == "AUTH_REQUIRED" &&
            unauthenticatedRemote.ReadCalls == 0,
            "account license seat read called Digital Solutions without authenticated Agent custody");

        var invalidStore = SeatCertStore.Active(account);
        var invalidService = new AccountLicenseSeatsService(
            new SeatCertAuthenticatedSessionService(account),
            invalidStore,
            new SeatCertThrowingRemote(
                readError: new UnauthorizedAccessException(
                    "certified invalid seat bearer")));

        var invalid = await invalidService.GetAsync(
            new AccountLicenseSeatsRequest(
                "seat-invalid-session",
                LicenseHandle),
            CancellationToken.None);
        Require(
            invalid.Status == "AUTH_REQUIRED" &&
            invalid.Error?.Code == "SESSION_INVALID" &&
            invalidStore.State is null,
            "invalid license seat bearer did not clear Agent session custody");

        var readFailureStore = SeatCertStore.Active(account);
        var readFailureService = new AccountLicenseSeatsService(
            new SeatCertAuthenticatedSessionService(account),
            readFailureStore,
            new SeatCertThrowingRemote(
                readError: new HttpRequestException(
                    "certified seat read outage")));

        var unavailable = await readFailureService.GetAsync(
            new AccountLicenseSeatsRequest(
                "seat-read-failure",
                LicenseHandle),
            CancellationToken.None);
        Require(
            unavailable.Status == "FAILED" &&
            unavailable.Error?.Code ==
                "LICENSE_SEATS_UNAVAILABLE" &&
            unavailable.Error.Retryable &&
            readFailureStore.State is ActiveAccountSessionState,
            "read-only seat failure did not preserve valid Agent custody");

        var mutationFailureStore = SeatCertStore.Active(account);
        var mutationFailureService =
            new AccountLicenseSeatsService(
                new SeatCertAuthenticatedSessionService(account),
                mutationFailureStore,
                new SeatCertThrowingRemote(
                    manageError: new HttpRequestException(
                        "certified ambiguous seat mutation")));

        var unknown = await mutationFailureService.ManageAsync(
            new AccountLicenseSeatsManageRequest(
                "seat-mutation-failure",
                "REMOVE",
                LicenseHandle,
                TargetHandle),
            CancellationToken.None);
        Require(
            unknown.Status == "OUTCOME_UNKNOWN" &&
            unknown.Error?.Code ==
                "LICENSE_SEAT_MANAGE_OUTCOME_UNKNOWN" &&
            !unknown.Error.Retryable &&
            mutationFailureStore.State is ActiveAccountSessionState,
            "ambiguous seat mutation became retryable or cleared valid custody");

        var conflictService = new AccountLicenseSeatsService(
            new SeatCertAuthenticatedSessionService(account),
            SeatCertStore.Active(account),
            new SeatCertRemote(
                new RemoteAccountLicenseSeatsResult("ready"),
                new RemoteAccountLicenseSeatsManageResult(
                    "license_seat_limit",
                    ErrorCode: "LICENSE_SEAT_LIMIT")));

        var conflict = await conflictService.ManageAsync(
            new AccountLicenseSeatsManageRequest(
                "seat-conflict",
                "ASSIGN",
                LicenseHandle,
                TargetHandle),
            CancellationToken.None);
        Require(
            conflict.Status == "CONFLICT" &&
            conflict.Error?.Code == "LICENSE_SEAT_LIMIT" &&
            !conflict.Error.Retryable,
            "authoritative seat-capacity conflict drifted");
    }

    private static async Task CertifyRemoteTransportAsync()
    {
        const string token = "seat-transport-secret";

        var readHandler = new SeatReadTransportHandler(
            HttpStatusCode.OK,
            $$"""
            {
              "status":"ready",
              "license":{
                "product_name":"Render Dock",
                "edition_name":"Pro",
                "key_last_four":"ABCD",
                "max_seats":3,
                "assigned_seats":2,
                "available_seats":1,
                "license_id":"raw-license-id-must-not-leak"
              },
              "targets":[
                {
                  "email":"member@example.test",
                  "name":"Member",
                  "assigned":true,
                  "eligible":true,
                  "management_handle":"{{TargetHandle}}",
                  "user_id":"raw-user-id-must-not-leak"
                }
              ]
            }
            """);

        using (var client = new HttpClient(readHandler))
        using (var remote = new AccountLicenseSeatsRemote(
            client,
            "https://seat-cert.example.test"))
        {
            var result = await remote.GetAsync(
                token,
                LicenseHandle,
                CancellationToken.None);

            Require(
                result.Status == "ready" &&
                result.License?.AssignedSeats == 2 &&
                result.Targets?.Count == 1 &&
                readHandler.RequestCount == 1 &&
                readHandler.SawBearer &&
                readHandler.SawProtocol &&
                readHandler.SawExactIntent,
                "account license seat read transport boundary drifted");

            var wire = JsonSerializer.Serialize(result);
            Require(
                !wire.Contains(
                    "raw-license-id-must-not-leak",
                    StringComparison.Ordinal) &&
                !wire.Contains(
                    "raw-user-id-must-not-leak",
                    StringComparison.Ordinal),
                "account license seat remote propagated ignored authority fields");
        }

        var manageHandler = new SeatManageTransportHandler(
            HttpStatusCode.OK,
            """{"status":"removed"}""");

        using (var client = new HttpClient(manageHandler))
        using (var remote = new AccountLicenseSeatsRemote(
            client,
            "https://seat-cert.example.test"))
        {
            var result = await remote.ManageAsync(
                token,
                "REMOVE",
                LicenseHandle,
                TargetHandle,
                CancellationToken.None);

            Require(
                result.Status == "removed" &&
                manageHandler.RequestCount == 1 &&
                manageHandler.SawBearer &&
                manageHandler.SawProtocol &&
                manageHandler.SawExactIntent,
                "account license seat mutation transport boundary drifted");
        }

        var ambiguousHandler = new SeatManageTransportHandler(
            HttpStatusCode.OK,
            "{}",
            throwTransport: true);
        using (var client = new HttpClient(ambiguousHandler))
        using (var remote = new AccountLicenseSeatsRemote(
            client,
            "https://seat-cert.example.test"))
        {
            await RequireThrowsAsync<HttpRequestException>(
                () => remote.ManageAsync(
                    token,
                    "ASSIGN",
                    LicenseHandle,
                    TargetHandle,
                    CancellationToken.None),
                "account license seat mutation swallowed ambiguous transport failure");
            Require(
                ambiguousHandler.RequestCount == 1,
                "account license seat mutation was blindly replayed");
        }

        var unauthorizedHandler = new SeatReadTransportHandler(
            HttpStatusCode.Unauthorized,
            """{"error":"INVALID_TOKEN"}""");
        using (var client = new HttpClient(unauthorizedHandler))
        using (var remote = new AccountLicenseSeatsRemote(
            client,
            "https://seat-cert.example.test"))
        {
            await RequireThrowsAsync<UnauthorizedAccessException>(
                () => remote.GetAsync(
                    token,
                    LicenseHandle,
                    CancellationToken.None),
                "account license seat invalid bearer was not rejected");
        }

        var redirectHandler = new SeatReadTransportHandler(
            HttpStatusCode.Redirect,
            "{}",
            includeProtocol: false);
        using (var client = new HttpClient(redirectHandler))
        using (var remote = new AccountLicenseSeatsRemote(
            client,
            "https://seat-cert.example.test"))
        {
            await RequireThrowsAsync<HttpRequestException>(
                () => remote.GetAsync(
                    token,
                    LicenseHandle,
                    CancellationToken.None),
                "account license seat redirect was not rejected");
            Require(
                redirectHandler.RequestCount == 1,
                "account license seat redirect was replayed");
        }
    }

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

sealed class SeatCertStore : IAccountSessionSecretStore
{
    public AccountSessionStoredState? State { get; private set; }

    private SeatCertStore(AccountSessionStoredState? state)
    {
        State = state;
    }

    public static SeatCertStore Active(
        AccountSessionAccount account) =>
        new(new ActiveAccountSessionState(
            "seat-access-secret",
            "seat-refresh-secret",
            "seat-session",
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

sealed class SeatCertAuthenticatedSessionService(
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

sealed class SeatCertUnauthenticatedSessionService :
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

sealed class SeatCertRemote(
    RemoteAccountLicenseSeatsResult readResult,
    RemoteAccountLicenseSeatsManageResult manageResult) :
    IAccountLicenseSeatsRemote
{
    public int ReadCalls { get; private set; }
    public int ManageCalls { get; private set; }
    public string? LastAccessToken { get; private set; }
    public string? LastLicenseHandle { get; private set; }
    public string? LastTargetHandle { get; private set; }
    public string? LastAction { get; private set; }

    public Task<RemoteAccountLicenseSeatsResult> GetAsync(
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

    public Task<RemoteAccountLicenseSeatsManageResult> ManageAsync(
        string accessToken,
        string action,
        string licenseManagementHandle,
        string targetManagementHandle,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ManageCalls += 1;
        LastAccessToken = accessToken;
        LastAction = action;
        LastLicenseHandle = licenseManagementHandle;
        LastTargetHandle = targetManagementHandle;
        return Task.FromResult(manageResult);
    }
}

sealed class SeatCertThrowingRemote(
    Exception? readError = null,
    Exception? manageError = null) :
    IAccountLicenseSeatsRemote
{
    public Task<RemoteAccountLicenseSeatsResult> GetAsync(
        string accessToken,
        string licenseManagementHandle,
        CancellationToken cancellationToken) =>
        Task.FromException<RemoteAccountLicenseSeatsResult>(
            readError ??
            new InvalidOperationException(
                "Seat read error not configured."));

    public Task<RemoteAccountLicenseSeatsManageResult> ManageAsync(
        string accessToken,
        string action,
        string licenseManagementHandle,
        string targetManagementHandle,
        CancellationToken cancellationToken) =>
        Task.FromException<RemoteAccountLicenseSeatsManageResult>(
            manageError ??
            new InvalidOperationException(
                "Seat mutation error not configured."));
}

sealed class SeatReadTransportHandler(
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
                "seat-transport-secret";
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
                    "/api/agent-sessions/account/license-seats" &&
                keys.SetEquals(["management_handle"]) &&
                root.GetProperty("management_handle").GetString() ==
                    AccountLicenseSeatsCertificationAccessor.LicenseHandle;
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

sealed class SeatManageTransportHandler(
    HttpStatusCode statusCode,
    string json,
    bool throwTransport = false) : HttpMessageHandler
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
                "seat-transport-secret";
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
                    "/api/agent-sessions/account/license-seats/manage" &&
                keys.SetEquals([
                    "action",
                    "license_management_handle",
                    "target_management_handle",
                ]) &&
                root.GetProperty("action").GetString() == "remove" &&
                root.GetProperty(
                    "license_management_handle").GetString() ==
                    AccountLicenseSeatsCertificationAccessor.LicenseHandle &&
                root.GetProperty(
                    "target_management_handle").GetString() ==
                    AccountLicenseSeatsCertificationAccessor.TargetHandle;
        }

        if (throwTransport)
        {
            throw new HttpRequestException(
                "certified ambiguous seat mutation");
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

static class AccountLicenseSeatsCertificationAccessor
{
    public static string LicenseHandle =>
        "bke-license-seat-v1_" + new string('a', 64);

    public static string TargetHandle =>
        "bke-license-seat-user-v1_" + new string('b', 64);
}
