using System.Net;
using System.Text;
using System.Text.Json;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;
using BKE.LicensingAgent.Infrastructure;

static class AccountPrivacyCertification
{
    public static async Task RunAsync()
    {
        CertifyStaticBoundaries();
        await CertifyServiceBoundaryAsync();
        await CertifyRemoteTransportAsync();
    }

    private static void CertifyStaticBoundaries()
    {
        Require(
            LocalAgentContract.AccountPrivacyCapabilityId ==
                "bke.account-privacy" &&
            LocalAgentContract.AccountPrivacyContractVersion == 1,
            "account privacy capability/version drifted");
        Require(
            LocalAgentContract.AccountPrivacyListPath ==
                "/v1/account/privacy/requests/list" &&
            LocalAgentContract.AccountPrivacyCreatePath ==
                "/v1/account/privacy/requests/create",
            "account privacy loopback paths drifted");

        var listFields = typeof(AccountPrivacyListRequest)
            .GetProperties()
            .Select(property => property.Name)
            .ToArray();
        Require(
            listFields.SequenceEqual(["CorrelationId", "Limit"]),
            "account privacy list request widened");

        var createFields = typeof(AccountPrivacyCreateRequest)
            .GetProperties()
            .Select(property => property.Name)
            .ToArray();
        Require(
            createFields.SequenceEqual([
                "CorrelationId",
                "RequestType",
                "Summary",
            ]),
            "account privacy create request widened");

        foreach (var type in new[]
        {
            typeof(AccountPrivacyListResponse),
            typeof(AccountPrivacyCreateResponse),
            typeof(AccountPrivacyItem),
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
                        StringComparison.OrdinalIgnoreCase)),
                $"account privacy local response {type.Name} exposes authority/session material");
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
                "AccountPrivacyRemote.cs"));
        var serviceSource = File.ReadAllText(
            Path.Combine(
                "dotnet",
                "src",
                "BKE.LicensingAgent.Application",
                "AccountPrivacyService.cs"));

        Require(
            hostSource.Contains(
                "app.MapPost(LocalAgentContract.AccountPrivacyListPath",
                StringComparison.Ordinal) &&
            hostSource.Contains(
                "app.MapPost(LocalAgentContract.AccountPrivacyCreatePath",
                StringComparison.Ordinal) &&
            hostSource.Contains(
                "AddSingleton<IAccountPrivacyService>",
                StringComparison.Ordinal) &&
            hostSource.Contains(
                "AddSingleton<IAccountPrivacyRemote>",
                StringComparison.Ordinal),
            "Agent Host account privacy mediation wiring drifted");

        Require(
            remoteSource.Contains(
                "/api/agent-sessions/privacy/requests",
                StringComparison.Ordinal) &&
            remoteSource.Contains(
                "new AuthenticationHeaderValue(\"Bearer\", accessToken)",
                StringComparison.Ordinal) &&
            remoteSource.Contains(
                "\"x-bke-account-session-version\"",
                StringComparison.Ordinal) &&
            remoteSource.Contains(
                "AllowAutoRedirect = false",
                StringComparison.Ordinal),
            "Agent account privacy remote lost bearer/protocol/redirect mediation");

        Require(
            remoteSource.Contains(
                "Privacy create is deliberately single-attempt",
                StringComparison.Ordinal) &&
            !remoteSource.Contains(
                "for (var attempt",
                StringComparison.Ordinal),
            "Agent account privacy create became retryable");

        Require(
            !remoteSource.Contains("Console.", StringComparison.Ordinal) &&
            !serviceSource.Contains("Console.", StringComparison.Ordinal) &&
            !serviceSource.Contains("AgentDatabase", StringComparison.Ordinal) &&
            !serviceSource.Contains("File.", StringComparison.Ordinal),
            "Agent account privacy mediation introduced logging or local persistence");
    }

    private static async Task CertifyServiceBoundaryAsync()
    {
        var account = new AccountSessionAccount(
            "privacy-user",
            "privacy@example.test",
            "privacy-account",
            "INDIVIDUAL",
            "Privacy User");

        var listItem = new RemoteAccountPrivacyItem(
            "privacy-request-1",
            "ACCOUNT",
            "ACCESS",
            "OPEN",
            "Please provide the personal data associated with this account.",
            null,
            null,
            null,
            "2026-09-29T12:00:00.000Z");

        var store = PrivacyStore.Active(account);
        var remote = new FakeAccountPrivacyRemote(
            new RemoteAccountPrivacyResult(
                "ok",
                RequestTypes: ["ACCESS", "EXPORT", "DELETION"],
                Items: [listItem]),
            new RemoteAccountPrivacyResult(
                "created",
                RequestId: "privacy-request-2",
                RequestType: "EXPORT",
                RequestStatus: "OPEN"));
        var service = new AccountPrivacyService(
            new PrivacyAuthenticatedSessionService(account),
            store,
            remote);

        var list = await service.ListAsync(
            new AccountPrivacyListRequest(
                "privacy-list-cert",
                50),
            CancellationToken.None);
        Require(
            list.Status == "READY" &&
            list.RequestTypes.SequenceEqual([
                "ACCESS",
                "EXPORT",
                "DELETION",
            ]) &&
            list.Items.Count == 1 &&
            list.Items[0].Id == "privacy-request-1",
            "account privacy list mediation drifted");
        Require(
            remote.ListCalls == 1 &&
            remote.LastAccessToken == "privacy-access-secret" &&
            remote.LastLimit == 50,
            "account privacy list did not use Agent-owned session custody");

        var listWire = JsonSerializer.Serialize(list);
        Require(
            !listWire.Contains(
                "privacy-access-secret",
                StringComparison.Ordinal) &&
            !listWire.Contains(
                "privacy-refresh-secret",
                StringComparison.Ordinal) &&
            !listWire.Contains(
                "privacy-account",
                StringComparison.Ordinal),
            "account privacy list leaked Agent/cloud authority material");

        var created = await service.CreateAsync(
            new AccountPrivacyCreateRequest(
                "privacy-create-cert",
                "EXPORT",
                "Please export the personal data associated with this account."),
            CancellationToken.None);
        Require(
            created.Status == "CREATED" &&
            created.RequestId == "privacy-request-2" &&
            created.RequestType == "EXPORT" &&
            created.RequestStatus == "OPEN",
            "account privacy create mediation drifted");
        Require(
            remote.CreateCalls == 1 &&
            remote.LastRequestType == "EXPORT" &&
            remote.LastSummary ==
                "Please export the personal data associated with this account.",
            "account privacy create intent drifted");
        Require(
            store.State is ActiveAccountSessionState,
            "successful privacy request unexpectedly destroyed Agent session custody");

        var unauthenticatedRemote = new FakeAccountPrivacyRemote(
            new RemoteAccountPrivacyResult(
                "ok",
                RequestTypes: ["ACCESS"],
                Items: []),
            new RemoteAccountPrivacyResult("created"));
        var unauthenticated = new AccountPrivacyService(
            new PrivacyUnauthenticatedSessionService(),
            PrivacyStore.Active(account),
            unauthenticatedRemote);
        var denied = await unauthenticated.ListAsync(
            new AccountPrivacyListRequest(
                "privacy-auth-cert",
                10),
            CancellationToken.None);
        Require(
            denied.Status == "AUTH_REQUIRED" &&
            unauthenticatedRemote.ListCalls == 0,
            "account privacy called Digital Solutions without authenticated Agent custody");

        var invalidStore = PrivacyStore.Active(account);
        var invalidRemote = new ThrowingAccountPrivacyRemote(
            new UnauthorizedAccessException(
                "certified invalid bearer"));
        var invalidService = new AccountPrivacyService(
            new PrivacyAuthenticatedSessionService(account),
            invalidStore,
            invalidRemote);
        var invalid = await invalidService.ListAsync(
            new AccountPrivacyListRequest(
                "privacy-invalid-session",
                10),
            CancellationToken.None);
        Require(
            invalid.Status == "AUTH_REQUIRED" &&
            invalidStore.State is null,
            "invalid privacy bearer did not clear Agent session custody");

        var listFailureStore = PrivacyStore.Active(account);
        var listFailure = new AccountPrivacyService(
            new PrivacyAuthenticatedSessionService(account),
            listFailureStore,
            new ThrowingAccountPrivacyRemote(
                new HttpRequestException(
                    "certified privacy list outage")));
        var unavailable = await listFailure.ListAsync(
            new AccountPrivacyListRequest(
                "privacy-list-failure",
                10),
            CancellationToken.None);
        Require(
            unavailable.Status == "FAILED" &&
            listFailureStore.State is ActiveAccountSessionState,
            "read-only privacy failure destroyed a valid Agent session");

        var ambiguousStore = PrivacyStore.Active(account);
        var ambiguousRemote = new FakeAccountPrivacyRemote(
            new RemoteAccountPrivacyResult(
                "ok",
                RequestTypes: ["ACCESS"],
                Items: []),
            null,
            new HttpRequestException(
                "certified ambiguous privacy create"));
        var ambiguousService = new AccountPrivacyService(
            new PrivacyAuthenticatedSessionService(account),
            ambiguousStore,
            ambiguousRemote);
        var ambiguous = await ambiguousService.CreateAsync(
            new AccountPrivacyCreateRequest(
                "privacy-ambiguous-create",
                "ACCESS",
                "Please provide the data associated with this account."),
            CancellationToken.None);
        Require(
            ambiguous.Status == "OUTCOME_UNKNOWN" &&
            ambiguous.Error?.Code ==
                "PRIVACY_CREATE_OUTCOME_UNKNOWN" &&
            ambiguousRemote.CreateCalls == 1,
            "ambiguous privacy create did not fail closed without replay");
        Require(
            ambiguousStore.State is ActiveAccountSessionState,
            "ambiguous privacy create unnecessarily destroyed Agent session custody");
    }

    private static async Task CertifyRemoteTransportAsync()
    {
        const string token = "privacy-transport-secret";

        var listHandler = new PrivacyTransportHandler(
            HttpStatusCode.OK,
            """
            {
              "status":"ok",
              "account_id":"cloud-account-hidden",
              "request_types":["ACCESS","EXPORT"],
              "requests":[
                {
                  "id":"privacy-wire-1",
                  "scope":"ACCOUNT",
                  "request_type":"ACCESS",
                  "status":"OPEN",
                  "summary":"Please provide the personal data held for this account.",
                  "response_summary":null,
                  "reviewed_at":null,
                  "closed_at":null,
                  "created_at":"2026-09-29T12:00:00.000Z"
                }
              ]
            }
            """);
        using (var client = new HttpClient(listHandler))
        using (var remote = new AccountPrivacyRemote(
            client,
            "https://privacy-cert.example.test"))
        {
            var result = await remote.ListAsync(
                token,
                25,
                CancellationToken.None);
            Require(
                result.Status == "ok" &&
                result.Items?.Count == 1 &&
                listHandler.RequestCount == 1 &&
                listHandler.SawBearer &&
                listHandler.SawProtocol &&
                listHandler.SawListRequest &&
                listHandler.SawNoBody,
                "account privacy list transport boundary drifted");
        }

        var createHandler = new PrivacyTransportHandler(
            HttpStatusCode.Created,
            """
            {
              "status":"created",
              "account_id":"cloud-account-hidden",
              "request":{
                "id":"privacy-wire-2",
                "request_type":"EXPORT",
                "status":"OPEN"
              }
            }
            """);
        using (var client = new HttpClient(createHandler))
        using (var remote = new AccountPrivacyRemote(
            client,
            "https://privacy-cert.example.test"))
        {
            var result = await remote.CreateAsync(
                token,
                "EXPORT",
                "Please export the personal data associated with this account.",
                CancellationToken.None);
            Require(
                result.Status == "created" &&
                result.RequestId == "privacy-wire-2" &&
                createHandler.RequestCount == 1 &&
                createHandler.SawBearer &&
                createHandler.SawProtocol &&
                createHandler.SawCreateRequest &&
                createHandler.SawCreateBody,
                "account privacy create transport boundary drifted");
        }

        var redirectHandler = new PrivacyTransportHandler(
            HttpStatusCode.Redirect,
            "{}");
        using (var client = new HttpClient(redirectHandler))
        using (var remote = new AccountPrivacyRemote(
            client,
            "https://privacy-cert.example.test"))
        {
            await RequireThrowsAsync<HttpRequestException>(
                () => remote.CreateAsync(
                    token,
                    "ACCESS",
                    "Please provide the personal data associated with this account.",
                    CancellationToken.None),
                "account privacy create redirect was not rejected");
            Require(
                redirectHandler.RequestCount == 1,
                "account privacy create redirect was replayed");
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

    private static void Require(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }
}

sealed class PrivacyStore : IAccountSessionSecretStore
{
    public AccountSessionStoredState? State { get; private set; }

    private PrivacyStore(AccountSessionStoredState? state)
    {
        State = state;
    }

    public static PrivacyStore Active(AccountSessionAccount account) =>
        new(new ActiveAccountSessionState(
            "privacy-access-secret",
            "privacy-refresh-secret",
            "privacy-session",
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

    public Task ClearAsync(CancellationToken cancellationToken)
    {
        State = null;
        return Task.CompletedTask;
    }
}

sealed class PrivacyAuthenticatedSessionService(
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

sealed class PrivacyUnauthenticatedSessionService : IAccountSessionService
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

sealed class FakeAccountPrivacyRemote(
    RemoteAccountPrivacyResult listResult,
    RemoteAccountPrivacyResult? createResult,
    Exception? createException = null) : IAccountPrivacyRemote
{
    public int ListCalls { get; private set; }
    public int CreateCalls { get; private set; }
    public string? LastAccessToken { get; private set; }
    public int? LastLimit { get; private set; }
    public string? LastRequestType { get; private set; }
    public string? LastSummary { get; private set; }

    public Task<RemoteAccountPrivacyResult> ListAsync(
        string accessToken,
        int limit,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ListCalls += 1;
        LastAccessToken = accessToken;
        LastLimit = limit;
        return Task.FromResult(listResult);
    }

    public Task<RemoteAccountPrivacyResult> CreateAsync(
        string accessToken,
        string requestType,
        string summary,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        CreateCalls += 1;
        LastAccessToken = accessToken;
        LastRequestType = requestType;
        LastSummary = summary;
        if (createException is not null)
        {
            throw createException;
        }
        return Task.FromResult(
            createResult ??
            new RemoteAccountPrivacyResult(
                "privacy_unavailable",
                ErrorCode: "PRIVACY_UNAVAILABLE",
                Retryable: true));
    }
}

sealed class ThrowingAccountPrivacyRemote(
    Exception error) : IAccountPrivacyRemote
{
    public Task<RemoteAccountPrivacyResult> ListAsync(
        string accessToken,
        int limit,
        CancellationToken cancellationToken) =>
        Task.FromException<RemoteAccountPrivacyResult>(error);

    public Task<RemoteAccountPrivacyResult> CreateAsync(
        string accessToken,
        string requestType,
        string summary,
        CancellationToken cancellationToken) =>
        Task.FromException<RemoteAccountPrivacyResult>(error);
}

sealed class PrivacyTransportHandler(
    HttpStatusCode statusCode,
    string json) : HttpMessageHandler
{
    public int RequestCount { get; private set; }
    public bool SawBearer { get; private set; }
    public bool SawProtocol { get; private set; }
    public bool SawListRequest { get; private set; }
    public bool SawNoBody { get; private set; }
    public bool SawCreateRequest { get; private set; }
    public bool SawCreateBody { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        RequestCount += 1;
        SawBearer =
            request.Headers.Authorization?.Scheme == "Bearer" &&
            request.Headers.Authorization.Parameter ==
                "privacy-transport-secret";
        SawProtocol =
            request.Headers.TryGetValues(
                "x-bke-account-session-version",
                out var versions) &&
            versions.SingleOrDefault() ==
                AccountSessionRemote.ProtocolVersion;

        SawListRequest =
            request.Method == HttpMethod.Get &&
            request.RequestUri?.AbsolutePath ==
                "/api/agent-sessions/privacy/requests" &&
            request.RequestUri?.Query == "?limit=25";
        SawNoBody =
            request.Method != HttpMethod.Get ||
            request.Content is null;

        SawCreateRequest =
            request.Method == HttpMethod.Post &&
            request.RequestUri?.AbsolutePath ==
                "/api/agent-sessions/privacy/requests";

        if (SawCreateRequest && request.Content is not null)
        {
            var body = await request.Content.ReadAsStringAsync(
                cancellationToken);
            using var document = JsonDocument.Parse(body);
            var root = document.RootElement;
            var keys = root.EnumerateObject()
                .Select(property => property.Name)
                .ToHashSet(StringComparer.Ordinal);

            SawCreateBody =
                keys.SetEquals(["request_type", "summary"]) &&
                root.GetProperty("request_type").GetString() ==
                    "EXPORT" &&
                root.GetProperty("summary").GetString() ==
                    "Please export the personal data associated with this account.";
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
