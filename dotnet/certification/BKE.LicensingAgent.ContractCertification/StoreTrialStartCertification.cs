using System.Net;
using System.Text;
using System.Text.Json;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;
using BKE.LicensingAgent.Infrastructure;

static class StoreTrialStartCertification
{
    private const string ExpectedDigitalSolutionsSource =
        "b84965a513f6cdcd9574c8da8fef86785f5f207d";

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
            "Agent is not pinned to the merged Digital Solutions trial authority.");

        Require(
            LocalAgentContract.StoreTrialStartCapabilityId ==
                "bke.store-trial-start" &&
            LocalAgentContract.StoreTrialStartContractVersion == 1 &&
            LocalAgentContract.StoreTrialStartPath ==
                "/v1/store/trials/start",
            "Store trial-start local capability drifted");

        Require(
            typeof(StoreTrialStartRequest)
                .GetProperties()
                .Select(property => property.Name)
                .SequenceEqual([
                    "CorrelationId",
                    "EditionId",
                ]),
            "Store trial-start request widened");

        foreach (var type in new[]
        {
            typeof(StoreTrialStartRequest),
            typeof(StoreTrialStartResponse),
            typeof(StoreTrialStartError),
        })
        {
            Require(
                type.GetProperties().All(property =>
                    !property.Name.Equals(
                        "TrialId",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Equals(
                        "LicenseId",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Equals(
                        "OrderId",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Equals(
                        "AccountId",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Equals(
                        "UserId",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Contains(
                        "AccessToken",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Contains(
                        "RefreshToken",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Contains(
                        "Payment",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Contains(
                        "Provider",
                        StringComparison.OrdinalIgnoreCase)),
                $"Store trial-start contract {type.Name} exposes cloud or secret authority");
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
                "StoreTrialStartRemote.cs"));
        var serviceSource = File.ReadAllText(
            Path.Combine(
                "dotnet",
                "src",
                "BKE.LicensingAgent.Application",
                "StoreTrialStartService.cs"));

        Require(
            hostSource.Contains(
                "app.MapPost(LocalAgentContract.StoreTrialStartPath",
                StringComparison.Ordinal) &&
            hostSource.Contains(
                "AddSingleton<IStoreTrialStartService>",
                StringComparison.Ordinal) &&
            hostSource.Contains(
                "AddSingleton<IStoreTrialStartRemote>",
                StringComparison.Ordinal),
            "Store trial-start Host mediation wiring drifted");

        Require(
            remoteSource.Contains(
                "/api/agent-sessions/store/trials/start",
                StringComparison.Ordinal) &&
            remoteSource.Contains(
                "HttpMethod.Post",
                StringComparison.Ordinal) &&
            remoteSource.Contains(
                "new AuthenticationHeaderValue",
                StringComparison.Ordinal) &&
            remoteSource.Contains(
                "\"x-bke-account-session-version\"",
                StringComparison.Ordinal) &&
            remoteSource.Contains(
                "AllowAutoRedirect = false",
                StringComparison.Ordinal) &&
            remoteSource.Contains(
                "correlation_id = request.CorrelationId",
                StringComparison.Ordinal) &&
            remoteSource.Contains(
                "edition_id = request.EditionId",
                StringComparison.Ordinal) &&
            remoteSource.Split(
                "SendAsync(",
                StringSplitOptions.None).Length == 2,
            "Store trial-start remote lost strict single-attempt bearer/protocol transport");

        Require(
            !serviceSource.Contains(
                "Console.",
                StringComparison.Ordinal) &&
            !serviceSource.Contains(
                "AgentDatabase",
                StringComparison.Ordinal) &&
            !serviceSource.Contains(
                "File.",
                StringComparison.Ordinal) &&
            serviceSource.Contains(
                "\"RESULT_UNKNOWN\"",
                StringComparison.Ordinal) &&
            serviceSource.Contains(
                "No automatic retry",
                StringComparison.OrdinalIgnoreCase),
            "Store trial-start service lost no-persistence or ambiguity boundary");
    }

    private static async Task CertifyServiceBoundaryAsync()
    {
        var account = new AccountSessionAccount(
            "trial-user",
            "trial@example.test",
            "cloud-account-must-not-leak",
            "INDIVIDUAL",
            "Trial Customer");
        var store = TrialStore.Active(account);
        var remote = new FakeStoreTrialStartRemote(
            new RemoteStoreTrialStartResult(
                "started",
                "trial-correlation-cert",
                "2026-10-08T00:00:00.000Z",
                "2026-10-08T00:00:00.000Z"));
        var service = new StoreTrialStartService(
            new TrialAuthenticatedSessionService(account),
            store,
            remote);

        var response = await service.StartAsync(
            new StoreTrialStartRequest(
                "trial-correlation-cert",
                "cmtrialeditioncert000000000001"),
            CancellationToken.None);

        Require(
            response.Status == "STARTED" &&
            response.CorrelationId ==
                "trial-correlation-cert" &&
            response.TrialEndsAt ==
                "2026-10-08T00:00:00.000Z" &&
            response.GraceEndsAt ==
                "2026-10-08T00:00:00.000Z" &&
            response.Error is null &&
            remote.Calls == 1 &&
            remote.LastAccessToken ==
                "trial-access-secret",
            "Store trial-start service success mediation drifted");

        var wire = JsonSerializer.Serialize(response);
        foreach (var forbidden in new[]
        {
            "trial-access-secret",
            "trial-refresh-secret",
            "cloud-account-must-not-leak",
        })
        {
            Require(
                !wire.Contains(
                    forbidden,
                    StringComparison.Ordinal),
                "Store trial-start response leaked Agent/cloud secret material");
        }

        var ambiguousRemote =
            new ThrowingStoreTrialStartRemote(
                new HttpRequestException(
                    "certified ambiguous transport"));
        var ambiguous = await new StoreTrialStartService(
            new TrialAuthenticatedSessionService(account),
            TrialStore.Active(account),
            ambiguousRemote)
            .StartAsync(
                new StoreTrialStartRequest(
                    "trial-ambiguous-cert",
                    "cmtrialeditioncert000000000001"),
                CancellationToken.None);

        Require(
            ambiguous.Status == "RESULT_UNKNOWN" &&
            ambiguous.Error?.Code ==
                "TRIAL_START_RESULT_UNKNOWN" &&
            ambiguous.Error.Retryable == false &&
            ambiguousRemote.Calls == 1,
            "Store trial-start ambiguity was replayed or marked retryable");

        var invalidStore = TrialStore.Active(account);
        var unauthorizedRemote =
            new ThrowingStoreTrialStartRemote(
                new UnauthorizedAccessException(
                    "certified invalid bearer"));
        var unauthorized = await new StoreTrialStartService(
            new TrialAuthenticatedSessionService(account),
            invalidStore,
            unauthorizedRemote)
            .StartAsync(
                new StoreTrialStartRequest(
                    "trial-auth-cert",
                    "cmtrialeditioncert000000000001"),
                CancellationToken.None);

        Require(
            unauthorized.Status == "AUTH_REQUIRED" &&
            unauthorized.Error?.Code == "SESSION_INVALID" &&
            invalidStore.State is null &&
            unauthorizedRemote.Calls == 1,
            "Store trial-start invalid bearer did not clear Agent session custody");

        var signedOutRemote = new FakeStoreTrialStartRemote(
            new RemoteStoreTrialStartResult(
                "started",
                "unused"));
        var signedOut = await new StoreTrialStartService(
            new TrialUnauthenticatedSessionService(),
            TrialStore.Active(account),
            signedOutRemote)
            .StartAsync(
                new StoreTrialStartRequest(
                    "trial-signed-out-cert",
                    "cmtrialeditioncert000000000001"),
                CancellationToken.None);

        Require(
            signedOut.Status == "AUTH_REQUIRED" &&
            signedOutRemote.Calls == 0,
            "Signed-out Store trial-start reached cloud authority");
    }

    private static async Task CertifyRemoteTransportAsync()
    {
        const string token = "trial-transport-secret";

        var success = new TrialTransportHandler(
            HttpStatusCode.Created,
            """
            {
              "status":"started",
              "correlation_id":"trial-transport-cert",
              "trial_ends_at":"2026-10-08T00:00:00.000Z",
              "grace_ends_at":"2026-10-08T00:00:00.000Z"
            }
            """,
            token);

        using (var client = new HttpClient(success))
        using (var remote = new StoreTrialStartRemote(
            client,
            "https://trial-cert.example.test"))
        {
            var result = await remote.StartAsync(
                token,
                new StoreTrialStartRequest(
                    "trial-transport-cert",
                    "cmtrialeditioncert000000000001"),
                CancellationToken.None);

            Require(
                result.Status == "started" &&
                result.CorrelationId ==
                    "trial-transport-cert" &&
                result.TrialEndsAt ==
                    "2026-10-08T00:00:00.000Z" &&
                success.RequestCount == 1 &&
                success.SawBearer &&
                success.SawProtocol &&
                success.SawExpectedPath &&
                success.SawNarrowBody,
                "Store trial-start remote transport drifted");
        }

        var widened = new TrialTransportHandler(
            HttpStatusCode.Created,
            """
            {
              "status":"started",
              "correlation_id":"trial-transport-cert",
              "trial_ends_at":"2026-10-08T00:00:00.000Z",
              "grace_ends_at":"2026-10-08T00:00:00.000Z",
              "trial_id":"raw-trial-id-must-not-cross"
            }
            """,
            token);
        using (var client = new HttpClient(widened))
        using (var remote = new StoreTrialStartRemote(
            client,
            "https://trial-cert.example.test"))
        {
            await RequireThrowsAsync<InvalidDataException>(
                () => remote.StartAsync(
                    token,
                    new StoreTrialStartRequest(
                        "trial-transport-cert",
                        "cmtrialeditioncert000000000001"),
                    CancellationToken.None),
                "Store trial-start remote accepted widened raw identifier response");
        }

        var unauthorized = new TrialTransportHandler(
            HttpStatusCode.Unauthorized,
            """{"error":"INVALID_TOKEN"}""",
            token);
        using (var client = new HttpClient(unauthorized))
        using (var remote = new StoreTrialStartRemote(
            client,
            "https://trial-cert.example.test"))
        {
            await RequireThrowsAsync<UnauthorizedAccessException>(
                () => remote.StartAsync(
                    token,
                    new StoreTrialStartRequest(
                        "trial-auth-cert-0001",
                        "cmtrialeditioncert000000000001"),
                    CancellationToken.None),
                "Store trial-start invalid bearer was accepted");
        }

        var redirect = new TrialTransportHandler(
            HttpStatusCode.Redirect,
            "{}",
            token,
            includeProtocol: false);
        using (var client = new HttpClient(redirect))
        using (var remote = new StoreTrialStartRemote(
            client,
            "https://trial-cert.example.test"))
        {
            await RequireThrowsAsync<HttpRequestException>(
                () => remote.StartAsync(
                    token,
                    new StoreTrialStartRequest(
                        "trial-redirect-cert",
                        "cmtrialeditioncert000000000001"),
                    CancellationToken.None),
                "Store trial-start redirect was accepted");
            Require(
                redirect.RequestCount == 1,
                "Store trial-start redirect was replayed");
        }

        var missingProtocol = new TrialTransportHandler(
            HttpStatusCode.Created,
            """
            {
              "status":"started",
              "correlation_id":"trial-protocol-cert",
              "trial_ends_at":"2026-10-08T00:00:00.000Z",
              "grace_ends_at":"2026-10-08T00:00:00.000Z"
            }
            """,
            token,
            includeProtocol: false);
        using (var client = new HttpClient(missingProtocol))
        using (var remote = new StoreTrialStartRemote(
            client,
            "https://trial-cert.example.test"))
        {
            await RequireThrowsAsync<InvalidDataException>(
                () => remote.StartAsync(
                    token,
                    new StoreTrialStartRequest(
                        "trial-protocol-cert",
                        "cmtrialeditioncert000000000001"),
                    CancellationToken.None),
                "Store trial-start response without protocol was accepted");
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

sealed class TrialStore : IAccountSessionSecretStore
{
    public AccountSessionStoredState? State { get; private set; }

    private TrialStore(AccountSessionStoredState? state)
    {
        State = state;
    }

    public static TrialStore Active(
        AccountSessionAccount account) =>
        new(new ActiveAccountSessionState(
            "trial-access-secret",
            "trial-refresh-secret",
            "trial-session",
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

sealed class TrialAuthenticatedSessionService(
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

sealed class TrialUnauthenticatedSessionService :
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

sealed class FakeStoreTrialStartRemote(
    RemoteStoreTrialStartResult result) :
    IStoreTrialStartRemote
{
    public int Calls { get; private set; }
    public string? LastAccessToken { get; private set; }

    public Task<RemoteStoreTrialStartResult> StartAsync(
        string accessToken,
        StoreTrialStartRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Calls += 1;
        LastAccessToken = accessToken;
        return Task.FromResult(result);
    }
}

sealed class ThrowingStoreTrialStartRemote(
    Exception error) : IStoreTrialStartRemote
{
    public int Calls { get; private set; }

    public Task<RemoteStoreTrialStartResult> StartAsync(
        string accessToken,
        StoreTrialStartRequest request,
        CancellationToken cancellationToken)
    {
        Calls += 1;
        return Task.FromException<RemoteStoreTrialStartResult>(
            error);
    }
}

sealed class TrialTransportHandler(
    HttpStatusCode statusCode,
    string json,
    string expectedToken,
    bool includeProtocol = true) : HttpMessageHandler
{
    public int RequestCount { get; private set; }
    public bool SawBearer { get; private set; }
    public bool SawProtocol { get; private set; }
    public bool SawExpectedPath { get; private set; }
    public bool SawNarrowBody { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        RequestCount += 1;
        SawBearer =
            request.Headers.Authorization?.Scheme == "Bearer" &&
            request.Headers.Authorization.Parameter ==
                expectedToken;
        SawProtocol =
            request.Headers.TryGetValues(
                "x-bke-account-session-version",
                out var versions) &&
            versions.SingleOrDefault() ==
                AccountSessionRemote.ProtocolVersion;
        SawExpectedPath =
            request.Method == HttpMethod.Post &&
            request.RequestUri?.AbsolutePath ==
                "/api/agent-sessions/store/trials/start";

        if (request.Content is not null)
        {
            var body = await request.Content.ReadAsStringAsync(
                cancellationToken);
            using var document = JsonDocument.Parse(body);
            var keys = document.RootElement
                .EnumerateObject()
                .Select(property => property.Name)
                .ToHashSet(StringComparer.Ordinal);
            SawNarrowBody =
                keys.SetEquals([
                    "correlation_id",
                    "edition_id",
                ]) &&
                document.RootElement
                    .GetProperty("correlation_id")
                    .GetString() is not null &&
                document.RootElement
                    .GetProperty("edition_id")
                    .GetString() is not null;
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
