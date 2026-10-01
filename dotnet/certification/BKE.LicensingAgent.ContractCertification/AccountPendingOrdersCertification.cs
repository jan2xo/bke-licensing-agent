using System.Net;
using System.Text;
using System.Text.Json;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;
using BKE.LicensingAgent.Infrastructure;

static class AccountPendingOrdersCertification
{
    private const string ExpectedDigitalSolutionsSource =
        "b84965a513f6cdcd9574c8da8fef86785f5f207d";
    private static readonly string ContinueHandle =
        "bke-order-continue-v1_" + new string('a', 64);
    private static readonly string CancelHandle =
        "bke-order-cancel-v1_" + new string('b', 64);

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
            "Agent is not pinned to the merged Digital Solutions pending-order authority.");

        Require(
            LocalAgentContract.AccountPendingOrdersCapabilityId ==
                "bke.account-pending-orders" &&
            LocalAgentContract.AccountPendingOrdersContractVersion == 1 &&
            LocalAgentContract.AccountPendingOrderContinuePath ==
                "/v1/account/orders/continue" &&
            LocalAgentContract.AccountPendingOrderCancelPath ==
                "/v1/account/orders/cancel",
            "pending-order local capability drifted");

        Require(
            typeof(AccountPendingOrderContinueRequest)
                .GetProperties()
                .Select(property => property.Name)
                .SequenceEqual([
                    "CorrelationId",
                    "OrderContinueHandle",
                ]) &&
            typeof(AccountPendingOrderCancelRequest)
                .GetProperties()
                .Select(property => property.Name)
                .SequenceEqual([
                    "CorrelationId",
                    "OrderCancelHandle",
                ]),
            "pending-order request contract widened");

        foreach (var type in new[]
        {
            typeof(AccountPendingOrderContinueRequest),
            typeof(AccountPendingOrderCancelRequest),
            typeof(AccountPendingOrderContinueResponse),
            typeof(AccountPendingOrderCancelResponse),
            typeof(AccountPendingOrderError),
        })
        {
            Require(
                type.GetProperties().All(property =>
                    !property.Name.Equals(
                        "OrderId",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Equals(
                        "AccountId",
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
                $"pending-order local contract {type.Name} exposes cloud authority identifiers");
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
                "AccountPendingOrdersRemote.cs"));
        var serviceSource = File.ReadAllText(
            Path.Combine(
                "dotnet",
                "src",
                "BKE.LicensingAgent.Application",
                "AccountPendingOrdersService.cs"));

        Require(
            hostSource.Contains(
                "app.MapPost(LocalAgentContract.AccountPendingOrderContinuePath",
                StringComparison.Ordinal) &&
            hostSource.Contains(
                "app.MapPost(LocalAgentContract.AccountPendingOrderCancelPath",
                StringComparison.Ordinal) &&
            hostSource.Contains(
                "AddSingleton<IAccountPendingOrdersService>",
                StringComparison.Ordinal) &&
            hostSource.Contains(
                "AddSingleton<IAccountPendingOrdersRemote>",
                StringComparison.Ordinal),
            "Agent Host pending-order mediation wiring drifted");

        foreach (var endpoint in new[]
        {
            "/api/agent-sessions/account/orders/continue",
            "/api/agent-sessions/account/orders/cancel",
        })
        {
            Require(
                remoteSource.Contains(
                    endpoint,
                    StringComparison.Ordinal),
                $"pending-order remote endpoint drifted: {endpoint}");
        }

        Require(
            remoteSource.Contains(
                "new AuthenticationHeaderValue(",
                StringComparison.Ordinal) &&
            remoteSource.Contains(
                "\"Bearer\"",
                StringComparison.Ordinal) &&
            remoteSource.Contains(
                "accessToken",
                StringComparison.Ordinal) &&
            remoteSource.Contains(
                "\"x-bke-account-session-version\"",
                StringComparison.Ordinal) &&
            remoteSource.Contains(
                "AllowAutoRedirect = false",
                StringComparison.Ordinal) &&
            remoteSource.Contains(
                "HttpMethod.Post",
                StringComparison.Ordinal) &&
            !remoteSource.Contains(
                "order_id",
                StringComparison.OrdinalIgnoreCase),
            "pending-order remote lost bearer/protocol/no-redirect/opaque-intent boundary");

        Require(
            serviceSource.Contains(
                "\"OUTCOME_UNKNOWN\"",
                StringComparison.Ordinal) &&
            serviceSource.Contains(
                "\"ORDER_CONTINUE_OUTCOME_UNKNOWN\"",
                StringComparison.Ordinal) &&
            serviceSource.Contains(
                "\"ORDER_CANCEL_OUTCOME_UNKNOWN\"",
                StringComparison.Ordinal) &&
            serviceSource.Contains(
                "Refresh purchases before trying another order action.",
                StringComparison.Ordinal),
            "pending-order service lost single-attempt ambiguity handling");
    }

    private static async Task CertifyServiceBoundaryAsync()
    {
        var account = new AccountSessionAccount(
            "pending-order-user",
            "pending-order@example.test",
            "cloud-account-must-not-leak",
            "ORGANIZATION",
            "Pending Order Organization");

        var store = PendingOrderStore.Active(account);
        var remote = new PendingOrderRemote(
            new RemoteAccountPendingOrderContinueResult(
                "continued",
                "https://checkout.example.test/session"),
            new RemoteAccountPendingOrderCancelResult(
                "cancelled"));

        var service = new AccountPendingOrdersService(
            new PendingOrderAuthenticatedSessionService(
                account),
            store,
            remote);

        var continued = await service.ContinueAsync(
            new AccountPendingOrderContinueRequest(
                "pending-order-continue-cert",
                ContinueHandle),
            CancellationToken.None);
        Require(
            continued.Status == "CONTINUED" &&
            continued.CheckoutUrl ==
                "https://checkout.example.test/session" &&
            remote.ContinueCalls == 1 &&
            remote.LastAccessToken ==
                "pending-order-access-secret" &&
            remote.LastContinueHandle == ContinueHandle,
            "pending-order continuation mediation drifted");

        var cancelled = await service.CancelAsync(
            new AccountPendingOrderCancelRequest(
                "pending-order-cancel-cert",
                CancelHandle),
            CancellationToken.None);
        Require(
            cancelled.Status == "CANCELLED" &&
            remote.CancelCalls == 1 &&
            remote.LastCancelHandle == CancelHandle,
            "pending-order cancellation mediation drifted");

        var wire = JsonSerializer.Serialize(new
        {
            continued,
            cancelled,
        });
        foreach (var forbiddenValue in new[]
        {
            "pending-order-access-secret",
            "pending-order-refresh-secret",
            "cloud-account-must-not-leak",
            "raw-order-id-must-not-leak",
        })
        {
            Require(
                !wire.Contains(
                    forbiddenValue,
                    StringComparison.Ordinal),
                "pending-order response leaked Agent/cloud authority material");
        }

        var signedOutRemote = new PendingOrderRemote(
            new RemoteAccountPendingOrderContinueResult(
                "continued",
                "https://checkout.example.test/session"),
            new RemoteAccountPendingOrderCancelResult(
                "cancelled"));
        var signedOut = await new AccountPendingOrdersService(
            new PendingOrderUnauthenticatedSessionService(),
            PendingOrderStore.Active(account),
            signedOutRemote)
            .ContinueAsync(
                new AccountPendingOrderContinueRequest(
                    "pending-order-signed-out",
                    ContinueHandle),
                CancellationToken.None);
        Require(
            signedOut.Status == "AUTH_REQUIRED" &&
            signedOutRemote.ContinueCalls == 0 &&
            signedOutRemote.CancelCalls == 0,
            "signed-out pending-order flow reached cloud authority");

        var invalidStore = PendingOrderStore.Active(account);
        var invalid = await new AccountPendingOrdersService(
            new PendingOrderAuthenticatedSessionService(
                account),
            invalidStore,
            new PendingOrderThrowingRemote(
                continueError:
                    new UnauthorizedAccessException(
                        "certified invalid bearer")))
            .ContinueAsync(
                new AccountPendingOrderContinueRequest(
                    "pending-order-invalid-token",
                    ContinueHandle),
                CancellationToken.None);
        Require(
            invalid.Status == "AUTH_REQUIRED" &&
            invalid.Error?.Code == "SESSION_INVALID" &&
            invalidStore.State is null,
            "invalid pending-order bearer did not clear Agent session custody");

        var ambiguousContinueStore =
            PendingOrderStore.Active(account);
        var ambiguousContinue =
            await new AccountPendingOrdersService(
                new PendingOrderAuthenticatedSessionService(
                    account),
                ambiguousContinueStore,
                new PendingOrderThrowingRemote(
                    continueError:
                        new HttpRequestException(
                            "certified ambiguous continuation")))
            .ContinueAsync(
                new AccountPendingOrderContinueRequest(
                    "pending-order-continue-ambiguous",
                    ContinueHandle),
                CancellationToken.None);
        Require(
            ambiguousContinue.Status == "OUTCOME_UNKNOWN" &&
            ambiguousContinue.Error?.Code ==
                "ORDER_CONTINUE_OUTCOME_UNKNOWN" &&
            !ambiguousContinue.Error.Retryable &&
            ambiguousContinueStore.State is
                ActiveAccountSessionState,
            "ambiguous pending-order continuation became retryable or damaged Agent custody");

        var ambiguousCancelStore =
            PendingOrderStore.Active(account);
        var ambiguousCancel =
            await new AccountPendingOrdersService(
                new PendingOrderAuthenticatedSessionService(
                    account),
                ambiguousCancelStore,
                new PendingOrderThrowingRemote(
                    cancelError:
                        new TaskCanceledException(
                            "certified ambiguous cancellation")))
            .CancelAsync(
                new AccountPendingOrderCancelRequest(
                    "pending-order-cancel-ambiguous",
                    CancelHandle),
                CancellationToken.None);
        Require(
            ambiguousCancel.Status == "OUTCOME_UNKNOWN" &&
            ambiguousCancel.Error?.Code ==
                "ORDER_CANCEL_OUTCOME_UNKNOWN" &&
            !ambiguousCancel.Error.Retryable &&
            ambiguousCancelStore.State is
                ActiveAccountSessionState,
            "ambiguous pending-order cancellation became retryable or damaged Agent custody");

        var legal = await new AccountPendingOrdersService(
            new PendingOrderAuthenticatedSessionService(
                account),
            PendingOrderStore.Active(account),
            new PendingOrderRemote(
                new RemoteAccountPendingOrderContinueResult(
                    "legal_reacceptance_required",
                    ErrorCode:
                        "LEGAL_REACCEPTANCE_REQUIRED"),
                new RemoteAccountPendingOrderCancelResult(
                    "legal_acceptance_required",
                    ErrorCode:
                        "LEGAL_ACCEPTANCE_REQUIRED")))
            .ContinueAsync(
                new AccountPendingOrderContinueRequest(
                    "pending-order-legal",
                    ContinueHandle),
                CancellationToken.None);
        Require(
            legal.Status == "LEGAL_REACCEPTANCE_REQUIRED" &&
            legal.Error?.Code ==
                "LEGAL_REACCEPTANCE_REQUIRED",
            "pending-order continuation lost Legal reacceptance state");

        var forbidden = await new AccountPendingOrdersService(
            new PendingOrderAuthenticatedSessionService(
                account),
            PendingOrderStore.Active(account),
            new PendingOrderRemote(
                new RemoteAccountPendingOrderContinueResult(
                    "account_forbidden",
                    ErrorCode: "ACCOUNT_FORBIDDEN"),
                new RemoteAccountPendingOrderCancelResult(
                    "account_forbidden",
                    ErrorCode: "ACCOUNT_FORBIDDEN")))
            .CancelAsync(
                new AccountPendingOrderCancelRequest(
                    "pending-order-forbidden",
                    CancelHandle),
                CancellationToken.None);
        Require(
            forbidden.Status == "FORBIDDEN" &&
            forbidden.Error?.Code == "ACCOUNT_FORBIDDEN",
            "pending-order cancellation lost selected-account authorization denial");
    }

    private static async Task CertifyRemoteTransportAsync()
    {
        const string token =
            "pending-order-transport-secret";

        var continueHandler =
            new PendingOrderTransportHandler(
                HttpStatusCode.OK,
                """
                {
                  "status":"continued",
                  "checkout_url":"https://checkout.example.test/session",
                  "order_id":"raw-order-id-must-not-leak"
                }
                """,
                "/api/agent-sessions/account/orders/continue",
                "order_continue_handle",
                ContinueHandle,
                token);
        using (var client = new HttpClient(continueHandler))
        using (var remote = new AccountPendingOrdersRemote(
            client,
            "https://pending-orders-cert.example.test"))
        {
            var result = await remote.ContinueAsync(
                token,
                ContinueHandle,
                CancellationToken.None);
            Require(
                result.Status == "continued" &&
                result.CheckoutUrl ==
                    "https://checkout.example.test/session" &&
                continueHandler.RequestCount == 1 &&
                continueHandler.SawBearer &&
                continueHandler.SawProtocol &&
                continueHandler.SawExactIntent,
                "pending-order continuation transport drifted");

            Require(
                !JsonSerializer.Serialize(result).Contains(
                    "raw-order-id-must-not-leak",
                    StringComparison.Ordinal),
                "pending-order continuation propagated ignored raw order authority");
        }

        var cancelHandler =
            new PendingOrderTransportHandler(
                HttpStatusCode.OK,
                """{"status":"cancelled","order_id":"raw-order-id-must-not-leak"}""",
                "/api/agent-sessions/account/orders/cancel",
                "order_cancel_handle",
                CancelHandle,
                token);
        using (var client = new HttpClient(cancelHandler))
        using (var remote = new AccountPendingOrdersRemote(
            client,
            "https://pending-orders-cert.example.test"))
        {
            var result = await remote.CancelAsync(
                token,
                CancelHandle,
                CancellationToken.None);
            Require(
                result.Status == "cancelled" &&
                cancelHandler.RequestCount == 1 &&
                cancelHandler.SawBearer &&
                cancelHandler.SawProtocol &&
                cancelHandler.SawExactIntent,
                "pending-order cancellation transport drifted");
        }

        var invalidHandleHandler =
            new PendingOrderTransportHandler(
                HttpStatusCode.OK,
                """{"status":"cancelled"}""",
                "/api/agent-sessions/account/orders/cancel",
                "order_cancel_handle",
                CancelHandle,
                token);
        using (var client =
            new HttpClient(invalidHandleHandler))
        using (var remote = new AccountPendingOrdersRemote(
            client,
            "https://pending-orders-cert.example.test"))
        {
            var result = await remote.CancelAsync(
                token,
                "raw-order-id-must-not-leak",
                CancellationToken.None);
            Require(
                result.Status == "invalid_input" &&
                invalidHandleHandler.RequestCount == 0,
                "pending-order remote sent malformed/raw order intent to Digital Solutions");
        }

        var unauthorized =
            new PendingOrderTransportHandler(
                HttpStatusCode.Unauthorized,
                """{"error":"INVALID_TOKEN"}""",
                "/api/agent-sessions/account/orders/continue",
                "order_continue_handle",
                ContinueHandle,
                token);
        using (var client = new HttpClient(unauthorized))
        using (var remote = new AccountPendingOrdersRemote(
            client,
            "https://pending-orders-cert.example.test"))
        {
            await RequireThrowsAsync<UnauthorizedAccessException>(
                () => remote.ContinueAsync(
                    token,
                    ContinueHandle,
                    CancellationToken.None),
                "pending-order invalid bearer was not rejected");
        }

        var limited =
            new PendingOrderTransportHandler(
                HttpStatusCode.TooManyRequests,
                """{"error":"RATE_LIMITED"}""",
                "/api/agent-sessions/account/orders/cancel",
                "order_cancel_handle",
                CancelHandle,
                token);
        using (var client = new HttpClient(limited))
        using (var remote = new AccountPendingOrdersRemote(
            client,
            "https://pending-orders-cert.example.test"))
        {
            var result = await remote.CancelAsync(
                token,
                CancelHandle,
                CancellationToken.None);
            Require(
                result.Status == "rate_limited" &&
                result.ErrorCode == "RATE_LIMITED" &&
                result.Retryable &&
                limited.RequestCount == 1,
                "pending-order rate-limit response drifted");
        }

        var redirect =
            new PendingOrderTransportHandler(
                HttpStatusCode.Redirect,
                "{}",
                "/api/agent-sessions/account/orders/cancel",
                "order_cancel_handle",
                CancelHandle,
                token);
        using (var client = new HttpClient(redirect))
        using (var remote = new AccountPendingOrdersRemote(
            client,
            "https://pending-orders-cert.example.test"))
        {
            await RequireThrowsAsync<HttpRequestException>(
                () => remote.CancelAsync(
                    token,
                    CancelHandle,
                    CancellationToken.None),
                "pending-order redirect was accepted");
            Require(
                redirect.RequestCount == 1,
                "pending-order redirect was replayed");
        }

        var malformedCheckout =
            new PendingOrderTransportHandler(
                HttpStatusCode.OK,
                """
                {
                  "status":"continued",
                  "checkout_url":"http://attacker.example.test/session"
                }
                """,
                "/api/agent-sessions/account/orders/continue",
                "order_continue_handle",
                ContinueHandle,
                token);
        using (var client =
            new HttpClient(malformedCheckout))
        using (var remote = new AccountPendingOrdersRemote(
            client,
            "https://pending-orders-cert.example.test"))
        {
            await RequireThrowsAsync<InvalidDataException>(
                () => remote.ContinueAsync(
                    token,
                    ContinueHandle,
                    CancellationToken.None),
                "pending-order continuation accepted an insecure non-loopback checkout URL");
        }

        var missingProtocol =
            new PendingOrderTransportHandler(
                HttpStatusCode.OK,
                """{"status":"cancelled"}""",
                "/api/agent-sessions/account/orders/cancel",
                "order_cancel_handle",
                CancelHandle,
                token,
                includeProtocol: false);
        using (var client =
            new HttpClient(missingProtocol))
        using (var remote = new AccountPendingOrdersRemote(
            client,
            "https://pending-orders-cert.example.test"))
        {
            await RequireThrowsAsync<InvalidDataException>(
                () => remote.CancelAsync(
                    token,
                    CancelHandle,
                    CancellationToken.None),
                "pending-order response without protocol version was accepted");
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

sealed class PendingOrderStore : IAccountSessionSecretStore
{
    public AccountSessionStoredState? State { get; private set; }

    private PendingOrderStore(
        AccountSessionStoredState? state)
    {
        State = state;
    }

    public static PendingOrderStore Active(
        AccountSessionAccount account) =>
        new(new ActiveAccountSessionState(
            "pending-order-access-secret",
            "pending-order-refresh-secret",
            "pending-order-session",
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

sealed class PendingOrderAuthenticatedSessionService(
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

sealed class PendingOrderUnauthenticatedSessionService :
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

sealed class PendingOrderRemote(
    RemoteAccountPendingOrderContinueResult continueResult,
    RemoteAccountPendingOrderCancelResult cancelResult) :
    IAccountPendingOrdersRemote
{
    public int ContinueCalls { get; private set; }
    public int CancelCalls { get; private set; }
    public string? LastAccessToken { get; private set; }
    public string? LastContinueHandle { get; private set; }
    public string? LastCancelHandle { get; private set; }

    public Task<RemoteAccountPendingOrderContinueResult>
        ContinueAsync(
            string accessToken,
            string orderContinueHandle,
            CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ContinueCalls += 1;
        LastAccessToken = accessToken;
        LastContinueHandle = orderContinueHandle;
        return Task.FromResult(continueResult);
    }

    public Task<RemoteAccountPendingOrderCancelResult>
        CancelAsync(
            string accessToken,
            string orderCancelHandle,
            CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        CancelCalls += 1;
        LastAccessToken = accessToken;
        LastCancelHandle = orderCancelHandle;
        return Task.FromResult(cancelResult);
    }
}

sealed class PendingOrderThrowingRemote(
    Exception? continueError = null,
    Exception? cancelError = null) :
    IAccountPendingOrdersRemote
{
    public Task<RemoteAccountPendingOrderContinueResult>
        ContinueAsync(
            string accessToken,
            string orderContinueHandle,
            CancellationToken cancellationToken) =>
        Task.FromException<RemoteAccountPendingOrderContinueResult>(
            continueError ??
            new InvalidOperationException(
                "Pending-order continuation error not configured."));

    public Task<RemoteAccountPendingOrderCancelResult>
        CancelAsync(
            string accessToken,
            string orderCancelHandle,
            CancellationToken cancellationToken) =>
        Task.FromException<RemoteAccountPendingOrderCancelResult>(
            cancelError ??
            new InvalidOperationException(
                "Pending-order cancellation error not configured."));
}

sealed class PendingOrderTransportHandler(
    HttpStatusCode statusCode,
    string json,
    string expectedPath,
    string expectedProperty,
    string expectedValue,
    string expectedToken,
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
                expectedToken;
        SawProtocol =
            request.Headers.TryGetValues(
                "x-bke-account-session-version",
                out var versions) &&
            versions.SingleOrDefault() ==
                AccountSessionRemote.ProtocolVersion;

        var exactBody = false;
        if (request.Content is not null)
        {
            var body = await request.Content.ReadAsStringAsync(
                cancellationToken);
            using var document = JsonDocument.Parse(body);
            var root = document.RootElement;
            var properties = root.EnumerateObject().ToArray();
            exactBody =
                properties.Length == 1 &&
                properties[0].Name == expectedProperty &&
                properties[0].Value.ValueKind ==
                    JsonValueKind.String &&
                properties[0].Value.GetString() ==
                    expectedValue;
        }

        SawExactIntent =
            request.Method == HttpMethod.Post &&
            request.RequestUri?.AbsolutePath ==
                expectedPath &&
            exactBody;

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
