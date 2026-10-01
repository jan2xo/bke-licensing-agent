using System.Net;
using System.Text;
using System.Text.Json;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;
using BKE.LicensingAgent.Infrastructure;

static class AccountBillingCertification
{
    private const string ExpectedDigitalSolutionsSource =
        "e90689096583760e9959b95bbea030a9060acf48";

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
            "Agent is not pinned to the merged Digital Solutions billing authority.");

        Require(
            LocalAgentContract.AccountBillingCapabilityId ==
                "bke.account-billing" &&
            LocalAgentContract.AccountBillingContractVersion == 1 &&
            LocalAgentContract.AccountBillingPath ==
                "/v1/account/billing",
            "account billing local capability drifted");

        Require(
            typeof(AccountBillingRequest)
                .GetProperties()
                .Select(property => property.Name)
                .SequenceEqual(["CorrelationId"]),
            "account billing request widened");

        foreach (var type in new[]
        {
            typeof(AccountBillingResponse),
            typeof(AccountBillingAccount),
            typeof(AccountBillingPermissions),
            typeof(AccountBillingInvoice),
            typeof(AccountBillingInvoiceLine),
            typeof(AccountBillingPayment),
            typeof(AccountBillingError),
        })
        {
            Require(
                type.GetProperties().All(property =>
                    !property.Name.Equals(
                        "InvoiceId",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Equals(
                        "PaymentId",
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
                        "Provider",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Contains(
                        "External",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Contains(
                        "Checkout",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Contains(
                        "AccessToken",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Contains(
                        "RefreshToken",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Contains(
                        "Snapshot",
                        StringComparison.OrdinalIgnoreCase)),
                $"account billing local response {type.Name} exposes cloud/provider authority");
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
                "AccountBillingRemote.cs"));
        var serviceSource = File.ReadAllText(
            Path.Combine(
                "dotnet",
                "src",
                "BKE.LicensingAgent.Application",
                "AccountBillingService.cs"));

        Require(
            hostSource.Contains(
                "app.MapPost(LocalAgentContract.AccountBillingPath",
                StringComparison.Ordinal) &&
            hostSource.Contains(
                "AddSingleton<IAccountBillingService>",
                StringComparison.Ordinal) &&
            hostSource.Contains(
                "AddSingleton<IAccountBillingRemote>",
                StringComparison.Ordinal),
            "Agent Host account billing mediation wiring drifted");

        Require(
            remoteSource.Contains(
                "/api/agent-sessions/account/billing",
                StringComparison.Ordinal) &&
            remoteSource.Contains(
                "HttpMethod.Get",
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
            remoteSource.Contains(
                "MaximumInvoiceLines = 100",
                StringComparison.Ordinal) &&
            !remoteSource.Contains(
                "HttpMethod.Post",
                StringComparison.Ordinal),
            "Agent billing remote lost read-only bearer/protocol/bounds/no-redirect mediation");

        Require(
            !serviceSource.Contains("Console.", StringComparison.Ordinal) &&
            !serviceSource.Contains("AgentDatabase", StringComparison.Ordinal) &&
            !serviceSource.Contains("File.", StringComparison.Ordinal),
            "Agent billing service introduced logging or local persistence");
    }

    private static async Task CertifyServiceBoundaryAsync()
    {
        var account = new AccountSessionAccount(
            "billing-user",
            "billing@example.test",
            "cloud-account-must-not-leak",
            "ORGANIZATION",
            "Billing Organization");
        var store = BillingStore.Active(account);
        var remote = new FakeAccountBillingRemote(
            ReadyResult());
        var service = new AccountBillingService(
            new BillingAuthenticatedSessionService(account),
            store,
            remote);

        var response = await service.GetAsync(
            new AccountBillingRequest(
                "billing-cert"),
            CancellationToken.None);

        Require(
            response.Status == "READY" &&
            response.Account?.Role == "BILLING" &&
            response.Permissions?.ViewInvoices == true &&
            response.Permissions.ViewPayments &&
            response.Invoices.Count == 1 &&
            response.Invoices[0].Number == "INV-CERT-001" &&
            response.Invoices[0].Lines.Count == 1 &&
            response.Payments.Count == 1 &&
            response.Payments[0].Status == "PAID" &&
            remote.Calls == 1 &&
            remote.LastAccessToken ==
                "billing-access-secret",
            "account billing service mediation drifted");

        var wire = JsonSerializer.Serialize(response);
        foreach (var forbiddenValue in new[]
        {
            "billing-access-secret",
            "billing-refresh-secret",
            "cloud-account-must-not-leak",
            "provider-must-not-leak",
            "external-id-must-not-leak",
            "raw-order-id-must-not-leak",
        })
        {
            Require(
                !wire.Contains(
                    forbiddenValue,
                    StringComparison.Ordinal),
                "account billing response leaked Agent/cloud authority material");
        }

        var signedOutRemote = new FakeAccountBillingRemote(
            ReadyResult());
        var signedOut = await new AccountBillingService(
            new BillingUnauthenticatedSessionService(),
            BillingStore.Active(account),
            signedOutRemote)
            .GetAsync(
                new AccountBillingRequest(
                    "billing-signed-out"),
                CancellationToken.None);
        Require(
            signedOut.Status == "AUTH_REQUIRED" &&
            signedOutRemote.Calls == 0,
            "signed-out billing flow reached cloud authority");

        var invalidStore = BillingStore.Active(account);
        var invalid = await new AccountBillingService(
            new BillingAuthenticatedSessionService(account),
            invalidStore,
            new ThrowingAccountBillingRemote(
                new UnauthorizedAccessException(
                    "certified invalid bearer")))
            .GetAsync(
                new AccountBillingRequest(
                    "billing-invalid-token"),
                CancellationToken.None);
        Require(
            invalid.Status == "AUTH_REQUIRED" &&
            invalid.Error?.Code == "SESSION_INVALID" &&
            invalidStore.State is null,
            "invalid billing bearer did not clear Agent session custody");
    }

    private static async Task CertifyRemoteTransportAsync()
    {
        const string token = "billing-transport-secret";

        var success = new BillingTransportHandler(
            HttpStatusCode.OK,
            """
            {
              "status":"ready",
              "account":{
                "type":"ORGANIZATION",
                "display_name":"Billing Organization",
                "lifecycle_state":"ACTIVE",
                "role":"BILLING"
              },
              "permissions":{
                "view_invoices":true,
                "view_payments":true
              },
              "invoices":[
                {
                  "number":"INV-CERT-001",
                  "status":"FINAL",
                  "order_number":"ORD-CERT-001",
                  "currency":"PHP",
                  "subtotal_minor":30000000,
                  "tax_minor":0,
                  "total_minor":30000000,
                  "issued_at":"2026-10-01T01:05:00.000Z",
                  "created_at":"2026-10-01T01:04:00.000Z",
                  "invoice_id":"invoice-id-must-not-leak",
                  "customer_snapshot":"snapshot-must-not-leak",
                  "lines":[
                    {
                      "description":"Render Dock",
                      "quantity":1,
                      "unit_amount_minor":30000000,
                      "total_minor":30000000
                    }
                  ]
                }
              ],
              "payments":[
                {
                  "order_number":"ORD-CERT-001",
                  "status":"PAID",
                  "amount_minor":30000000,
                  "currency":"PHP",
                  "paid_at":"2026-10-01T01:00:00.000Z",
                  "created_at":"2026-10-01T00:59:00.000Z",
                  "provider":"provider-must-not-leak",
                  "external_id":"external-id-must-not-leak",
                  "order_id":"raw-order-id-must-not-leak"
                }
              ]
            }
            """,
            token);

        using (var client = new HttpClient(success))
        using (var remote = new AccountBillingRemote(
            client,
            "https://billing-cert.example.test"))
        {
            var result = await remote.GetAsync(
                token,
                CancellationToken.None);
            Require(
                result.Status == "ready" &&
                result.Invoices?.Count == 1 &&
                result.Payments?.Count == 1 &&
                success.RequestCount == 1 &&
                success.SawBearer &&
                success.SawProtocol &&
                success.SawReadOnlyPath,
                "account billing transport drifted");

            var wire = JsonSerializer.Serialize(result);
            foreach (var forbiddenValue in new[]
            {
                "invoice-id-must-not-leak",
                "snapshot-must-not-leak",
                "provider-must-not-leak",
                "external-id-must-not-leak",
                "raw-order-id-must-not-leak",
            })
            {
                Require(
                    !wire.Contains(
                        forbiddenValue,
                        StringComparison.Ordinal),
                    "billing transport propagated ignored cloud authority material");
            }
        }

        var permissionDrift = new BillingTransportHandler(
            HttpStatusCode.OK,
            """
            {
              "status":"ready",
              "account":{
                "type":"ORGANIZATION",
                "display_name":"License Organization",
                "lifecycle_state":"ACTIVE",
                "role":"LICENSE_MANAGER"
              },
              "permissions":{
                "view_invoices":false,
                "view_payments":false
              },
              "invoices":[],
              "payments":[
                {
                  "order_number":"ORD-CERT-001",
                  "status":"PAID",
                  "amount_minor":100,
                  "currency":"PHP",
                  "paid_at":null,
                  "created_at":"2026-10-01T00:59:00.000Z"
                }
              ]
            }
            """,
            token);
        using (var client = new HttpClient(permissionDrift))
        using (var remote = new AccountBillingRemote(
            client,
            "https://billing-cert.example.test"))
        {
            await RequireThrowsAsync<InvalidDataException>(
                () => remote.GetAsync(
                    token,
                    CancellationToken.None),
                "billing transport accepted payment history without permission");
        }

        var unauthorized = new BillingTransportHandler(
            HttpStatusCode.Unauthorized,
            """{"error":"INVALID_TOKEN"}""",
            token);
        using (var client = new HttpClient(unauthorized))
        using (var remote = new AccountBillingRemote(
            client,
            "https://billing-cert.example.test"))
        {
            await RequireThrowsAsync<UnauthorizedAccessException>(
                () => remote.GetAsync(
                    token,
                    CancellationToken.None),
                "billing invalid bearer was not rejected");
        }

        var redirect = new BillingTransportHandler(
            HttpStatusCode.Redirect,
            "{}",
            token);
        using (var client = new HttpClient(redirect))
        using (var remote = new AccountBillingRemote(
            client,
            "https://billing-cert.example.test"))
        {
            await RequireThrowsAsync<HttpRequestException>(
                () => remote.GetAsync(
                    token,
                    CancellationToken.None),
                "billing redirect was accepted");
            Require(
                redirect.RequestCount == 1,
                "billing redirect was replayed");
        }

        var missingProtocol = new BillingTransportHandler(
            HttpStatusCode.OK,
            """
            {
              "status":"ready",
              "account":{
                "type":"INDIVIDUAL",
                "display_name":"Billing User",
                "lifecycle_state":"ACTIVE",
                "role":"OWNER"
              },
              "permissions":{
                "view_invoices":true,
                "view_payments":true
              },
              "invoices":[],
              "payments":[]
            }
            """,
            token,
            includeProtocol: false);
        using (var client = new HttpClient(missingProtocol))
        using (var remote = new AccountBillingRemote(
            client,
            "https://billing-cert.example.test"))
        {
            await RequireThrowsAsync<InvalidDataException>(
                () => remote.GetAsync(
                    token,
                    CancellationToken.None),
                "billing response without protocol version was accepted");
        }
    }

    private static RemoteAccountBillingResult ReadyResult() =>
        new(
            "ready",
            new AccountBillingAccount(
                "ORGANIZATION",
                "Billing Organization",
                "ACTIVE",
                "BILLING"),
            new AccountBillingPermissions(
                true,
                true),
            [
                new AccountBillingInvoice(
                    "INV-CERT-001",
                    "FINAL",
                    "ORD-CERT-001",
                    "PHP",
                    30000000,
                    0,
                    30000000,
                    "2026-10-01T01:05:00.000Z",
                    "2026-10-01T01:04:00.000Z",
                    [
                        new AccountBillingInvoiceLine(
                            "Render Dock",
                            1,
                            30000000,
                            30000000),
                    ]),
            ],
            [
                new AccountBillingPayment(
                    "ORD-CERT-001",
                    "PAID",
                    30000000,
                    "PHP",
                    "2026-10-01T01:00:00.000Z",
                    "2026-10-01T00:59:00.000Z"),
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

sealed class BillingStore : IAccountSessionSecretStore
{
    public AccountSessionStoredState? State { get; private set; }

    private BillingStore(
        AccountSessionStoredState? state)
    {
        State = state;
    }

    public static BillingStore Active(
        AccountSessionAccount account) =>
        new(new ActiveAccountSessionState(
            "billing-access-secret",
            "billing-refresh-secret",
            "billing-session",
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

sealed class BillingAuthenticatedSessionService(
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

sealed class BillingUnauthenticatedSessionService :
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

sealed class FakeAccountBillingRemote(
    RemoteAccountBillingResult result) :
    IAccountBillingRemote
{
    public int Calls { get; private set; }
    public string? LastAccessToken { get; private set; }

    public Task<RemoteAccountBillingResult> GetAsync(
        string accessToken,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Calls += 1;
        LastAccessToken = accessToken;
        return Task.FromResult(result);
    }
}

sealed class ThrowingAccountBillingRemote(
    Exception error) : IAccountBillingRemote
{
    public Task<RemoteAccountBillingResult> GetAsync(
        string accessToken,
        CancellationToken cancellationToken) =>
        Task.FromException<RemoteAccountBillingResult>(
            error);
}

sealed class BillingTransportHandler(
    HttpStatusCode statusCode,
    string json,
    string expectedToken,
    bool includeProtocol = true) : HttpMessageHandler
{
    public int RequestCount { get; private set; }
    public bool SawBearer { get; private set; }
    public bool SawProtocol { get; private set; }
    public bool SawReadOnlyPath { get; private set; }

    protected override Task<HttpResponseMessage> SendAsync(
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
        SawReadOnlyPath =
            request.Method == HttpMethod.Get &&
            request.RequestUri?.AbsolutePath ==
                "/api/agent-sessions/account/billing" &&
            request.Content is null;

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

        return Task.FromResult(response);
    }
}
