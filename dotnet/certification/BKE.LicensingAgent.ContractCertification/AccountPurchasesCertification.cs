using System.Net;
using System.Text;
using System.Text.Json;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;
using BKE.LicensingAgent.Infrastructure;

static class AccountPurchasesCertification
{
    private const string ExpectedDigitalSolutionsSource =
        "01035e8d57d4600b8b7199cee046fe45de3fb569";

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
            "Agent is not pinned to the merged Digital Solutions purchases authority.");

        Require(
            LocalAgentContract.AccountPurchasesCapabilityId ==
                "bke.account-purchases" &&
            LocalAgentContract.AccountPurchasesContractVersion == 1 &&
            LocalAgentContract.AccountPurchasesPath ==
                "/v1/account/purchases",
            "account purchases local capability drifted");

        Require(
            typeof(AccountPurchasesRequest)
                .GetProperties()
                .Select(property => property.Name)
                .SequenceEqual(["CorrelationId"]),
            "account purchases request widened");

        foreach (var type in new[]
        {
            typeof(AccountPurchasesResponse),
            typeof(AccountPurchasesAccount),
            typeof(AccountPurchasesPermissions),
            typeof(AccountPurchasesLicense),
            typeof(AccountPurchasesSubscription),
            typeof(AccountPurchasesOrder),
            typeof(AccountPurchasesOrderItem),
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
                    !property.Name.Contains(
                        "CheckoutUrl",
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
                        "OrderId",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Equals(
                        "SubscriptionId",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Equals(
                        "InvoiceId",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Equals(
                        "DeviceId",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Equals(
                        "LicenseKey",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Contains(
                        "Payment",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Contains(
                        "Provider",
                        StringComparison.OrdinalIgnoreCase)),
                $"account purchases local response {type.Name} exposes authority or payment material");
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
                "AccountPurchasesRemote.cs"));
        var serviceSource = File.ReadAllText(
            Path.Combine(
                "dotnet",
                "src",
                "BKE.LicensingAgent.Application",
                "AccountPurchasesService.cs"));

        Require(
            hostSource.Contains(
                "app.MapPost(LocalAgentContract.AccountPurchasesPath",
                StringComparison.Ordinal) &&
            hostSource.Contains(
                "AddSingleton<IAccountPurchasesService>",
                StringComparison.Ordinal) &&
            hostSource.Contains(
                "AddSingleton<IAccountPurchasesRemote>",
                StringComparison.Ordinal),
            "Agent Host account purchases mediation wiring drifted");

        Require(
            remoteSource.Contains(
                "/api/agent-sessions/account/purchases",
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
                StringComparison.Ordinal),
            "Agent account purchases remote lost read-only bearer/protocol/redirect mediation");

        Require(
            !remoteSource.Contains("Console.", StringComparison.Ordinal) &&
            !serviceSource.Contains("Console.", StringComparison.Ordinal) &&
            !serviceSource.Contains("AgentDatabase", StringComparison.Ordinal) &&
            !serviceSource.Contains("File.", StringComparison.Ordinal),
            "Agent account purchases mediation introduced logging or local persistence");
    }

    private static async Task CertifyServiceBoundaryAsync()
    {
        var account = new AccountSessionAccount(
            "purchases-user",
            "purchases@example.test",
            "cloud-account-must-not-leak",
            "ORGANIZATION",
            "Purchases Organization");
        var store = PurchasesStore.Active(account);
        var remote = new FakeAccountPurchasesRemote(
            ReadyRemoteResult());
        var service = new AccountPurchasesService(
            new PurchasesAuthenticatedSessionService(account),
            store,
            remote);

        var response = await service.GetAsync(
            new AccountPurchasesRequest(
                "account-purchases-cert"),
            CancellationToken.None);

        Require(
            response.Status == "READY" &&
            response.Account?.Type == "ORGANIZATION" &&
            response.Account.Role == "OWNER" &&
            response.Permissions?.ViewOrders == true &&
            response.Permissions.ViewSubscriptions &&
            response.Permissions.ViewAllLicenses &&
            response.Permissions.ManageLicenseSeats &&
            response.Licenses.Count == 1 &&
            response.Licenses[0].KeyLastFour == "ABCD" &&
            response.Licenses[0].MaxSeats == 2 &&
            response.Licenses[0].AssignedSeats == 1 &&
            response.Licenses[0].SeatManagementHandle ==
                "bke-license-seat-v1_" + new string('a', 64) &&
            response.Subscriptions.Count == 1 &&
            response.Orders.Count == 1 &&
            response.Orders[0].Number == "ORD-CERT-001" &&
            remote.Calls == 1 &&
            remote.LastAccessToken == "purchases-access-secret",
            "account purchases service mediation drifted");

        var wire = JsonSerializer.Serialize(response);
        foreach (var forbiddenValue in new[]
        {
            "purchases-access-secret",
            "purchases-refresh-secret",
            "cloud-account-must-not-leak",
            "license-id-must-not-leak",
            "payment-secret-must-not-leak",
        })
        {
            Require(
                !wire.Contains(
                    forbiddenValue,
                    StringComparison.Ordinal),
                "account purchases response leaked Agent/cloud authority material");
        }

        var unauthenticatedRemote =
            new FakeAccountPurchasesRemote(
                ReadyRemoteResult());
        var unauthenticated =
            new AccountPurchasesService(
                new PurchasesUnauthenticatedSessionService(),
                PurchasesStore.Active(account),
                unauthenticatedRemote);
        var denied = await unauthenticated.GetAsync(
            new AccountPurchasesRequest(
                "purchases-auth-cert"),
            CancellationToken.None);
        Require(
            denied.Status == "AUTH_REQUIRED" &&
            unauthenticatedRemote.Calls == 0,
            "account purchases called Digital Solutions without authenticated Agent custody");

        var invalidStore = PurchasesStore.Active(account);
        var invalidService =
            new AccountPurchasesService(
                new PurchasesAuthenticatedSessionService(
                    account),
                invalidStore,
                new ThrowingAccountPurchasesRemote(
                    new UnauthorizedAccessException(
                        "certified invalid bearer")));
        var invalid = await invalidService.GetAsync(
            new AccountPurchasesRequest(
                "purchases-invalid-session"),
            CancellationToken.None);
        Require(
            invalid.Status == "AUTH_REQUIRED" &&
            invalid.Error?.Code == "SESSION_INVALID" &&
            invalidStore.State is null,
            "invalid purchases bearer did not clear Agent session custody");

        var failureStore = PurchasesStore.Active(account);
        var failureService =
            new AccountPurchasesService(
                new PurchasesAuthenticatedSessionService(
                    account),
                failureStore,
                new ThrowingAccountPurchasesRemote(
                    new HttpRequestException(
                        "certified purchases outage")));
        var unavailable = await failureService.GetAsync(
            new AccountPurchasesRequest(
                "purchases-failure"),
            CancellationToken.None);
        Require(
            unavailable.Status == "FAILED" &&
            unavailable.Error?.Code ==
                "ACCOUNT_PURCHASES_UNAVAILABLE" &&
            unavailable.Error.Retryable &&
            failureStore.State is ActiveAccountSessionState,
            "read-only purchases failure did not preserve valid Agent custody");

        var malformedStore = PurchasesStore.Active(account);
        var malformedService =
            new AccountPurchasesService(
                new PurchasesAuthenticatedSessionService(
                    account),
                malformedStore,
                new ThrowingAccountPurchasesRemote(
                    new JsonException(
                        "certified malformed purchases JSON")));
        var malformed = await malformedService.GetAsync(
            new AccountPurchasesRequest(
                "purchases-malformed-json"),
            CancellationToken.None);
        Require(
            malformed.Status == "FAILED" &&
            malformed.Error?.Code ==
                "ACCOUNT_PURCHASES_UNAVAILABLE" &&
            malformedStore.State is ActiveAccountSessionState,
            "malformed purchases JSON escaped the fail-closed service envelope");

        var forbiddenService =
            new AccountPurchasesService(
                new PurchasesAuthenticatedSessionService(
                    account),
                PurchasesStore.Active(account),
                new FakeAccountPurchasesRemote(
                    new RemoteAccountPurchasesResult(
                        "account_forbidden",
                        ErrorCode: "ACCOUNT_FORBIDDEN")));
        var forbidden = await forbiddenService.GetAsync(
            new AccountPurchasesRequest(
                "purchases-forbidden"),
            CancellationToken.None);
        Require(
            forbidden.Status == "FORBIDDEN" &&
            forbidden.Error?.Code == "ACCOUNT_FORBIDDEN" &&
            !forbidden.Error.Retryable,
            "account purchases did not preserve authoritative selected-account denial");
    }

    private static async Task CertifyRemoteTransportAsync()
    {
        const string token = "purchases-transport-secret";

        var handler = new PurchasesTransportHandler(
            HttpStatusCode.OK,
            """
            {
              "status":"ready",
              "account":{
                "type":"ORGANIZATION",
                "display_name":"Certification Organization",
                "lifecycle_state":"ACTIVE",
                "role":"OWNER",
                "account_id":"cloud-account-must-not-leak"
              },
              "permissions":{
                "view_orders":true,
                "view_subscriptions":true,
                "view_all_licenses":true,
                "manage_license_seats":true
              },
              "licenses":[
                {
                  "product_name":"Render Dock",
                  "edition_name":"Pro",
                  "plan_type":"ANNUAL",
                  "status":"ACTIVE",
                  "key_last_four":"ABCD",
                  "expires_at":"2027-09-30T00:00:00.000Z",
                  "max_devices":4,
                  "active_devices":1,
                  "max_seats":2,
                  "assigned_seats":1,
                  "seat_management_handle":"bke-license-seat-v1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                  "license_id":"license-id-must-not-leak"
                }
              ],
              "subscriptions":[
                {
                  "product_name":"Render Dock",
                  "edition_name":"Pro",
                  "plan_type":"ANNUAL",
                  "status":"ACTIVE",
                  "seats":2,
                  "current_period_end":"2027-09-30T00:00:00.000Z"
                }
              ],
              "orders":[
                {
                  "number":"ORD-CERT-001",
                  "status":"PAID",
                  "total_minor":30000000,
                  "currency":"PHP",
                  "created_at":"2026-09-30T00:00:00.000Z",
                  "invoice_available":true,
                  "payment_secret":"payment-secret-must-not-leak",
                  "items":[
                    {
                      "product_name":"Render Dock",
                      "edition_name":"Pro",
                      "plan_name":"Annual"
                    }
                  ]
                }
              ]
            }
            """);

        using (var client = new HttpClient(handler))
        using (var remote = new AccountPurchasesRemote(
            client,
            "https://purchases-cert.example.test"))
        {
            var result = await remote.GetAsync(
                token,
                CancellationToken.None);
            Require(
                result.Status == "ready" &&
                result.Account?.Role == "OWNER" &&
                result.Licenses?.Count == 1 &&
                result.Orders?.Count == 1 &&
                handler.RequestCount == 1 &&
                handler.SawBearer &&
                handler.SawProtocol &&
                handler.SawGet &&
                handler.SawNoBody,
                "account purchases transport boundary drifted");

            var wire = JsonSerializer.Serialize(result);
            Require(
                !wire.Contains(
                    "cloud-account-must-not-leak",
                    StringComparison.Ordinal) &&
                !wire.Contains(
                    "license-id-must-not-leak",
                    StringComparison.Ordinal) &&
                !wire.Contains(
                    "payment-secret-must-not-leak",
                    StringComparison.Ordinal),
                "account purchases remote propagated ignored authority fields");
        }

        var unauthorized = new PurchasesTransportHandler(
            HttpStatusCode.Unauthorized,
            """{"error":"INVALID_TOKEN"}""");
        using (var client = new HttpClient(unauthorized))
        using (var remote = new AccountPurchasesRemote(
            client,
            "https://purchases-cert.example.test"))
        {
            await RequireThrowsAsync<UnauthorizedAccessException>(
                () => remote.GetAsync(
                    token,
                    CancellationToken.None),
                "account purchases invalid bearer was not rejected");
        }

        var redirect = new PurchasesTransportHandler(
            HttpStatusCode.Redirect,
            "{}",
            includeProtocol: false);
        using (var client = new HttpClient(redirect))
        using (var remote = new AccountPurchasesRemote(
            client,
            "https://purchases-cert.example.test"))
        {
            await RequireThrowsAsync<HttpRequestException>(
                () => remote.GetAsync(
                    token,
                    CancellationToken.None),
                "account purchases redirect was not rejected");
            Require(
                redirect.RequestCount == 1,
                "account purchases read redirect was replayed");
        }

        var malformedItem = new PurchasesTransportHandler(
            HttpStatusCode.OK,
            """
            {
              "status":"ready",
              "account":{
                "type":"INDIVIDUAL",
                "display_name":"Certification Personal",
                "lifecycle_state":"ACTIVE",
                "role":"OWNER"
              },
              "permissions":{
                "view_orders":true,
                "view_subscriptions":true,
                "view_all_licenses":true,
                "manage_license_seats":true
              },
              "licenses":["not-an-object"],
              "subscriptions":[],
              "orders":[]
            }
            """);
        using (var client = new HttpClient(malformedItem))
        using (var remote = new AccountPurchasesRemote(
            client,
            "https://purchases-cert.example.test"))
        {
            await RequireThrowsAsync<InvalidDataException>(
                () => remote.GetAsync(
                    token,
                    CancellationToken.None),
                "account purchases accepted a malformed collection item");
        }

        var missingProtocol = new PurchasesTransportHandler(
            HttpStatusCode.OK,
            """{"status":"ready"}""",
            includeProtocol: false);
        using (var client = new HttpClient(missingProtocol))
        using (var remote = new AccountPurchasesRemote(
            client,
            "https://purchases-cert.example.test"))
        {
            await RequireThrowsAsync<InvalidDataException>(
                () => remote.GetAsync(
                    token,
                    CancellationToken.None),
                "account purchases response without protocol version was accepted");
        }
    }

    private static RemoteAccountPurchasesResult ReadyRemoteResult() =>
        new(
            "ready",
            new AccountPurchasesAccount(
                "ORGANIZATION",
                "Purchases Organization",
                "ACTIVE",
                "OWNER"),
            new AccountPurchasesPermissions(
                true,
                true,
                true,
                true),
            [
                new AccountPurchasesLicense(
                    "Render Dock",
                    "Pro",
                    "ANNUAL",
                    "ACTIVE",
                    "ABCD",
                    "2027-09-30T00:00:00.000Z",
                    4,
                    1,
                    2,
                    1,
                    "bke-license-seat-v1_" + new string('a', 64)),
            ],
            [
                new AccountPurchasesSubscription(
                    "Render Dock",
                    "Pro",
                    "ANNUAL",
                    "ACTIVE",
                    2,
                    "2027-09-30T00:00:00.000Z"),
            ],
            [
                new AccountPurchasesOrder(
                    "ORD-CERT-001",
                    "PAID",
                    30000000,
                    "PHP",
                    "2026-09-30T00:00:00.000Z",
                    true,
                    [
                        new AccountPurchasesOrderItem(
                            "Render Dock",
                            "Pro",
                            "Annual"),
                    ]),
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

sealed class PurchasesStore : IAccountSessionSecretStore
{
    public AccountSessionStoredState? State { get; private set; }

    private PurchasesStore(AccountSessionStoredState? state)
    {
        State = state;
    }

    public static PurchasesStore Active(
        AccountSessionAccount account) =>
        new(new ActiveAccountSessionState(
            "purchases-access-secret",
            "purchases-refresh-secret",
            "purchases-session",
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

sealed class PurchasesAuthenticatedSessionService(
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

sealed class PurchasesUnauthenticatedSessionService :
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

sealed class FakeAccountPurchasesRemote(
    RemoteAccountPurchasesResult result) :
    IAccountPurchasesRemote
{
    public int Calls { get; private set; }
    public string? LastAccessToken { get; private set; }

    public Task<RemoteAccountPurchasesResult> GetAsync(
        string accessToken,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Calls += 1;
        LastAccessToken = accessToken;
        return Task.FromResult(result);
    }
}

sealed class ThrowingAccountPurchasesRemote(
    Exception error) : IAccountPurchasesRemote
{
    public Task<RemoteAccountPurchasesResult> GetAsync(
        string accessToken,
        CancellationToken cancellationToken) =>
        Task.FromException<RemoteAccountPurchasesResult>(
            error);
}

sealed class PurchasesTransportHandler(
    HttpStatusCode statusCode,
    string json,
    bool includeProtocol = true) : HttpMessageHandler
{
    public int RequestCount { get; private set; }
    public bool SawBearer { get; private set; }
    public bool SawProtocol { get; private set; }
    public bool SawGet { get; private set; }
    public bool SawNoBody { get; private set; }

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        RequestCount += 1;
        SawBearer =
            request.Headers.Authorization?.Scheme == "Bearer" &&
            request.Headers.Authorization.Parameter ==
                "purchases-transport-secret";
        SawProtocol =
            request.Headers.TryGetValues(
                "x-bke-account-session-version",
                out var versions) &&
            versions.SingleOrDefault() ==
                AccountSessionRemote.ProtocolVersion;
        SawGet =
            request.Method == HttpMethod.Get &&
            request.RequestUri?.AbsolutePath ==
                "/api/agent-sessions/account/purchases";
        SawNoBody = request.Content is null;

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
