using System.Net;
using System.Text;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;
using BKE.LicensingAgent.Infrastructure;

static class AccountOrganizationCertification
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
            LocalAgentContract.AccountOrganizationCapabilityId ==
                "bke.account-organization" &&
            LocalAgentContract.AccountOrganizationContractVersion == 1 &&
            LocalAgentContract.AccountOrganizationOverviewPath ==
                "/v1/account/organization",
            "account organization contract drifted");

        Require(
            typeof(AccountOrganizationOverviewRequest)
                .GetProperties()
                .Select(property => property.Name)
                .SequenceEqual(["CorrelationId"]),
            "account organization request widened");

        foreach (var type in new[]
        {
            typeof(AccountOrganizationOverviewResponse),
            typeof(AccountOrganizationAccount),
            typeof(AccountOrganizationMember),
            typeof(AccountOrganizationInvitation),
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
                        "InvitationId",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Equals(
                        "OwnerId",
                        StringComparison.OrdinalIgnoreCase)),
                $"account organization response {type.Name} exposes authority/mutation identifiers");
        }

        var host = File.ReadAllText(
            Path.Combine(
                "dotnet",
                "src",
                "BKE.LicensingAgent.Host",
                "Program.cs"));
        var remote = File.ReadAllText(
            Path.Combine(
                "dotnet",
                "src",
                "BKE.LicensingAgent.Infrastructure",
                "AccountOrganizationRemote.cs"));
        var service = File.ReadAllText(
            Path.Combine(
                "dotnet",
                "src",
                "BKE.LicensingAgent.Application",
                "AccountOrganizationService.cs"));

        Require(
            host.Contains(
                "app.MapPost(LocalAgentContract.AccountOrganizationOverviewPath",
                StringComparison.Ordinal) &&
            host.Contains(
                "AddSingleton<IAccountOrganizationService>",
                StringComparison.Ordinal),
            "Agent organization Host wiring drifted");

        Require(
            remote.Contains(
                "/api/agent-sessions/account/organization",
                StringComparison.Ordinal) &&
            remote.Contains(
                "new AuthenticationHeaderValue("Bearer", accessToken)",
                StringComparison.Ordinal) &&
            remote.Contains(
                ""x-bke-account-session-version"",
                StringComparison.Ordinal) &&
            remote.Contains(
                "AllowAutoRedirect = false",
                StringComparison.Ordinal),
            "Agent organization bearer/protocol/redirect mediation drifted");

        Require(
            !remote.Contains("Console.", StringComparison.Ordinal) &&
            !service.Contains("Console.", StringComparison.Ordinal) &&
            !service.Contains("AgentDatabase", StringComparison.Ordinal) &&
            !service.Contains("File.", StringComparison.Ordinal),
            "Agent organization overview introduced local persistence/logging");
    }

    private static async Task CertifyServiceBoundaryAsync()
    {
        var account = new AccountSessionAccount(
            "org-user",
            "org@example.test",
            "org-account",
            "ORGANIZATION",
            "Certification Organization");
        var store = OrganizationStore.Active(account);

        var ready = new RemoteAccountOrganizationResult(
            "ready",
            Account: new AccountOrganizationAccount(
                "Certification Organization",
                "ACTIVE",
                "OWNER"),
            Permissions: new AccountOrganizationPermissions(
                true,
                true,
                true),
            Organization: new AccountOrganizationProfile(
                "Certification Organization Legal",
                "REG-001"),
            BillingEmail: "billing@example.test",
            TaxId: "TAX-001",
            Counts: new AccountOrganizationCounts(2, 1, 3),
            Members: [
                new AccountOrganizationMember(
                    "owner@example.test",
                    "Owner",
                    "OWNER"),
            ],
            Invitations: [
                new AccountOrganizationInvitation(
                    "invitee@example.test",
                    "MEMBER",
                    "PENDING",
                    "2026-10-01T12:00:00.000Z",
                    "2026-09-29T12:00:00.000Z"),
            ]);

        var remote = new FakeOrganizationRemote(ready);
        var service = new AccountOrganizationService(
            new OrganizationAuthenticatedSessionService(account),
            store,
            remote);

        var result = await service.GetAsync(
            new AccountOrganizationOverviewRequest(
                "organization-overview-cert"),
            CancellationToken.None);

        Require(
            result.Status == "READY" &&
            result.Account?.Role == "OWNER" &&
            result.Members.Count == 1 &&
            result.Invitations.Count == 1 &&
            remote.Calls == 1 &&
            remote.LastAccessToken == "organization-access-secret",
            "Agent organization overview did not use session custody correctly");

        var wire = System.Text.Json.JsonSerializer.Serialize(result);
        Require(
            !wire.Contains(
                "organization-access-secret",
                StringComparison.Ordinal) &&
            !wire.Contains(
                "organization-refresh-secret",
                StringComparison.Ordinal) &&
            !wire.Contains(
                "org-account",
                StringComparison.Ordinal),
            "Agent organization response leaked cloud/session account identifiers");

        var personal = new AccountOrganizationService(
            new OrganizationAuthenticatedSessionService(account),
            OrganizationStore.Active(account),
            new FakeOrganizationRemote(
                new RemoteAccountOrganizationResult(
                    "not_organization")));
        var personalResult = await personal.GetAsync(
            new AccountOrganizationOverviewRequest(
                "organization-personal-cert"),
            CancellationToken.None);
        Require(
            personalResult.Status == "NOT_ORGANIZATION" &&
            personalResult.Account is null &&
            personalResult.Members.Count == 0,
            "Agent organization overview did not preserve personal-account no-op semantics");

        var invalidStore = OrganizationStore.Active(account);
        var invalid = new AccountOrganizationService(
            new OrganizationAuthenticatedSessionService(account),
            invalidStore,
            new ThrowingOrganizationRemote(
                new UnauthorizedAccessException(
                    "certified selected account rejection")));
        var invalidResult = await invalid.GetAsync(
            new AccountOrganizationOverviewRequest(
                "organization-invalid-cert"),
            CancellationToken.None);
        Require(
            invalidResult.Status == "AUTH_REQUIRED" &&
            invalidStore.State is null,
            "Agent organization selected-account rejection did not clear session custody");

        var outageStore = OrganizationStore.Active(account);
        var outage = new AccountOrganizationService(
            new OrganizationAuthenticatedSessionService(account),
            outageStore,
            new ThrowingOrganizationRemote(
                new HttpRequestException(
                    "certified organization outage")));
        var outageResult = await outage.GetAsync(
            new AccountOrganizationOverviewRequest(
                "organization-outage-cert"),
            CancellationToken.None);
        Require(
            outageResult.Status == "FAILED" &&
            outageStore.State is ActiveAccountSessionState,
            "read-only organization failure destroyed a valid Agent session");

        var signedOutRemote = new FakeOrganizationRemote(ready);
        var signedOut = new AccountOrganizationService(
            new OrganizationSignedOutSessionService(),
            OrganizationStore.Active(account),
            signedOutRemote);
        var signedOutResult = await signedOut.GetAsync(
            new AccountOrganizationOverviewRequest(
                "organization-auth-cert"),
            CancellationToken.None);
        Require(
            signedOutResult.Status == "AUTH_REQUIRED" &&
            signedOutRemote.Calls == 0,
            "Agent organization authority was called without authenticated session custody");
    }

    private static async Task CertifyRemoteTransportAsync()
    {
        const string token = "organization-transport-secret";
        var handler = new OrganizationTransportHandler(
            HttpStatusCode.OK,
            """
            {
              "status":"ready",
              "account":{
                "type":"ORGANIZATION",
                "display_name":"Certification Organization",
                "lifecycle_state":"ACTIVE",
                "role":"OWNER"
              },
              "permissions":{
                "manage_members":true,
                "view_billing":true,
                "view_licenses":true
              },
              "organization":{
                "legal_name":"Certification Organization Legal",
                "registration_number":"REG-001"
              },
              "billing_email":"billing@example.test",
              "tax_id":"TAX-001",
              "counts":{
                "licenses":2,
                "subscriptions":1,
                "orders":3
              },
              "members":[
                {
                  "email":"owner@example.test",
                  "name":"Owner",
                  "role":"OWNER"
                }
              ],
              "invitations":[
                {
                  "email":"invitee@example.test",
                  "role":"MEMBER",
                  "status":"PENDING",
                  "expires_at":"2026-10-01T12:00:00.000Z",
                  "created_at":"2026-09-29T12:00:00.000Z"
                }
              ]
            }
            """);
        using (var client = new HttpClient(handler))
        using (var remote = new AccountOrganizationRemote(
            client,
            "https://organization-cert.example.test"))
        {
            var result = await remote.GetAsync(
                token,
                CancellationToken.None);
            Require(
                result.Status == "ready" &&
                result.Account?.Role == "OWNER" &&
                result.Members?.Count == 1 &&
                handler.RequestCount == 1 &&
                handler.SawBearer &&
                handler.SawProtocol &&
                handler.SawGet &&
                handler.SawNoBody,
                "Agent organization remote transport drifted");
        }

        var notOrgHandler = new OrganizationTransportHandler(
            HttpStatusCode.OK,
            """{"status":"not_organization"}""");
        using (var client = new HttpClient(notOrgHandler))
        using (var remote = new AccountOrganizationRemote(
            client,
            "https://organization-cert.example.test"))
        {
            var result = await remote.GetAsync(
                token,
                CancellationToken.None);
            Require(
                result.Status == "not_organization",
                "Agent organization remote lost personal-account no-op response");
        }

        var redirect = new OrganizationTransportHandler(
            HttpStatusCode.Redirect,
            "{}");
        using (var client = new HttpClient(redirect))
        using (var remote = new AccountOrganizationRemote(
            client,
            "https://organization-cert.example.test"))
        {
            await RequireThrowsAsync<HttpRequestException>(
                () => remote.GetAsync(
                    token,
                    CancellationToken.None),
                "Agent organization redirect was not rejected");
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

sealed class OrganizationStore : IAccountSessionSecretStore
{
    public AccountSessionStoredState? State { get; private set; }

    private OrganizationStore(AccountSessionStoredState? state)
    {
        State = state;
    }

    public static OrganizationStore Active(
        AccountSessionAccount account) =>
        new(new ActiveAccountSessionState(
            "organization-access-secret",
            "organization-refresh-secret",
            "organization-session",
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

sealed class OrganizationAuthenticatedSessionService(
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

sealed class OrganizationSignedOutSessionService : IAccountSessionService
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

sealed class FakeOrganizationRemote(
    RemoteAccountOrganizationResult result) : IAccountOrganizationRemote
{
    public int Calls { get; private set; }
    public string? LastAccessToken { get; private set; }

    public Task<RemoteAccountOrganizationResult> GetAsync(
        string accessToken,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Calls++;
        LastAccessToken = accessToken;
        return Task.FromResult(result);
    }
}

sealed class ThrowingOrganizationRemote(
    Exception error) : IAccountOrganizationRemote
{
    public Task<RemoteAccountOrganizationResult> GetAsync(
        string accessToken,
        CancellationToken cancellationToken) =>
        Task.FromException<RemoteAccountOrganizationResult>(error);
}

sealed class OrganizationTransportHandler(
    HttpStatusCode statusCode,
    string json) : HttpMessageHandler
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
        RequestCount++;
        SawBearer =
            request.Headers.Authorization?.Scheme == "Bearer" &&
            request.Headers.Authorization.Parameter ==
                "organization-transport-secret";
        SawProtocol =
            request.Headers.TryGetValues(
                "x-bke-account-session-version",
                out var values) &&
            values.SingleOrDefault() ==
                AccountSessionRemote.ProtocolVersion;
        SawGet =
            request.Method == HttpMethod.Get &&
            request.RequestUri?.AbsolutePath ==
                "/api/agent-sessions/account/organization";
        SawNoBody = request.Content is null;

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
        return Task.FromResult(response);
    }
}
