using System.Net;
using System.Text;
using System.Text.Json;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;
using BKE.LicensingAgent.Infrastructure;

static class PersistentGiftClaimCertification
{
    private const string ExpectedDigitalSolutionsSource =
        "b84965a513f6cdcd9574c8da8fef86785f5f207d";
    private static readonly string GiftHandle =
        "bke-gift-claim-v1_" + new string('a', 64);

    public static async Task RunAsync()
    {
        CertifyStaticBoundaries();
        await CertifyServiceBoundariesAsync();
        await CertifyRemoteTransportsAsync();
    }

    private static void CertifyStaticBoundaries()
    {
        Require(
            File.ReadAllText(
                Path.Combine(
                    "eng",
                    "digital-solutions-source.sha")).Trim() ==
                ExpectedDigitalSolutionsSource,
            "Agent is not pinned to the merged Digital Solutions persistent Gift Claim Code authority.");

        Require(
            PersistentGiftContractExtensions.AccountRecentAuthPathSet() &&
            LocalAgentContract.AccountRecentAuthCapabilityId ==
                "bke.account-recent-auth" &&
            LocalAgentContract.AccountRecentAuthContractVersion == 1,
            "Recent-auth local capability drifted.");

        Require(
            LocalAgentContract.StoreGiftClaimsPath ==
                "/v1/store/gift-claim-codes" &&
            LocalAgentContract.StoreGiftClaimPersistentRevealPath ==
                "/v1/store/gift-claim-codes/reveal" &&
            LocalAgentContract.StoreGiftClaimsCapabilityId ==
                "bke.store-gift-claims" &&
            LocalAgentContract.StoreGiftClaimPersistentRevealCapabilityId ==
                "bke.store-gift-claim-persistent-reveal",
            "Persistent Gift Claim Code local capability drifted.");

        Require(
            typeof(AccountRecentAuthStartRequest)
                .GetProperties()
                .Select(property => property.Name)
                .SequenceEqual([
                    "CorrelationId",
                    "CurrentPassword",
                ]) &&
            typeof(AccountRecentAuthCompleteRequest)
                .GetProperties()
                .Select(property => property.Name)
                .SequenceEqual([
                    "CorrelationId",
                    "ChallengeToken",
                    "Code",
                ]),
            "Recent-auth transient request contract widened.");

        Require(
            typeof(StoreGiftClaimsRequest)
                .GetProperties()
                .Select(property => property.Name)
                .SequenceEqual(["CorrelationId"]) &&
            typeof(StoreGiftClaimPersistentRevealRequest)
                .GetProperties()
                .Select(property => property.Name)
                .SequenceEqual([
                    "CorrelationId",
                    "GiftClaimHandle",
                ]),
            "Persistent Gift Claim Code request contract widened.");

        foreach (var type in new[]
        {
            typeof(StoreGiftClaimItem),
            typeof(StoreGiftClaimsResponse),
            typeof(StoreGiftClaimPersistentRevealResponse),
        })
        {
            Require(
                type.GetProperties().All(property =>
                    !property.Name.Equals(
                        "ClaimCodeId",
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
                    !property.Name.Equals(
                        "LicenseId",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Equals(
                        "EntitlementId",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Contains(
                        "AccessToken",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Contains(
                        "RefreshToken",
                        StringComparison.OrdinalIgnoreCase)),
                $"{type.Name} exposes a raw cloud authority identifier.");
        }

        var hostSource = File.ReadAllText(
            Path.Combine(
                "dotnet",
                "src",
                "BKE.LicensingAgent.Host",
                "Program.cs"));
        var recentRemoteSource = File.ReadAllText(
            Path.Combine(
                "dotnet",
                "src",
                "BKE.LicensingAgent.Infrastructure",
                "AccountRecentAuthRemote.cs"));
        var recentServiceSource = File.ReadAllText(
            Path.Combine(
                "dotnet",
                "src",
                "BKE.LicensingAgent.Application",
                "AccountRecentAuthService.cs"));
        var giftRemoteSource = File.ReadAllText(
            Path.Combine(
                "dotnet",
                "src",
                "BKE.LicensingAgent.Infrastructure",
                "StoreGiftClaimsRemote.cs"));
        var giftServiceSource = File.ReadAllText(
            Path.Combine(
                "dotnet",
                "src",
                "BKE.LicensingAgent.Application",
                "StoreGiftClaimsService.cs"));

        foreach (var route in new[]
        {
            "AccountRecentAuthStartPath",
            "AccountRecentAuthCompletePath",
            "StoreGiftClaimsPath",
            "StoreGiftClaimPersistentRevealPath",
        })
        {
            Require(
                hostSource.Contains(
                    $"app.MapPost(LocalAgentContract.{route}",
                    StringComparison.Ordinal),
                $"Host route {route} is not mediated.");
        }

        Require(
            hostSource.Contains(
                "AddSingleton<IAccountRecentAuthService>",
                StringComparison.Ordinal) &&
            hostSource.Contains(
                "AddSingleton<IStoreGiftClaimsService>",
                StringComparison.Ordinal),
            "Persistent Gift Claim Code Host DI wiring drifted.");

        Require(
            recentRemoteSource.Contains(
                "/api/agent-sessions/account/recent-auth/start",
                StringComparison.Ordinal) &&
            recentRemoteSource.Contains(
                "/api/agent-sessions/account/recent-auth/complete",
                StringComparison.Ordinal) &&
            recentRemoteSource.Contains(
                "AllowAutoRedirect = false",
                StringComparison.Ordinal) &&
            !recentRemoteSource.Contains(
                "for (var attempt",
                StringComparison.Ordinal) &&
            recentRemoteSource.Split(
                "_http.SendAsync(",
                StringSplitOptions.None).Length == 2,
            "Recent-auth transport lost single-attempt no-redirect semantics.");

        Require(
            !recentServiceSource.Contains(
                "AgentDatabase",
                StringComparison.Ordinal) &&
            !recentServiceSource.Contains(
                "File.",
                StringComparison.Ordinal) &&
            !recentServiceSource.Contains(
                "Console.",
                StringComparison.Ordinal) &&
            recentServiceSource.Contains(
                "\"RESULT_UNKNOWN\"",
                StringComparison.Ordinal),
            "Recent-auth service introduced persistence/logging or lost ambiguity handling.");

        Require(
            giftRemoteSource.Contains(
                "/api/agent-sessions/store/gift-claim-codes",
                StringComparison.Ordinal) &&
            giftRemoteSource.Contains(
                "/api/agent-sessions/store/gift-claim-codes/reveal",
                StringComparison.Ordinal) &&
            giftRemoteSource.Contains(
                "for (var attempt = 0; attempt <= 2; attempt++)",
                StringComparison.Ordinal) &&
            giftRemoteSource.Split(
                "_http.SendAsync(",
                StringSplitOptions.None).Length == 3 &&
            giftRemoteSource.Contains(
                "AllowAutoRedirect = false",
                StringComparison.Ordinal),
            "Persistent Gift Claim Code transport lost bounded-list/single-reveal/no-redirect semantics.");

        Require(
            !giftServiceSource.Contains(
                "AgentDatabase",
                StringComparison.Ordinal) &&
            !giftServiceSource.Contains(
                "File.",
                StringComparison.Ordinal) &&
            !giftServiceSource.Contains(
                "Console.",
                StringComparison.Ordinal) &&
            giftServiceSource.Contains(
                "\"RECENT_AUTH_REQUIRED\"",
                StringComparison.Ordinal) &&
            giftServiceSource.Contains(
                "\"RESULT_UNKNOWN\"",
                StringComparison.Ordinal),
            "Persistent Gift Claim Code service lost secret or fail-closed boundaries.");
    }

    private static async Task CertifyServiceBoundariesAsync()
    {
        var account = new AccountSessionAccount(
            "gift-user",
            "gift@example.test",
            "cloud-account-must-not-leak",
            "INDIVIDUAL",
            "Gift Buyer");

        var recentStore = GiftStore.Active(account);
        var recentRemote = new FakeRecentAuthRemote(
            start: new RemoteAccountRecentAuthResult(
                "mfa_challenge_issued",
                ChallengeToken: "challenge-secret-must-be-transient",
                ExpiresAt: "2026-10-01T07:00:00.000Z",
                EmailSent: true,
                MfaReference: "MFA-CERT"),
            complete: new RemoteAccountRecentAuthResult(
                "verified",
                RecentAuthenticatedUntil:
                    "2026-10-01T07:15:00.000Z"));
        var recentService = new AccountRecentAuthService(
            new GiftAuthenticatedSessionService(account),
            recentStore,
            recentRemote);

        var start = await recentService.StartAsync(
            new AccountRecentAuthStartRequest(
                "recent-auth-cert-0001",
                "Current-Password-Secret"),
            CancellationToken.None);
        Require(
            start.Status == "MFA_CHALLENGE_ISSUED" &&
            start.ChallengeToken ==
                "challenge-secret-must-be-transient" &&
            recentRemote.StartCalls == 1 &&
            recentRemote.LastPassword ==
                "Current-Password-Secret" &&
            recentRemote.LastAccessToken ==
                "gift-access-secret",
            "Recent-auth start mediation drifted.");

        var startWire = JsonSerializer.Serialize(start);
        Require(
            !startWire.Contains(
                "Current-Password-Secret",
                StringComparison.Ordinal) &&
            !startWire.Contains(
                "gift-access-secret",
                StringComparison.Ordinal) &&
            !startWire.Contains(
                "gift-refresh-secret",
                StringComparison.Ordinal),
            "Recent-auth response leaked password or Agent bearer custody.");

        var complete = await recentService.CompleteAsync(
            new AccountRecentAuthCompleteRequest(
                "recent-auth-cert-0002",
                "challenge-secret-must-be-transient",
                "123456"),
            CancellationToken.None);
        Require(
            complete.Status == "VERIFIED" &&
            complete.RecentAuthenticatedUntil ==
                "2026-10-01T07:15:00.000Z" &&
            recentRemote.CompleteCalls == 1 &&
            recentRemote.LastChallengeToken ==
                "challenge-secret-must-be-transient" &&
            recentRemote.LastCode == "123456",
            "Recent-auth completion mediation drifted.");

        var ambiguous = await new AccountRecentAuthService(
            new GiftAuthenticatedSessionService(account),
            GiftStore.Active(account),
            new ThrowingRecentAuthRemote(
                new HttpRequestException(
                    "certified ambiguous recent-auth")))
            .CompleteAsync(
                new AccountRecentAuthCompleteRequest(
                    "recent-auth-ambiguous",
                    "challenge-secret-must-be-transient",
                    "123456"),
                CancellationToken.None);
        Require(
            ambiguous.Status == "RESULT_UNKNOWN" &&
            ambiguous.Error?.Retryable == false,
            "Recent-auth ambiguity became an automatic-retry state.");

        var invalidRecentStore = GiftStore.Active(account);
        var invalidRecent = await new AccountRecentAuthService(
            new GiftAuthenticatedSessionService(account),
            invalidRecentStore,
            new ThrowingRecentAuthRemote(
                new UnauthorizedAccessException(
                    "certified invalid bearer")))
            .StartAsync(
                new AccountRecentAuthStartRequest(
                    "recent-auth-invalid",
                    "Current-Password-Secret"),
                CancellationToken.None);
        Require(
            invalidRecent.Status == "AUTH_REQUIRED" &&
            invalidRecentStore.State is null,
            "Recent-auth invalid bearer did not clear Agent session custody.");

        var claim = new StoreGiftClaimItem(
            GiftHandle,
            "ORD-CERT-001",
            "Render Dock",
            "Professional",
            "Perpetual",
            "ABCD",
            "AVAILABLE",
            "2026-10-01T06:00:00.000Z",
            null);
        var giftRemote = new FakeGiftClaimsRemote(
            new RemoteStoreGiftClaimsListResult(
                "ready",
                "gift-list-cert-0001",
                "ACTIVE",
                [claim]),
            new RemoteStoreGiftClaimPersistentRevealResult(
                "available",
                "gift-reveal-cert-0001",
                GiftHandle,
                "BKE-CLM-AAAAA-BBBBB-CCCCC-DDDDD-EEEEE-FFFFF"));
        var giftService = new StoreGiftClaimsService(
            new GiftAuthenticatedSessionService(account),
            GiftStore.Active(account),
            giftRemote);

        var list = await giftService.ListAsync(
            new StoreGiftClaimsRequest(
                "gift-list-cert-0001"),
            CancellationToken.None);
        Require(
            list.Status == "READY" &&
            list.Claims.Count == 1 &&
            list.Claims[0].GiftClaimHandle == GiftHandle &&
            giftRemote.ListCalls == 1 &&
            giftRemote.LastAccessToken ==
                "gift-access-secret",
            "Persistent Gift Claim Code list mediation drifted.");

        var listWire = JsonSerializer.Serialize(list);
        foreach (var forbidden in new[]
        {
            "gift-access-secret",
            "gift-refresh-secret",
            "cloud-account-must-not-leak",
            "raw-claim-id",
            "raw-order-id",
        })
        {
            Require(
                !listWire.Contains(
                    forbidden,
                    StringComparison.Ordinal),
                "Persistent Gift Claim Code list leaked cloud authority material.");
        }

        var reveal = await giftService.RevealAsync(
            new StoreGiftClaimPersistentRevealRequest(
                "gift-reveal-cert-0001",
                GiftHandle),
            CancellationToken.None);
        Require(
            reveal.Status == "AVAILABLE" &&
            reveal.GiftClaimHandle == GiftHandle &&
            reveal.ClaimCode ==
                "BKE-CLM-AAAAA-BBBBB-CCCCC-DDDDD-EEEEE-FFFFF" &&
            giftRemote.RevealCalls == 1,
            "Persistent Gift Claim Code reveal mediation drifted.");

        var recentRequired = await new StoreGiftClaimsService(
            new GiftAuthenticatedSessionService(account),
            GiftStore.Active(account),
            new FakeGiftClaimsRemote(
                new RemoteStoreGiftClaimsListResult(
                    "ready",
                    "unused",
                    "ACTIVE",
                    []),
                new RemoteStoreGiftClaimPersistentRevealResult(
                    "recent_auth_required",
                    "gift-recent-auth-required")))
            .RevealAsync(
                new StoreGiftClaimPersistentRevealRequest(
                    "gift-recent-auth-required",
                    GiftHandle),
                CancellationToken.None);
        Require(
            recentRequired.Status == "RECENT_AUTH_REQUIRED" &&
            recentRequired.ClaimCode is null,
            "Persistent Gift Claim Code reveal weakened recent-auth.");

        var ambiguousReveal = await new StoreGiftClaimsService(
            new GiftAuthenticatedSessionService(account),
            GiftStore.Active(account),
            new ThrowingGiftClaimsRemote(
                new HttpRequestException(
                    "certified ambiguous reveal")))
            .RevealAsync(
                new StoreGiftClaimPersistentRevealRequest(
                    "gift-reveal-ambiguous",
                    GiftHandle),
                CancellationToken.None);
        Require(
            ambiguousReveal.Status == "RESULT_UNKNOWN" &&
            ambiguousReveal.Error?.Retryable == false,
            "Secret reveal ambiguity became an automatic-retry state.");

        var invalidGiftStore = GiftStore.Active(account);
        var invalidGift = await new StoreGiftClaimsService(
            new GiftAuthenticatedSessionService(account),
            invalidGiftStore,
            new ThrowingGiftClaimsRemote(
                new UnauthorizedAccessException(
                    "certified invalid bearer")))
            .ListAsync(
                new StoreGiftClaimsRequest(
                    "gift-invalid-bearer"),
                CancellationToken.None);
        Require(
            invalidGift.Status == "AUTH_REQUIRED" &&
            invalidGiftStore.State is null,
            "Persistent Gift Claim Code invalid bearer did not clear Agent session custody.");
    }

    private static async Task CertifyRemoteTransportsAsync()
    {
        const string token = "transport-gift-access-secret";

        var recentStart = new PersistentGiftTransportHandler(
            HttpStatusCode.Created,
            """
            {
              "status":"mfa_challenge_issued",
              "challenge_token":"cert-challenge-token-00000001",
              "expires_at":"2026-10-01T07:00:00.000Z",
              "email_sent":true,
              "mfa_reference":"MFA-CERT"
            }
            """,
            token,
            "/api/agent-sessions/account/recent-auth/start");
        using (var client = new HttpClient(recentStart))
        using (var remote = new AccountRecentAuthRemote(
            client,
            "https://gift-cert.example.test"))
        {
            var result = await remote.StartAsync(
                token,
                "Current-Password-Secret",
                CancellationToken.None);
            Require(
                result.Status == "mfa_challenge_issued" &&
                recentStart.RequestCount == 1 &&
                recentStart.SawBearer &&
                recentStart.SawProtocol &&
                recentStart.SawExpectedPath &&
                recentStart.BodyContains(
                    "current_password",
                    "Current-Password-Secret") &&
                !recentStart.BodyHasKey("correlation_id"),
                "Recent-auth start remote transport widened or drifted.");
        }

        var recentComplete = new PersistentGiftTransportHandler(
            HttpStatusCode.OK,
            """
            {
              "status":"verified",
              "recent_authenticated_until":"2026-10-01T07:15:00.000Z"
            }
            """,
            token,
            "/api/agent-sessions/account/recent-auth/complete");
        using (var client = new HttpClient(recentComplete))
        using (var remote = new AccountRecentAuthRemote(
            client,
            "https://gift-cert.example.test"))
        {
            var result = await remote.CompleteAsync(
                token,
                "cert-challenge-token-00000001",
                "123456",
                CancellationToken.None);
            Require(
                result.Status == "verified" &&
                recentComplete.RequestCount == 1 &&
                recentComplete.BodyContains(
                    "challenge_token",
                    "cert-challenge-token-00000001") &&
                recentComplete.BodyContains("code", "123456"),
                "Recent-auth completion remote transport drifted.");
        }

        var recentThrow = new PersistentGiftTransportHandler(
            HttpStatusCode.OK,
            "{}",
            token,
            "/api/agent-sessions/account/recent-auth/start",
            throwTransport: true);
        using (var client = new HttpClient(recentThrow))
        using (var remote = new AccountRecentAuthRemote(
            client,
            "https://gift-cert.example.test"))
        {
            await RequireThrowsAsync<HttpRequestException>(
                () => remote.StartAsync(
                    token,
                    "Current-Password-Secret",
                    CancellationToken.None),
                "Recent-auth transport failure was hidden.");
            Require(
                recentThrow.RequestCount == 1,
                "Recent-auth start was automatically replayed.");
        }

        var listHandler = new PersistentGiftTransportHandler(
            HttpStatusCode.OK,
            $$"""
            {
              "status":"ready",
              "correlation_id":"gift-list-transport",
              "account_lifecycle_state":"ACTIVE",
              "claims":[
                {
                  "gift_claim_handle":"{{GiftHandle}}",
                  "order_number":"ORD-CERT-001",
                  "product_name":"Render Dock",
                  "edition_name":"Professional",
                  "plan_name":"Perpetual",
                  "last_four":"ABCD",
                  "status":"AVAILABLE",
                  "created_at":"2026-10-01T06:00:00.000Z",
                  "expires_at":null
                }
              ]
            }
            """,
            token,
            "/api/agent-sessions/store/gift-claim-codes",
            transientFailures: 2);
        using (var client = new HttpClient(listHandler))
        using (var remote = new StoreGiftClaimsRemote(
            client,
            "https://gift-cert.example.test"))
        {
            var result = await remote.ListAsync(
                token,
                "gift-list-transport",
                CancellationToken.None);
            Require(
                result.Status == "ready" &&
                result.Claims?.Count == 1 &&
                listHandler.RequestCount == 3 &&
                listHandler.SawBearer &&
                listHandler.SawProtocol &&
                listHandler.SawExpectedPath &&
                listHandler.BodyContains(
                    "correlation_id",
                    "gift-list-transport"),
                "Persistent Gift Claim Code list safe-read retry boundary drifted.");
        }

        var revealHandler = new PersistentGiftTransportHandler(
            HttpStatusCode.OK,
            $$"""
            {
              "status":"available",
              "correlation_id":"gift-reveal-transport",
              "gift_claim_handle":"{{GiftHandle}}",
              "claim_code":"BKE-CLM-AAAAA-BBBBB-CCCCC-DDDDD-EEEEE-FFFFF"
            }
            """,
            token,
            "/api/agent-sessions/store/gift-claim-codes/reveal");
        using (var client = new HttpClient(revealHandler))
        using (var remote = new StoreGiftClaimsRemote(
            client,
            "https://gift-cert.example.test"))
        {
            var result = await remote.RevealAsync(
                token,
                "gift-reveal-transport",
                GiftHandle,
                CancellationToken.None);
            Require(
                result.Status == "available" &&
                result.ClaimCode ==
                    "BKE-CLM-AAAAA-BBBBB-CCCCC-DDDDD-EEEEE-FFFFF" &&
                revealHandler.RequestCount == 1 &&
                revealHandler.BodyContains(
                    "gift_claim_handle",
                    GiftHandle) &&
                !revealHandler.BodyHasKey("claim_code_id") &&
                !revealHandler.BodyHasKey("order_id"),
                "Persistent Gift Claim Code reveal transport widened.");
        }

        var widenedReveal = new PersistentGiftTransportHandler(
            HttpStatusCode.OK,
            $$"""
            {
              "status":"available",
              "correlation_id":"gift-reveal-widened",
              "gift_claim_handle":"{{GiftHandle}}",
              "claim_code":"BKE-CLM-AAAAA-BBBBB-CCCCC-DDDDD-EEEEE-FFFFF",
              "claim_code_id":"raw-id-must-not-cross"
            }
            """,
            token,
            "/api/agent-sessions/store/gift-claim-codes/reveal");
        using (var client = new HttpClient(widenedReveal))
        using (var remote = new StoreGiftClaimsRemote(
            client,
            "https://gift-cert.example.test"))
        {
            await RequireThrowsAsync<InvalidDataException>(
                () => remote.RevealAsync(
                    token,
                    "gift-reveal-widened",
                    GiftHandle,
                    CancellationToken.None),
                "Persistent Gift Claim Code reveal accepted a widened raw identifier.");
        }

        var revealThrow = new PersistentGiftTransportHandler(
            HttpStatusCode.OK,
            "{}",
            token,
            "/api/agent-sessions/store/gift-claim-codes/reveal",
            throwTransport: true);
        using (var client = new HttpClient(revealThrow))
        using (var remote = new StoreGiftClaimsRemote(
            client,
            "https://gift-cert.example.test"))
        {
            await RequireThrowsAsync<HttpRequestException>(
                () => remote.RevealAsync(
                    token,
                    "gift-reveal-single-attempt",
                    GiftHandle,
                    CancellationToken.None),
                "Persistent Gift Claim Code reveal transport failure was hidden.");
            Require(
                revealThrow.RequestCount == 1,
                "Persistent Gift Claim Code reveal was automatically replayed.");
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

static class PersistentGiftContractExtensions
{
    public static bool AccountRecentAuthPathSet()
    {
        return
            LocalAgentContract.AccountRecentAuthStartPath ==
                "/v1/account/recent-auth/start" &&
            LocalAgentContract.AccountRecentAuthCompletePath ==
                "/v1/account/recent-auth/complete";
    }
}

sealed class GiftStore : IAccountSessionSecretStore
{
    public AccountSessionStoredState? State { get; private set; }

    private GiftStore(AccountSessionStoredState? state)
    {
        State = state;
    }

    public static GiftStore Active(
        AccountSessionAccount account) =>
        new(new ActiveAccountSessionState(
            "gift-access-secret",
            "gift-refresh-secret",
            "gift-session",
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

sealed class GiftAuthenticatedSessionService(
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

sealed class FakeRecentAuthRemote(
    RemoteAccountRecentAuthResult start,
    RemoteAccountRecentAuthResult complete)
    : IAccountRecentAuthRemote
{
    public int StartCalls { get; private set; }
    public int CompleteCalls { get; private set; }
    public string? LastAccessToken { get; private set; }
    public string? LastPassword { get; private set; }
    public string? LastChallengeToken { get; private set; }
    public string? LastCode { get; private set; }

    public Task<RemoteAccountRecentAuthResult> StartAsync(
        string accessToken,
        string currentPassword,
        CancellationToken cancellationToken)
    {
        StartCalls += 1;
        LastAccessToken = accessToken;
        LastPassword = currentPassword;
        return Task.FromResult(start);
    }

    public Task<RemoteAccountRecentAuthResult> CompleteAsync(
        string accessToken,
        string challengeToken,
        string code,
        CancellationToken cancellationToken)
    {
        CompleteCalls += 1;
        LastAccessToken = accessToken;
        LastChallengeToken = challengeToken;
        LastCode = code;
        return Task.FromResult(complete);
    }
}

sealed class ThrowingRecentAuthRemote(Exception error)
    : IAccountRecentAuthRemote
{
    public Task<RemoteAccountRecentAuthResult> StartAsync(
        string accessToken,
        string currentPassword,
        CancellationToken cancellationToken) =>
        Task.FromException<RemoteAccountRecentAuthResult>(
            error);

    public Task<RemoteAccountRecentAuthResult> CompleteAsync(
        string accessToken,
        string challengeToken,
        string code,
        CancellationToken cancellationToken) =>
        Task.FromException<RemoteAccountRecentAuthResult>(
            error);
}

sealed class FakeGiftClaimsRemote(
    RemoteStoreGiftClaimsListResult list,
    RemoteStoreGiftClaimPersistentRevealResult reveal)
    : IStoreGiftClaimsRemote
{
    public int ListCalls { get; private set; }
    public int RevealCalls { get; private set; }
    public string? LastAccessToken { get; private set; }

    public Task<RemoteStoreGiftClaimsListResult> ListAsync(
        string accessToken,
        string correlationId,
        CancellationToken cancellationToken)
    {
        ListCalls += 1;
        LastAccessToken = accessToken;
        return Task.FromResult(list);
    }

    public Task<RemoteStoreGiftClaimPersistentRevealResult>
        RevealAsync(
            string accessToken,
            string correlationId,
            string giftClaimHandle,
            CancellationToken cancellationToken)
    {
        RevealCalls += 1;
        LastAccessToken = accessToken;
        return Task.FromResult(reveal);
    }
}

sealed class ThrowingGiftClaimsRemote(Exception error)
    : IStoreGiftClaimsRemote
{
    public Task<RemoteStoreGiftClaimsListResult> ListAsync(
        string accessToken,
        string correlationId,
        CancellationToken cancellationToken) =>
        Task.FromException<RemoteStoreGiftClaimsListResult>(
            error);

    public Task<RemoteStoreGiftClaimPersistentRevealResult>
        RevealAsync(
            string accessToken,
            string correlationId,
            string giftClaimHandle,
            CancellationToken cancellationToken) =>
        Task.FromException<RemoteStoreGiftClaimPersistentRevealResult>(
            error);
}

sealed class PersistentGiftTransportHandler(
    HttpStatusCode statusCode,
    string json,
    string expectedToken,
    string expectedPath,
    int transientFailures = 0,
    bool includeProtocol = true,
    bool throwTransport = false) : HttpMessageHandler
{
    private JsonDocument? _lastBody;

    public int RequestCount { get; private set; }
    public bool SawBearer { get; private set; }
    public bool SawProtocol { get; private set; }
    public bool SawExpectedPath { get; private set; }

    public bool BodyHasKey(string key) =>
        _lastBody?.RootElement.TryGetProperty(
            key,
            out _) == true;

    public bool BodyContains(
        string key,
        string expected) =>
        _lastBody?.RootElement.TryGetProperty(
            key,
            out var value) == true &&
        value.ValueKind == JsonValueKind.String &&
        value.GetString() == expected;

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
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
                expectedPath;

        _lastBody?.Dispose();
        if (request.Content is not null)
        {
            var body = await request.Content.ReadAsStringAsync(
                cancellationToken);
            _lastBody = JsonDocument.Parse(body);
        }

        if (throwTransport)
        {
            throw new HttpRequestException(
                "certified transport failure");
        }

        var transient = RequestCount <= transientFailures;
        var response = new HttpResponseMessage(
            transient
                ? HttpStatusCode.ServiceUnavailable
                : statusCode)
        {
            Content = new StringContent(
                transient
                    ? """{"error":"RATE_LIMITED"}"""
                    : json,
                Encoding.UTF8,
                "application/json"),
        };

        if (includeProtocol)
        {
            response.Headers.TryAddWithoutValidation(
                "x-bke-account-session-version",
                AccountSessionRemote.ProtocolVersion);
        }

        return response;
    }
}
