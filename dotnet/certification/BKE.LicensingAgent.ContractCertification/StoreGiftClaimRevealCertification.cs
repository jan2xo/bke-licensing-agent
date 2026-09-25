using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;
using BKE.LicensingAgent.Infrastructure;

public static class StoreGiftClaimRevealCertification
{
    public static async Task RunAsync()
    {
        Require(
            LocalAgentContract.StoreGiftClaimRevealPath == "/v1/store/gift-claim-code",
            "Store gift Claim Code local path drifted");
        Require(
            LocalAgentContract.StoreGiftClaimRevealCapabilityId == "bke.store-gift-claim-reveal",
            "Store gift Claim Code capability id drifted");
        Require(
            LocalAgentContract.StoreGiftClaimRevealContractVersion == 1,
            "Store gift Claim Code contract version drifted");
        Require(
            typeof(IStoreGiftClaimRevealService).GetMethods()
                .Select(method => method.Name)
                .ToHashSet(StringComparer.Ordinal)
                .SetEquals(["RevealAsync"]),
            "Store gift Claim Code service port drifted");

        var requestWire = JsonSerializer.Serialize(
            new StoreGiftClaimRevealRequest("cert-gift-reveal-correlation"));
        Require(
            requestWire == """{"correlation_id":"cert-gift-reveal-correlation"}""",
            "Store gift Claim Code request wire widened");

        var account = new AccountSessionAccount(
            "user-gift-reveal",
            "gift-buyer@example.com",
            "account-gift-reveal",
            "INDIVIDUAL",
            "Gift Buyer");
        var store = new GiftRevealFakeSecretStore();
        await store.WriteAsync(
            new ActiveAccountSessionState(
                "gift-reveal-access-secret",
                "gift-reveal-refresh-secret",
                "gift-reveal-session",
                DateTimeOffset.UtcNow.AddMinutes(15),
                DateTimeOffset.UtcNow.AddDays(30),
                account),
            CancellationToken.None);

        var remote = new GiftRevealFakeRemote(
            new RemoteStoreGiftClaimRevealResult(
                "available",
                "cert-gift-reveal-correlation",
                "order-gift-cert",
                "claim-gift-cert",
                "BKE-CLM-AAAAA-BBBBB-CCCCC-DDDDD-EEEEE-FFFFF"));
        var service = new StoreGiftClaimRevealService(
            new GiftRevealAuthenticatedSessionService(account),
            store,
            remote);
        var response = await service.RevealAsync(
            new StoreGiftClaimRevealRequest(
                "cert-gift-reveal-correlation"),
            CancellationToken.None);

        Require(response.Status == "AVAILABLE", "Gift Claim Code reveal did not become AVAILABLE");
        Require(response.OrderId == "order-gift-cert", "Gift Claim Code reveal order drifted");
        Require(response.ClaimCodeId == "claim-gift-cert", "Gift Claim Code id drifted");
        Require(
            response.ClaimCode == "BKE-CLM-AAAAA-BBBBB-CCCCC-DDDDD-EEEEE-FFFFF",
            "Gift Claim Code secret drifted");
        Require(
            remote.AccessToken == "gift-reveal-access-secret",
            "Gift Claim Code remote did not receive Agent-owned access token");
        Require(
            remote.CorrelationId == "cert-gift-reveal-correlation",
            "Gift Claim Code remote correlation drifted");

        var responseWire = JsonSerializer.Serialize(response);
        Require(
            !responseWire.Contains("gift-reveal-access-secret", StringComparison.Ordinal),
            "Gift Claim Code local response leaked cloud access token");
        Require(
            !responseWire.Contains("gift-reveal-refresh-secret", StringComparison.Ordinal),
            "Gift Claim Code local response leaked cloud refresh token");
        Require(
            !responseWire.Contains("account-gift-reveal", StringComparison.Ordinal),
            "Gift Claim Code local response leaked cloud account id");

        var deniedRemote = new GiftRevealFakeRemote(
            new RemoteStoreGiftClaimRevealResult(
                "available",
                "cert-gift-auth",
                "order-should-not-run",
                "claim-should-not-run",
                "BKE-CLM-11111-22222-33333-44444-55555-66666"));
        var deniedService = new StoreGiftClaimRevealService(
            new GiftRevealUnauthenticatedSessionService(),
            store,
            deniedRemote);
        var denied = await deniedService.RevealAsync(
            new StoreGiftClaimRevealRequest("cert-gift-auth"),
            CancellationToken.None);
        Require(denied.Status == "AUTH_REQUIRED", "Gift Claim Code reveal did not require authentication");
        Require(deniedRemote.AccessToken is null, "Gift Claim Code authority was called without authentication");

        const string availableJson = """
            {
              "status":"available",
              "correlation_id":"cert-gift-reveal-correlation",
              "order_id":"order-gift-cert",
              "claim_code_id":"claim-gift-cert",
              "claim_code":"BKE-CLM-AAAAA-BBBBB-CCCCC-DDDDD-EEEEE-FFFFF"
            }
            """;
        using var handler = new GiftRevealAuthorityHandler(
            HttpStatusCode.OK,
            availableJson);
        using var http = new HttpClient(handler);
        using var transport = new StoreGiftClaimRevealRemote(
            http,
            "https://jl-bke.com");
        var snapshot = await transport.RevealAsync(
            "transport-gift-reveal-secret",
            "cert-gift-reveal-correlation",
            CancellationToken.None);

        Require(snapshot.Status == "available", "Gift Claim Code transport status drifted");
        Require(snapshot.OrderId == "order-gift-cert", "Gift Claim Code transport order drifted");
        Require(snapshot.ClaimCodeId == "claim-gift-cert", "Gift Claim Code transport claim id drifted");
        Require(
            snapshot.ClaimCode == "BKE-CLM-AAAAA-BBBBB-CCCCC-DDDDD-EEEEE-FFFFF",
            "Gift Claim Code transport secret drifted");
        Require(handler.RequestCount == 1, "Gift Claim Code reveal was retried unexpectedly");
        Require(handler.SawBearer, "Gift Claim Code transport omitted Agent-owned bearer token");
        Require(handler.SawProtocol, "Gift Claim Code transport omitted account-session protocol");
        Require(handler.SawExpectedPath, "Gift Claim Code transport endpoint drifted");
        Require(handler.SawExactBody, "Gift Claim Code transport widened reveal request authority");

        using var pendingHandler = new GiftRevealAuthorityHandler(
            HttpStatusCode.OK,
            """
            {
              "status":"fulfillment_pending",
              "correlation_id":"cert-gift-reveal-correlation",
              "order_id":"order-gift-cert"
            }
            """);
        using var pendingHttp = new HttpClient(pendingHandler);
        using var pendingTransport = new StoreGiftClaimRevealRemote(
            pendingHttp,
            "https://jl-bke.com");
        var pending = await pendingTransport.RevealAsync(
            "transport-gift-reveal-secret",
            "cert-gift-reveal-correlation",
            CancellationToken.None);
        Require(
            pending.Status == "fulfillment_pending",
            "Gift Claim Code fulfillment-pending state drifted");

        using var terminalHandler = new GiftRevealAuthorityHandler(
            HttpStatusCode.Conflict,
            """{"status":"claim_code_already_used"}""");
        using var terminalHttp = new HttpClient(terminalHandler);
        using var terminalTransport = new StoreGiftClaimRevealRemote(
            terminalHttp,
            "https://jl-bke.com");
        var terminal = await terminalTransport.RevealAsync(
            "transport-gift-reveal-secret",
            "cert-gift-reveal-correlation",
            CancellationToken.None);
        Require(
            terminal.Status == "claim_code_already_used",
            "Gift Claim Code terminal state drifted");

        using var conflictHandler = new GiftRevealAuthorityHandler(
            HttpStatusCode.Conflict,
            """{"error":"CLAIM_CODE_CARDINALITY_CONFLICT"}""");
        using var conflictHttp = new HttpClient(conflictHandler);
        using var conflictTransport = new StoreGiftClaimRevealRemote(
            conflictHttp,
            "https://jl-bke.com");
        var conflict = await conflictTransport.RevealAsync(
            "transport-gift-reveal-secret",
            "cert-gift-reveal-correlation",
            CancellationToken.None);
        Require(
            conflict.ErrorCode == "CLAIM_CODE_CARDINALITY_CONFLICT",
            "Gift Claim Code conflict mapping drifted");

        using var widenedHandler = new GiftRevealAuthorityHandler(
            HttpStatusCode.OK,
            """
            {
              "status":"available",
              "correlation_id":"cert-gift-reveal-correlation",
              "order_id":"order-gift-cert",
              "claim_code_id":"claim-gift-cert",
              "claim_code":"BKE-CLM-AAAAA-BBBBB-CCCCC-DDDDD-EEEEE-FFFFF",
              "recipient_email":"must-not-be-authority@example.com"
            }
            """);
        using var widenedHttp = new HttpClient(widenedHandler);
        using var widenedTransport = new StoreGiftClaimRevealRemote(
            widenedHttp,
            "https://jl-bke.com");
        try
        {
            _ = await widenedTransport.RevealAsync(
                "transport-gift-reveal-secret",
                "cert-gift-reveal-correlation",
                CancellationToken.None);
            throw new InvalidOperationException(
                "Gift Claim Code transport accepted widened recipient authority");
        }
        catch (InvalidDataException)
        {
            // Strict root keys intentionally reject recipient identity or provider authority.
        }

        var correlationMismatchService = new StoreGiftClaimRevealService(
            new GiftRevealAuthenticatedSessionService(account),
            store,
            new GiftRevealFakeRemote(
                new RemoteStoreGiftClaimRevealResult(
                    "available",
                    "different-correlation",
                    "order-gift-cert",
                    "claim-gift-cert",
                    "BKE-CLM-AAAAA-BBBBB-CCCCC-DDDDD-EEEEE-FFFFF")));
        var mismatch = await correlationMismatchService.RevealAsync(
            new StoreGiftClaimRevealRequest("cert-gift-reveal-correlation"),
            CancellationToken.None);
        Require(
            mismatch.Status == "FAILED" &&
            mismatch.Error?.Code == "CORRELATION_MISMATCH",
            "Gift Claim Code correlation mismatch did not fail closed");
    }

    private static void Require(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }
}

sealed class GiftRevealFakeSecretStore : IAccountSessionSecretStore
{
    private AccountSessionStoredState? _state;

    public Task<AccountSessionStoredState?> ReadAsync(
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(_state);
    }

    public Task WriteAsync(
        AccountSessionStoredState state,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _state = state;
        return Task.CompletedTask;
    }

    public Task ClearAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _state = null;
        return Task.CompletedTask;
    }
}

sealed class GiftRevealAuthenticatedSessionService(
    AccountSessionAccount account) : IAccountSessionService
{
    public Task<AccountSessionStatusResponse> StatusAsync(
        AccountSessionStatusRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(new AccountSessionStatusResponse(
            LocalAgentContract.AccountSessionCapabilityId,
            LocalAgentContract.AccountSessionContractVersion,
            "AUTHENTICATED",
            account,
            null));
    }

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

sealed class GiftRevealUnauthenticatedSessionService : IAccountSessionService
{
    public Task<AccountSessionStatusResponse> StatusAsync(
        AccountSessionStatusRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(new AccountSessionStatusResponse(
            LocalAgentContract.AccountSessionCapabilityId,
            LocalAgentContract.AccountSessionContractVersion,
            "SIGNED_OUT",
            null,
            null));
    }

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

sealed class GiftRevealFakeRemote(
    RemoteStoreGiftClaimRevealResult result) : IStoreGiftClaimRevealRemote
{
    public string? AccessToken { get; private set; }
    public string? CorrelationId { get; private set; }

    public Task<RemoteStoreGiftClaimRevealResult> RevealAsync(
        string accessToken,
        string correlationId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        AccessToken = accessToken;
        CorrelationId = correlationId;
        return Task.FromResult(result);
    }
}

sealed class GiftRevealAuthorityHandler(
    HttpStatusCode statusCode,
    string json) : HttpMessageHandler
{
    public int RequestCount { get; private set; }
    public bool SawBearer { get; private set; }
    public bool SawProtocol { get; private set; }
    public bool SawExpectedPath { get; private set; }
    public bool SawExactBody { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        RequestCount += 1;
        SawBearer =
            request.Headers.Authorization?.Scheme == "Bearer" &&
            request.Headers.Authorization.Parameter ==
                "transport-gift-reveal-secret";
        SawProtocol =
            request.Headers.TryGetValues(
                "x-bke-account-session-version",
                out var versions) &&
            versions.SingleOrDefault() == AccountSessionRemote.ProtocolVersion;
        SawExpectedPath =
            request.Method == HttpMethod.Post &&
            request.RequestUri?.AbsolutePath ==
                "/api/agent-sessions/store/gift-claim-code";

        if (request.Content is not null)
        {
            var body = await request.Content.ReadAsStringAsync(cancellationToken);
            using var document = JsonDocument.Parse(body);
            var root = document.RootElement;
            var keys = root.EnumerateObject()
                .Select(property => property.Name)
                .ToHashSet(StringComparer.Ordinal);
            SawExactBody =
                keys.SetEquals(["correlation_id"]) &&
                root.GetProperty("correlation_id").GetString() ==
                    "cert-gift-reveal-correlation";
        }

        var response = new HttpResponseMessage(statusCode)
        {
            Content = new StringContent(
                json,
                Encoding.UTF8,
                "application/json"),
        };
        response.Headers.TryAddWithoutValidation(
            "x-bke-account-session-version",
            AccountSessionRemote.ProtocolVersion);
        return response;
    }
}
