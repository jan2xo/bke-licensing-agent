using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;

var inventoryPath = Path.Combine(AppContext.BaseDirectory, "certified-contract-baseline.json");
using var inventory = JsonDocument.Parse(File.ReadAllText(inventoryPath));
var root = inventory.RootElement;
var localApi = root.GetProperty("local_api");
var capabilities = root.GetProperty("capabilities");
var storage = root.GetProperty("storage");
Require(localApi.GetProperty("contract_id").GetString() == LocalAgentContract.ContractId, "contract id mismatch");
Require(localApi.GetProperty("contract_version").GetInt32() == LocalAgentContract.ContractVersion, "contract version mismatch");
Require(localApi.GetProperty("bind_host").GetString() == LocalAgentContract.BindHost, "bind host mismatch");
Require(localApi.GetProperty("default_port").GetInt32() == LocalAgentContract.DefaultPort, "default port mismatch");
Require(localApi.GetProperty("max_json_body_bytes").GetInt64() == LocalAgentContract.MaxJsonBodyBytes, "body limit mismatch");
Require(localApi.GetProperty("max_chunk_line_bytes").GetInt32() == LocalAgentContract.MaxChunkLineBytes, "chunk-line limit mismatch");
Require(storage.GetProperty("schema_version").GetInt32() == LocalAgentContract.StorageSchemaVersion, "storage schema mismatch");

var inventoryRoutes = localApi.GetProperty("routes")
    .EnumerateArray()
    .Select(route => $"{route.GetProperty("method").GetString()} {route.GetProperty("path").GetString()}")
    .ToHashSet(StringComparer.Ordinal);

var contractRoutes = new HashSet<string>(StringComparer.Ordinal)
{
    $"GET {LocalAgentContract.LicenseCenterBrowserPath}",
    $"POST {LocalAgentContract.AuthorizePath}",
    $"POST {LocalAgentContract.ActivatePath}",
    $"POST {LocalAgentContract.OpenLicenseCenterPath}",
    $"POST {LocalAgentContract.RequestNotificationPath}",
    $"POST {LocalAgentContract.NotificationFeedPath}",
    $"POST {LocalAgentContract.NotificationMarkReadPath}",
    $"POST {LocalAgentContract.NotificationDismissPath}",
    $"POST {LocalAgentContract.NotificationUnreadCountPath}",
    $"POST {LocalAgentContract.CheckUpdatesPath}",
    $"POST {LocalAgentContract.OpenUpdateCenterPath}",
};
Require(inventoryRoutes.SetEquals(contractRoutes), "current route inventory mismatch");

var update = capabilities.GetProperty("updates");
Require(update.GetProperty("capability_id").GetString() == LocalAgentContract.UpdateCapabilityId, "update capability id mismatch");
Require(update.GetProperty("contract_version").GetInt32() == LocalAgentContract.UpdateContractVersion, "update contract version mismatch");

var typedNotifications = capabilities.GetProperty("typed_notifications");
Require(typedNotifications.GetProperty("capability_id").GetString() == LocalAgentContract.TypedNotificationCapabilityId, "typed-notification capability id mismatch");
Require(typedNotifications.GetProperty("contract_version").GetInt32() == LocalAgentContract.TypedNotificationContractVersion, "typed-notification contract version mismatch");

var notificationInbox = capabilities.GetProperty("notification_inbox");
Require(notificationInbox.GetProperty("capability_id").GetString() == LocalAgentContract.NotificationInboxCapabilityId, "notification inbox capability id mismatch");
Require(notificationInbox.GetProperty("contract_version").GetInt32() == LocalAgentContract.NotificationInboxContractVersion, "notification inbox contract version mismatch");
Require(notificationInbox.GetProperty("feed_limit_min").GetInt32() == 1, "notification feed minimum changed");
Require(notificationInbox.GetProperty("feed_limit_max").GetInt32() == 200, "notification feed maximum changed");

Require(JsonName<AuthorizeRequest>(nameof(AuthorizeRequest.ProductId)) == "product_id", "authorize product_id wire name mismatch");
Require(JsonName<AuthorizeRequest>(nameof(AuthorizeRequest.InstallationId)) == "installation_id", "authorize installation_id wire name mismatch");
Require(JsonName<ActivateRequest>(nameof(ActivateRequest.LicenseKey)) == "license_key", "activation license_key wire name mismatch");
Require(JsonName<TypedNotificationRequest>(nameof(TypedNotificationRequest.Code)) == "code", "notification code wire name mismatch");
Require(JsonName<NotificationFeedRequest>(nameof(NotificationFeedRequest.IncludeDismissed)) == "include_dismissed", "notification include_dismissed wire name mismatch");
Require(JsonName<NotificationItem>(nameof(NotificationItem.DeliveryMode)) == "delivery_mode", "notification delivery_mode wire name mismatch");
Require(JsonName<UpdateCheckRequest>(nameof(UpdateCheckRequest.CurrentVersion)) == "current_version", "update current_version wire name mismatch");
Require(JsonName<UpdateCheckRequest>(nameof(UpdateCheckRequest.RequestedVersion)) == "requested_version", "update requested_version wire name mismatch");

Require(MethodNames<IAuthorizationService>().SetEquals(["AuthorizeAsync"]), "authorization port drifted");
Require(MethodNames<IActivationService>().SetEquals(["ActivateAsync"]), "activation port drifted");
Require(MethodNames<ILicenseCenterService>().SetEquals(["OpenAsync"]), "License Center port drifted");
Require(MethodNames<INotificationService>().SetEquals(["RequestAsync", "FeedAsync", "MarkReadAsync", "DismissAsync", "UnreadCountAsync"]), "notification port drifted");
Require(MethodNames<IUpdateService>().SetEquals(["CheckAsync", "OpenCenterAsync"]), "update port drifted");
Require(MethodNames<IAccountSessionService>().SetEquals(["StartAsync", "StatusAsync", "LogoutAsync"]), "account-session port drifted");

await CertifyAccountSessionStateMachine();

var notificationColumns = storage.GetProperty("tables").GetProperty("notifications")
    .EnumerateArray().Select(value => value.GetString()).ToHashSet(StringComparer.Ordinal);
Require(!notificationColumns.Contains("delivery_mode"), "EVERY_LAUNCH must not force a schema-8 delivery_mode column");

Console.WriteLine("BKE Licensing Agent .NET 10 Gen2 contract certification: PASS");
Console.WriteLine($"Routes certified: {contractRoutes.Count}");
Console.WriteLine($"SQLite schema certified: {LocalAgentContract.StorageSchemaVersion}");
Console.WriteLine("Account-session device authorization state machine certified");
return;

static async Task CertifyAccountSessionStateMachine()
{
    var clock = new ManualTimeProvider(new DateTimeOffset(2026, 9, 19, 3, 0, 0, TimeSpan.Zero));
    var remote = new FakeAccountSessionRemote();
    var store = new FakeAccountSessionStore();
    var service = new AccountSessionService(remote, store, clock);

    var start = await service.StartAsync(
        new AccountSessionStartRequest("cert-start"),
        CancellationToken.None);
    Require(start.Status == "PENDING", "account-session start did not enter PENDING");
    Require(start.VerificationUri == "https://jl-bke.com/device", "verification URI drifted");
    Require(start.UserCode == "BKE-ABCD", "user code drifted");
    Require(remote.StartCount == 1, "remote device authorization was not started exactly once");
    Require(!JsonSerializer.Serialize(start).Contains("device-secret", StringComparison.Ordinal), "device_code leaked to local response");
    Require(!JsonSerializer.Serialize(start).Contains("refresh-secret", StringComparison.Ordinal), "refresh token leaked to local response");

    var repeated = await service.StartAsync(
        new AccountSessionStartRequest("cert-repeat"),
        CancellationToken.None);
    Require(repeated.Status == "PENDING", "repeated start did not retain pending flow");
    Require(remote.StartCount == 1, "repeated start minted a second remote device authorization");

    remote.Polls.Enqueue(new RemoteAccountSessionPoll("authorization_pending"));
    var pending = await service.StatusAsync(
        new AccountSessionStatusRequest("cert-status-1"),
        CancellationToken.None);
    Require(pending.Status == "PENDING", "pending poll state drifted");
    Require(remote.PollCount == 1, "first device authorization poll missing");

    var throttled = await service.StatusAsync(
        new AccountSessionStatusRequest("cert-status-2"),
        CancellationToken.None);
    Require(throttled.Status == "PENDING", "poll throttle did not retain PENDING");
    Require(remote.PollCount == 1, "poll interval was not enforced");

    clock.Advance(TimeSpan.FromSeconds(5));
    remote.Polls.Enqueue(new RemoteAccountSessionPoll(
        "approved",
        AccessToken: "access-secret",
        RefreshToken: "refresh-secret",
        SessionId: "session-1",
        ExpiresIn: TimeSpan.FromMinutes(30),
        Account: new AccountSessionAccount(
            "user-1",
            "buyer@example.com",
            "account-1",
            "INDIVIDUAL",
            "Buyer")));
    var approved = await service.StatusAsync(
        new AccountSessionStatusRequest("cert-status-3"),
        CancellationToken.None);
    Require(approved.Status == "AUTHENTICATED", "approved device authorization did not authenticate");
    Require(approved.Account?.AccountId == "account-1", "approved account metadata drifted");
    var approvedWire = JsonSerializer.Serialize(approved);
    Require(!approvedWire.Contains("access-secret", StringComparison.Ordinal), "access token leaked to local status");
    Require(!approvedWire.Contains("refresh-secret", StringComparison.Ordinal), "refresh token leaked to local status");
    Require(store.State is ActiveAccountSessionState active &&
            active.AccessToken == "access-secret" &&
            active.RefreshToken == "refresh-secret",
        "approved remote secrets were not retained by the secret-store boundary");

    remote.ThrowOnRevoke = true;
    var logout = await service.LogoutAsync(
        new AccountSessionLogoutRequest("cert-logout"),
        CancellationToken.None);
    Require(logout.Status == "SIGNED_OUT", "logout did not clear local authority");
    Require(logout.Error?.Code == "REMOTE_REVOKE_FAILED", "remote revoke failure was not surfaced");
    Require(store.State is null, "local account session survived logout revoke failure");
}

sealed class ManualTimeProvider : TimeProvider
{
    private DateTimeOffset _now;

    public ManualTimeProvider(DateTimeOffset now) => _now = now;

    public override DateTimeOffset GetUtcNow() => _now;

    public void Advance(TimeSpan duration) => _now = _now.Add(duration);
}

sealed class FakeAccountSessionStore : IAccountSessionSecretStore
{
    public AccountSessionStoredState? State { get; private set; }

    public Task<AccountSessionStoredState?> ReadAsync(CancellationToken cancellationToken) =>
        Task.FromResult(State);

    public Task WriteAsync(AccountSessionStoredState state, CancellationToken cancellationToken)
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

sealed class FakeAccountSessionRemote : IAccountSessionRemote
{
    public int StartCount { get; private set; }
    public int PollCount { get; private set; }
    public bool ThrowOnRevoke { get; set; }
    public Queue<RemoteAccountSessionPoll> Polls { get; } = new();

    public Task<RemoteAccountSessionStart> StartAsync(CancellationToken cancellationToken)
    {
        StartCount += 1;
        return Task.FromResult(new RemoteAccountSessionStart(
            "device-secret",
            "https://jl-bke.com/device",
            "BKE-ABCD",
            TimeSpan.FromMinutes(10),
            TimeSpan.FromSeconds(5)));
    }

    public Task<RemoteAccountSessionPoll> PollAsync(
        string deviceCode,
        CancellationToken cancellationToken)
    {
        PollCount += 1;
        Require(deviceCode == "device-secret", "secret-store device code drifted");
        return Task.FromResult(Polls.Dequeue());
    }

    public Task RevokeAsync(
        string? sessionId,
        string? refreshToken,
        string? deviceCode,
        CancellationToken cancellationToken)
    {
        if (ThrowOnRevoke) throw new HttpRequestException("certified remote revoke failure");
        return Task.CompletedTask;
    }
}

static HashSet<string> MethodNames<T>() =>
    typeof(T).GetMethods().Select(method => method.Name).ToHashSet(StringComparer.Ordinal);

static string JsonName<T>(string propertyName)
{
    var property = typeof(T).GetProperty(propertyName)
        ?? throw new InvalidOperationException($"Missing property {typeof(T).Name}.{propertyName}");
    return property.GetCustomAttribute<JsonPropertyNameAttribute>()?.Name
        ?? throw new InvalidOperationException($"Missing JsonPropertyName on {typeof(T).Name}.{propertyName}");
}

static void Require(bool condition, string message)
{
    if (!condition)
    {
        throw new InvalidOperationException(message);
    }
}
