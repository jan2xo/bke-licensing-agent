using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;
using BKE.LicensingAgent.Storage;
using BKE.LicensingAgent.Infrastructure;
using Microsoft.Data.Sqlite;

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
Require(AgentDatabase.CurrentSchemaVersion == LocalAgentContract.StorageSchemaVersion, "shared storage schema constant drifted");
Require(storage.GetProperty("fresh_bootstrap_required").GetBoolean(), "fresh storage bootstrap requirement drifted");
Require(storage.GetProperty("discovered_product_registration_owner").GetString() == "privileged-provision", "discovered-product registration ownership drifted");

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
    $"POST {LocalAgentContract.AccountSessionStartPath}",
    $"POST {LocalAgentContract.AccountSessionStatusPath}",
    $"POST {LocalAgentContract.AccountSessionLogoutPath}",
    $"POST {LocalAgentContract.SoftwareCatalogPath}",
    $"POST {LocalAgentContract.SoftwareInstallPath}",
    $"POST {LocalAgentContract.SoftwareOpenPath}",
};
Require(inventoryRoutes.SetEquals(contractRoutes), "current route inventory mismatch");

var update = capabilities.GetProperty("updates");
Require(update.GetProperty("capability_id").GetString() == LocalAgentContract.UpdateCapabilityId, "update capability id mismatch");
Require(update.GetProperty("contract_version").GetInt32() == LocalAgentContract.UpdateContractVersion, "update contract version mismatch");

var typedNotifications = capabilities.GetProperty("typed_notifications");
Require(typedNotifications.GetProperty("capability_id").GetString() == LocalAgentContract.TypedNotificationCapabilityId, "typed-notification capability id mismatch");
Require(typedNotifications.GetProperty("contract_version").GetInt32() == LocalAgentContract.TypedNotificationContractVersion, "typed-notification contract version mismatch");

var accountSession = capabilities.GetProperty("account_session");
Require(accountSession.GetProperty("capability_id").GetString() == LocalAgentContract.AccountSessionCapabilityId, "account-session capability id mismatch");
Require(accountSession.GetProperty("contract_version").GetInt32() == LocalAgentContract.AccountSessionContractVersion, "account-session contract version mismatch");
Require(accountSession.GetProperty("secret_owner").GetString() == "bke-licensing-agent", "account-session secret ownership drifted");
Require(accountSession.GetProperty("local_responses_expose_tokens").GetBoolean() == false, "account-session local secret exposure drifted");

var softwareCatalog = capabilities.GetProperty("software_catalog");
Require(softwareCatalog.GetProperty("capability_id").GetString() == LocalAgentContract.SoftwareCatalogCapabilityId, "software-catalog capability id mismatch");
Require(softwareCatalog.GetProperty("contract_version").GetInt32() == LocalAgentContract.SoftwareCatalogContractVersion, "software-catalog contract version mismatch");
Require(softwareCatalog.GetProperty("execution_type_owner").GetString() == "bke-digital-solutions", "software-catalog execution policy ownership drifted");
Require(softwareCatalog.GetProperty("installation_state_owner").GetString() == "bke-licensing-agent", "software-catalog installation-state ownership drifted");
Require(softwareCatalog.GetProperty("local_responses_expose_cloud_tokens").GetBoolean() == false, "software-catalog cloud secret exposure drifted");
Require(softwareCatalog.GetProperty("execution_types").EnumerateArray().Select(value => value.GetString()).ToHashSet(StringComparer.Ordinal)
    .SetEquals(["LAUNCHER_PLUGIN", "STANDALONE"]), "software-catalog execution types drifted");

var softwareInstall = capabilities.GetProperty("software_install");
Require(softwareInstall.GetProperty("capability_id").GetString() == LocalAgentContract.SoftwareInstallCapabilityId, "software-install capability id mismatch");
Require(softwareInstall.GetProperty("contract_version").GetInt32() == LocalAgentContract.SoftwareInstallContractVersion, "software-install contract version mismatch");
Require(softwareInstall.GetProperty("cloud_authorization_owner").GetString() == "bke-digital-solutions", "software-install cloud authorization ownership drifted");
Require(softwareInstall.GetProperty("release_authority").GetString() == "github-releases", "software-install release authority drifted");
Require(softwareInstall.GetProperty("privileged_install_owner").GetString() == "bke-licensing-agent", "software-install privileged authority drifted");
Require(softwareInstall.GetProperty("local_request_fields").EnumerateArray().Select(value => value.GetString()).ToArray()
    .SequenceEqual(["correlation_id", "product_id"]), "software-install local request widened");
Require(softwareInstall.GetProperty("local_responses_expose_cloud_tokens").GetBoolean() == false, "software-install cloud token exposure drifted");
Require(softwareInstall.GetProperty("local_responses_expose_download_urls").GetBoolean() == false, "software-install download URL exposure drifted");
Require(softwareInstall.GetProperty("local_responses_expose_install_paths").GetBoolean() == false, "software-install path exposure drifted");
Require(softwareInstall.GetProperty("fresh_database_bootstrap_owner").GetString() == "bke-licensing-agent", "software-install fresh bootstrap ownership drifted");
Require(softwareInstall.GetProperty("provision_commit_requires_inventory_registration").GetBoolean(), "software-install inventory commit requirement drifted");

var softwareOpen = capabilities.GetProperty("software_open");
Require(softwareOpen.GetProperty("capability_id").GetString() == LocalAgentContract.SoftwareOpenCapabilityId, "software-open capability id mismatch");
Require(softwareOpen.GetProperty("contract_version").GetInt32() == LocalAgentContract.SoftwareOpenContractVersion, "software-open contract version mismatch");
Require(softwareOpen.GetProperty("catalog_recheck_required").GetBoolean(), "software-open catalog recheck was disabled");
Require(softwareOpen.GetProperty("execution_type_required").GetString() == "STANDALONE", "software-open execution type drifted");
Require(softwareOpen.GetProperty("launch_owner").GetString() == "bke-licensing-agent", "software-open launch ownership drifted");
Require(softwareOpen.GetProperty("local_request_fields").EnumerateArray().Select(value => value.GetString()).ToArray()
    .SequenceEqual(["correlation_id", "product_id"]), "software-open local request widened");
Require(softwareOpen.GetProperty("local_responses_expose_entry_point").GetBoolean() == false, "software-open entry-point exposure drifted");
Require(softwareOpen.GetProperty("local_responses_expose_install_path").GetBoolean() == false, "software-open install-path exposure drifted");

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
Require(JsonName<AccountSessionStartRequest>(nameof(AccountSessionStartRequest.CorrelationId)) == "correlation_id", "account-session start correlation_id wire name mismatch");
Require(JsonName<AccountSessionStatusRequest>(nameof(AccountSessionStatusRequest.CorrelationId)) == "correlation_id", "account-session status correlation_id wire name mismatch");
Require(JsonName<AccountSessionLogoutRequest>(nameof(AccountSessionLogoutRequest.CorrelationId)) == "correlation_id", "account-session logout correlation_id wire name mismatch");
Require(JsonName<SoftwareCatalogRequest>(nameof(SoftwareCatalogRequest.CorrelationId)) == "correlation_id", "software-catalog correlation_id wire name mismatch");
Require(JsonName<SoftwareCatalogItem>(nameof(SoftwareCatalogItem.ExecutionType)) == "execution_type", "software-catalog execution_type wire name mismatch");
Require(JsonName<SoftwareCatalogItem>(nameof(SoftwareCatalogItem.InstalledVersion)) == "installed_version", "software-catalog installed_version wire name mismatch");
Require(JsonName<SoftwareInstallRequest>(nameof(SoftwareInstallRequest.CorrelationId)) == "correlation_id", "software-install correlation_id wire name mismatch");
Require(JsonName<SoftwareInstallRequest>(nameof(SoftwareInstallRequest.ProductId)) == "product_id", "software-install product_id wire name mismatch");
Require(JsonName<SoftwareOpenRequest>(nameof(SoftwareOpenRequest.CorrelationId)) == "correlation_id", "software-open correlation_id wire name mismatch");
Require(JsonName<SoftwareOpenRequest>(nameof(SoftwareOpenRequest.ProductId)) == "product_id", "software-open product_id wire name mismatch");

Require(MethodNames<IAuthorizationService>().SetEquals(["AuthorizeAsync"]), "authorization port drifted");
Require(MethodNames<IActivationService>().SetEquals(["ActivateAsync"]), "activation port drifted");
Require(MethodNames<ILicenseCenterService>().SetEquals(["OpenAsync"]), "License Center port drifted");
Require(MethodNames<INotificationService>().SetEquals(["RequestAsync", "FeedAsync", "MarkReadAsync", "DismissAsync", "UnreadCountAsync"]), "notification port drifted");
Require(MethodNames<IUpdateService>().SetEquals(["CheckAsync", "OpenCenterAsync"]), "update port drifted");
Require(MethodNames<IAccountSessionService>().SetEquals(["StartAsync", "StatusAsync", "LogoutAsync"]), "account-session port drifted");
Require(MethodNames<ISoftwareCatalogService>().SetEquals(["GetAsync"]), "software-catalog port drifted");
Require(MethodNames<ISoftwareInstallService>().SetEquals(["InstallAsync"]), "software-install port drifted");
Require(MethodNames<ISoftwareOpenService>().SetEquals(["OpenAsync"]), "software-open port drifted");

CertifyRuntimeEnvironmentBoundary();
CertifyFreshStorageBootstrap(storage);
CertifyNotificationSchemaUpgrade();
await CertifyAccountSessionStateMachine();
await CertifySoftwareCatalogBoundary();
await CertifySoftwareInstallBoundary();
await CertifySoftwareOpenBoundary();

var notificationColumns = storage.GetProperty("tables").GetProperty("notifications")
    .EnumerateArray().Select(value => value.GetString()).ToHashSet(StringComparer.Ordinal);
Require(!notificationColumns.Contains("delivery_mode"), "EVERY_LAUNCH must not force a durable delivery_mode column");
Require(notificationColumns.Contains("title") && notificationColumns.Contains("body") && notificationColumns.Contains("source") && notificationColumns.Contains("category"),
    "notification presentation ownership columns are missing");

Console.WriteLine("BKE Licensing Agent .NET 10 Gen2 contract certification: PASS");
Console.WriteLine($"Routes certified: {contractRoutes.Count}");
Console.WriteLine($"SQLite schema certified: {LocalAgentContract.StorageSchemaVersion}");
Console.WriteLine("Account-session device authorization state machine certified");
Console.WriteLine("Software catalog authority and secret boundary certified");
Console.WriteLine("Software install authority, release-source, and secret boundary certified");
Console.WriteLine("Software open entitlement, execution-type, and path-hiding boundary certified");
return;

static void CertifyRuntimeEnvironmentBoundary()
{
    var root = Path.Combine(
        Path.GetTempPath(),
        "bke-agent-env-cert-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(root);
    var envPath = Path.Combine(root, ".env");

    var originalEnvironment =
        Environment.GetEnvironmentVariable(
            AgentRuntimeEnvironmentLoader.EnvironmentVariableName);
    var originalPlatform =
        Environment.GetEnvironmentVariable(
            AgentRuntimeEnvironmentLoader.PlatformBaseUrlVariableName);
    var originalInsecure =
        Environment.GetEnvironmentVariable(
            "BKE_AGENT_VNEXT_ALLOW_INSECURE_LOCAL");

    try
    {
        Environment.SetEnvironmentVariable(
            AgentRuntimeEnvironmentLoader.EnvironmentVariableName,
            null,
            EnvironmentVariableTarget.Process);
        Environment.SetEnvironmentVariable(
            AgentRuntimeEnvironmentLoader.PlatformBaseUrlVariableName,
            "https://jl-bke.com",
            EnvironmentVariableTarget.Process);

        File.WriteAllText(
            envPath,
            "BKE_ENVIRONMENT=utm\n" +
            "BKE_PLATFORM_BASE_URL=https://utm-bke.invalid\n");

        var loaded = AgentRuntimeEnvironmentLoader.Load(envPath);
        Require(
            loaded.Name == AgentRuntimeEnvironmentLoader.UtmEnvironment,
            "Agent .env did not select UTM environment");
        Require(
            loaded.PlatformBaseUrl == "https://utm-bke.invalid",
            "Agent .env did not override stray process-level platform authority");

        File.WriteAllText(
            envPath,
            "BKE_ENVIRONMENT=utm\n" +
            "BKE_PLATFORM_BASE_URL=https://jl-bke.com\n");
        RequireThrows<InvalidOperationException>(
            () => AgentRuntimeEnvironmentLoader.Load(envPath),
            "UTM environment accepted production Digital Solutions authority");

        File.WriteAllText(
            envPath,
            "BKE_ENVIRONMENT=utm\n");
        Environment.SetEnvironmentVariable(
            AgentRuntimeEnvironmentLoader.PlatformBaseUrlVariableName,
            null,
            EnvironmentVariableTarget.Process);
        RequireThrows<InvalidOperationException>(
            () => AgentRuntimeEnvironmentLoader.Load(envPath),
            "UTM environment accepted a missing Digital Solutions authority");

        File.WriteAllText(
            envPath,
            "BKE_ENVIRONMENT=utm\n" +
            "BKE_PLATFORM_BASE_URL=http://127.0.0.1:3000\n" +
            "BKE_AGENT_VNEXT_ALLOW_INSECURE_LOCAL=1\n");
        loaded = AgentRuntimeEnvironmentLoader.Load(envPath);
        Require(
            loaded.PlatformBaseUrl == "http://127.0.0.1:3000",
            "Agent .env did not preserve disposable loopback authority");

        RequireThrows<InvalidDataException>(
            () => AgentRuntimeEnvironmentLoader.Parse(
                "BKE_AGENT_DATA_DIR=C:\\unsafe\n"),
            "Agent .env accepted installer-owned data directory override");
    }
    finally
    {
        Environment.SetEnvironmentVariable(
            AgentRuntimeEnvironmentLoader.EnvironmentVariableName,
            originalEnvironment,
            EnvironmentVariableTarget.Process);
        Environment.SetEnvironmentVariable(
            AgentRuntimeEnvironmentLoader.PlatformBaseUrlVariableName,
            originalPlatform,
            EnvironmentVariableTarget.Process);
        Environment.SetEnvironmentVariable(
            "BKE_AGENT_VNEXT_ALLOW_INSECURE_LOCAL",
            originalInsecure,
            EnvironmentVariableTarget.Process);

        try { Directory.Delete(root, recursive: true); } catch { }
    }
}

static void RequireThrows<TException>(
    Action action,
    string message)
    where TException : Exception
{
    try
    {
        action();
    }
    catch (TException)
    {
        return;
    }

    throw new InvalidOperationException(message);
}

static void CertifyFreshStorageBootstrap(JsonElement storage)
{
    var root = Path.Combine(
        Path.GetTempPath(),
        "bke-agent-storage-cert-" + Guid.NewGuid().ToString("N"));
    try
    {
        Require(!File.Exists(Path.Combine(root, "agent.db")), "fresh storage certification was not fresh");
        AgentDatabase.EnsureInitialized(root);

        var databasePath = AgentDatabase.DatabasePath(root);
        Require(File.Exists(databasePath), "fresh storage bootstrap did not create agent.db");

        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadOnly,
        }.ToString());
        connection.Open();

        using (var schema = connection.CreateCommand())
        {
            schema.CommandText = "SELECT version FROM schema_version LIMIT 1";
            Require(
                Convert.ToInt32(schema.ExecuteScalar()) == LocalAgentContract.StorageSchemaVersion,
                "fresh storage did not reach certified schema version");
        }

        var expectedTables = storage.GetProperty("tables")
            .EnumerateObject()
            .Select(property => property.Name)
            .ToHashSet(StringComparer.Ordinal);

        using var tables = connection.CreateCommand();
        tables.CommandText = """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
              AND name NOT LIKE 'sqlite_%'
            """;
        using var reader = tables.ExecuteReader();
        var actualTables = new HashSet<string>(StringComparer.Ordinal);
        while (reader.Read())
        {
            actualTables.Add(reader.GetString(0));
        }

        Require(actualTables.SetEquals(expectedTables), "fresh storage table inventory drifted");

        var expectedNotificationColumns = storage.GetProperty("tables")
            .GetProperty("notifications")
            .EnumerateArray()
            .Select(value => value.GetString()!)
            .ToArray();
        using var notificationColumns = connection.CreateCommand();
        notificationColumns.CommandText = "PRAGMA table_info(notifications)";
        using var notificationReader = notificationColumns.ExecuteReader();
        var actualNotificationColumns = new List<string>();
        while (notificationReader.Read())
        {
            actualNotificationColumns.Add(notificationReader.GetString(1));
        }
        Require(
            actualNotificationColumns.SequenceEqual(expectedNotificationColumns),
            "fresh notification storage columns drifted");
    }
    finally
    {
        try { Directory.Delete(root, recursive: true); } catch { }
    }
}

static void CertifyNotificationSchemaUpgrade()
{
    var root = Path.Combine(
        Path.GetTempPath(),
        "bke-agent-notification-v8-upgrade-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(root);
    try
    {
        var path = AgentDatabase.DatabasePath(root);
        using (var connection = new SqliteConnection(
            new SqliteConnectionStringBuilder
            {
                DataSource = path,
                Mode = SqliteOpenMode.ReadWriteCreate,
            }.ToString()))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = """
                CREATE TABLE schema_version (version INTEGER NOT NULL);
                INSERT INTO schema_version(version) VALUES (8);
                CREATE TABLE notifications (
                    id TEXT PRIMARY KEY,
                    product_id TEXT NOT NULL,
                    code TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    state TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    dismissed_at TEXT,
                    UNIQUE(product_id, code)
                );
                INSERT INTO notifications (
                    id, product_id, code, severity, state,
                    created_at, expires_at, dismissed_at
                ) VALUES (
                    'legacy-notification',
                    'bke-render-dock',
                    'BETA_ENDED',
                    'warning',
                    'read',
                    '2026-09-20T00:00:00.0000000+00:00',
                    NULL,
                    NULL
                );
                """;
            command.ExecuteNonQuery();
        }

        AgentDatabase.EnsureInitialized(root);

        using var upgraded = new SqliteConnection(
            new SqliteConnectionStringBuilder
            {
                DataSource = path,
                Mode = SqliteOpenMode.ReadWrite,
            }.ToString());
        upgraded.Open();

        using (var version = upgraded.CreateCommand())
        {
            version.CommandText = "SELECT version FROM schema_version LIMIT 1";
            Require(
                Convert.ToInt32(version.ExecuteScalar()) ==
                    LocalAgentContract.StorageSchemaVersion,
                "notification v8 upgrade did not reach current schema");
        }

        using (var preserved = upgraded.CreateCommand())
        {
            preserved.CommandText = """
                SELECT state, source, title, body, category
                FROM notifications
                WHERE id='legacy-notification'
                """;
            using var reader = preserved.ExecuteReader();
            Require(reader.Read(), "notification v8 row was not preserved");
            Require(reader.GetString(0) == "read", "notification read state was not preserved");
            Require(reader.IsDBNull(1) && reader.IsDBNull(2) &&
                    reader.IsDBNull(3) && reader.IsDBNull(4),
                "legacy notification unexpectedly gained fabricated presentation");
        }

        using (var multiple = upgraded.CreateCommand())
        {
            multiple.CommandText = """
                INSERT INTO notifications (
                    id, product_id, code, source, title, body, category,
                    severity, state, created_at, expires_at, dismissed_at
                ) VALUES
                (
                    'account-payment-1',
                    'bke-render-dock',
                    'PAYMENT_RECEIVED',
                    'payments',
                    'Payment received',
                    'Payment confirmed.',
                    'General',
                    'information',
                    'unread',
                    '2026-09-20T01:00:00.0000000+00:00',
                    NULL,
                    NULL
                ),
                (
                    'account-payment-2',
                    'bke-render-dock',
                    'PAYMENT_RECEIVED',
                    'payments',
                    'Payment received',
                    'Another payment confirmed.',
                    'General',
                    'information',
                    'unread',
                    '2026-09-20T02:00:00.0000000+00:00',
                    NULL,
                    NULL
                );
                """;
            Require(
                multiple.ExecuteNonQuery() == 2,
                "schema v9 did not permit multiple account notifications per code");
        }
    }
    finally
    {
        try { Directory.Delete(root, recursive: true); } catch { }
    }
}

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
        RefreshExpiresIn: TimeSpan.FromDays(30),
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
    if (store.State is not ActiveAccountSessionState active)
    {
        throw new InvalidOperationException(
            "approved remote secrets were not retained by the secret-store boundary");
    }
    Require(active.AccessToken == "access-secret",
        "approved remote access token was not retained by the secret-store boundary");
    Require(active.RefreshToken == "refresh-secret",
        "approved remote refresh token was not retained by the secret-store boundary");
    Require(remote.AcknowledgeCount == 1, "approved handoff was not acknowledged after secure-store write");

    clock.Advance(TimeSpan.FromMinutes(29));
    remote.Refreshes.Enqueue(new RemoteAccountSessionRefresh(
        "refreshed",
        AccessToken: "access-secret-2",
        RefreshToken: "refresh-secret-2",
        SessionId: "session-1",
        ExpiresIn: TimeSpan.FromMinutes(30),
        RefreshExpiresIn: TimeSpan.FromDays(29),
        Account: active.Account));
    var refreshed = await service.StatusAsync(
        new AccountSessionStatusRequest("cert-refresh"),
        CancellationToken.None);
    Require(refreshed.Status == "AUTHENTICATED", "account-session refresh did not remain authenticated");
    Require(remote.RefreshCount == 1, "account-session refresh did not call remote");
    Require(store.State is ActiveAccountSessionState rotated &&
            rotated.AccessToken == "access-secret-2" &&
            rotated.RefreshToken == "refresh-secret-2",
        "rotated account-session secrets did not replace the previous secure-store state");

    remote.ThrowOnRevoke = true;
    var logout = await service.LogoutAsync(
        new AccountSessionLogoutRequest("cert-logout"),
        CancellationToken.None);
    Require(logout.Status == "SIGNED_OUT", "logout did not clear local authority");
    Require(logout.Error?.Code == "REMOTE_REVOKE_FAILED", "remote revoke failure was not surfaced");
    Require(store.State is null, "local account session survived logout revoke failure");
}

static async Task CertifySoftwareCatalogBoundary()
{
    var account = new AccountSessionAccount(
        "user-catalog",
        "buyer@example.com",
        "account-catalog",
        "INDIVIDUAL",
        "Catalog Buyer");
    var store = new FakeAccountSessionStore();
    await store.WriteAsync(
        new ActiveAccountSessionState(
            "catalog-access-secret",
            "catalog-refresh-secret",
            "catalog-session",
            DateTimeOffset.UtcNow.AddMinutes(15),
            DateTimeOffset.UtcNow.AddDays(30),
            account),
        CancellationToken.None);

    var remote = new FakeSoftwareCatalogRemote([
        new RemoteSoftwareCatalogItem(
            "bke-render-dock",
            "Render Dock",
            "Standalone rendering product",
            "STANDALONE",
            true,
            true,
            "2.0.0"),
        new RemoteSoftwareCatalogItem(
            "bke-plugin-tool",
            "Plugin Tool",
            "Launcher-hosted tool",
            "LAUNCHER_PLUGIN",
            false,
            false,
            "1.0.0"),
    ]);
    var inventory = new FakeLocalProductInventory(
        new Dictionary<string, LocalInstalledProduct>(StringComparer.Ordinal)
        {
            ["bke-render-dock"] = new("bke-render-dock", "1.0.0"),
        });
    var service = new SoftwareCatalogService(
        new FakeAuthenticatedAccountSessionService(account),
        store,
        remote,
        inventory);

    var response = await service.GetAsync(
        new SoftwareCatalogRequest("cert-catalog"),
        CancellationToken.None);

    Require(response.Status == "READY", "software catalog did not become READY");
    Require(remote.AccessToken == "catalog-access-secret", "software catalog remote did not receive Agent-owned access token");
    Require(response.Items.Count == 2, "software catalog item count drifted");

    var renderDock = response.Items.Single(item => item.ProductId == "bke-render-dock");
    Require(renderDock.State == "UPDATE_AVAILABLE", "installed catalog update state drifted");
    Require(renderDock.InstalledVersion == "1.0.0", "local installed version was not merged");
    Require(renderDock.LatestVersion == "2.0.0", "cloud latest version was not retained");
    Require(renderDock.ExecutionType == "STANDALONE", "cloud execution type was not retained");

    var plugin = response.Items.Single(item => item.ProductId == "bke-plugin-tool");
    Require(plugin.State == "NOT_ENTITLED", "non-entitled product state drifted");

    var wire = JsonSerializer.Serialize(response);
    Require(!wire.Contains("catalog-access-secret", StringComparison.Ordinal), "catalog access token leaked to local response");
    Require(!wire.Contains("catalog-refresh-secret", StringComparison.Ordinal), "catalog refresh token leaked to local response");
}

static async Task CertifySoftwareInstallBoundary()
{
    var account = new AccountSessionAccount(
        "user-install",
        "installer@example.com",
        "account-install",
        "INDIVIDUAL",
        "Install Buyer");
    var store = new FakeAccountSessionStore();
    await store.WriteAsync(
        new ActiveAccountSessionState(
            "install-access-secret",
            "install-refresh-secret",
            "install-session",
            DateTimeOffset.UtcNow.AddMinutes(15),
            DateTimeOffset.UtcNow.AddDays(30),
            account),
        CancellationToken.None);

    var remote = new FakeStandaloneProvisionAuthorizationRemote(
        new StandaloneProvisionAuthorizationResult(
            "AUTHORIZED",
            new StandaloneProvisionAuthorization(
                "bke-render-dock",
                "1.0.2",
                "jan2xo/BKE_RENDER_DOCK",
                "v1.0.2")));
    var provisioner = new FakeStandaloneSoftwareProvisioner(
        new StandaloneProvisioningResult(
            "STARTED",
            "provision_started",
            false));
    var inventory = new FakeLocalProductInventory(
        new Dictionary<string, LocalInstalledProduct>(
            StringComparer.Ordinal));
    var service = new SoftwareInstallService(
        new FakeAuthenticatedAccountSessionService(account),
        store,
        inventory,
        remote,
        provisioner);

    var response = await service.InstallAsync(
        new SoftwareInstallRequest(
            "cert-install",
            "bke-render-dock"),
        CancellationToken.None);

    Require(response.Status == "STARTED", "software install did not enter STARTED");
    Require(response.State == "provision_started", "software install state drifted");
    Require(remote.AccessToken == "install-access-secret", "software install remote did not receive Agent-owned access token");
    Require(remote.ProductId == "bke-render-dock", "software install remote product drifted");
    Require(provisioner.Authorization?.Repository == "jan2xo/BKE_RENDER_DOCK", "verified release authority did not reach the provisioner");

    var wire = JsonSerializer.Serialize(response);
    Require(!wire.Contains("install-access-secret", StringComparison.Ordinal), "install access token leaked to local response");
    Require(!wire.Contains("install-refresh-secret", StringComparison.Ordinal), "install refresh token leaked to local response");
    Require(!wire.Contains("github.com", StringComparison.OrdinalIgnoreCase), "GitHub release URL leaked to local response");
    Require(!wire.Contains("BKE_RENDER_DOCK", StringComparison.Ordinal), "GitHub repository identity leaked to local response");
    Require(!wire.Contains("Program Files", StringComparison.OrdinalIgnoreCase), "privileged install path leaked to local response");

    var denied = new SoftwareInstallService(
        new FakeAuthenticatedAccountSessionService(account),
        store,
        inventory,
        new FakeStandaloneProvisionAuthorizationRemote(
            new StandaloneProvisionAuthorizationResult(
                "NOT_ENTITLED")),
        provisioner);
    var deniedResponse = await denied.InstallAsync(
        new SoftwareInstallRequest(
            "cert-install-denied",
            "bke-render-dock"),
        CancellationToken.None);
    Require(deniedResponse.Error?.Code == "NOT_ENTITLED", "truthful install denial was flattened");
}

static async Task CertifySoftwareOpenBoundary()
{
    var account = new AccountSessionAccount(
        "user-open",
        "opener@example.com",
        "account-open",
        "INDIVIDUAL",
        "Open Buyer");
    var store = new FakeAccountSessionStore();
    await store.WriteAsync(
        new ActiveAccountSessionState(
            "open-access-secret",
            "open-refresh-secret",
            "open-session",
            DateTimeOffset.UtcNow.AddMinutes(15),
            DateTimeOffset.UtcNow.AddDays(30),
            account),
        CancellationToken.None);

    var remote = new FakeSoftwareCatalogRemote([
        new RemoteSoftwareCatalogItem(
            "bke-render-dock",
            "Render Dock",
            "Standalone rendering product",
            "STANDALONE",
            true,
            true,
            "1.0.2"),
    ]);
    var inventory = new FakeLocalProductInventory(
        new Dictionary<string, LocalInstalledProduct>(StringComparer.Ordinal)
        {
            ["bke-render-dock"] =
                new("bke-render-dock", "1.0.2"),
        });
    var catalog = new SoftwareCatalogService(
        new FakeAuthenticatedAccountSessionService(account),
        store,
        remote,
        inventory);
    var launcher = new FakeLocalProductLauncher(
        new LocalProductLaunchResult(
            "STARTED",
            "started",
            false));
    var service = new SoftwareOpenService(
        catalog,
        launcher);

    var response = await service.OpenAsync(
        new SoftwareOpenRequest(
            "cert-open",
            "bke-render-dock"),
        CancellationToken.None);

    Require(response.Status == "STARTED", "software open did not enter STARTED");
    Require(response.State == "started", "software open state drifted");
    Require(launcher.ProductId == "bke-render-dock", "software open launcher product drifted");

    var wire = JsonSerializer.Serialize(response);
    Require(!wire.Contains("Program Files", StringComparison.OrdinalIgnoreCase), "software open leaked an install path");
    Require(!wire.Contains("RENDER DOCK.exe", StringComparison.OrdinalIgnoreCase), "software open leaked an entry point");
    Require(!wire.Contains("open-access-secret", StringComparison.Ordinal), "software open leaked an account token");

    var deniedRemote = new FakeSoftwareCatalogRemote([
        new RemoteSoftwareCatalogItem(
            "bke-render-dock",
            "Render Dock",
            "Standalone rendering product",
            "STANDALONE",
            false,
            false,
            "1.0.2"),
    ]);
    var deniedCatalog = new SoftwareCatalogService(
        new FakeAuthenticatedAccountSessionService(account),
        store,
        deniedRemote,
        inventory);
    var deniedLauncher = new FakeLocalProductLauncher(
        new LocalProductLaunchResult(
            "STARTED",
            "started",
            false));
    var deniedService = new SoftwareOpenService(
        deniedCatalog,
        deniedLauncher);
    var denied = await deniedService.OpenAsync(
        new SoftwareOpenRequest(
            "cert-open-denied",
            "bke-render-dock"),
        CancellationToken.None);

    Require(denied.Error?.Code == "NOT_ENTITLED", "software open entitlement denial was flattened");
    Require(deniedLauncher.ProductId is null, "software open launched despite entitlement denial");

    var pluginRemote = new FakeSoftwareCatalogRemote([
        new RemoteSoftwareCatalogItem(
            "bke-plugin-tool",
            "Plugin Tool",
            "Launcher-hosted tool",
            "LAUNCHER_PLUGIN",
            true,
            true,
            "1.0.0"),
    ]);
    var pluginInventory = new FakeLocalProductInventory(
        new Dictionary<string, LocalInstalledProduct>(StringComparer.Ordinal)
        {
            ["bke-plugin-tool"] =
                new("bke-plugin-tool", "1.0.0"),
        });
    var pluginCatalog = new SoftwareCatalogService(
        new FakeAuthenticatedAccountSessionService(account),
        store,
        pluginRemote,
        pluginInventory);
    var pluginLauncher = new FakeLocalProductLauncher(
        new LocalProductLaunchResult(
            "STARTED",
            "started",
            false));
    var pluginService = new SoftwareOpenService(
        pluginCatalog,
        pluginLauncher);
    var plugin = await pluginService.OpenAsync(
        new SoftwareOpenRequest(
            "cert-open-plugin",
            "bke-plugin-tool"),
        CancellationToken.None);

    Require(plugin.Error?.Code == "UNSUPPORTED_EXECUTION_TYPE", "software open accepted Launcher plugin");
    Require(pluginLauncher.ProductId is null, "software open launched a Launcher plugin as standalone");
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
    public int RefreshCount { get; private set; }
    public int AcknowledgeCount { get; private set; }
    public bool ThrowOnRevoke { get; set; }
    public Queue<RemoteAccountSessionPoll> Polls { get; } = new();
    public Queue<RemoteAccountSessionRefresh> Refreshes { get; } = new();

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
        if (deviceCode != "device-secret")
        {
            throw new InvalidOperationException("secret-store device code drifted");
        }
        return Task.FromResult(Polls.Dequeue());
    }

    public Task<RemoteAccountSessionRefresh> RefreshAsync(
        string refreshToken,
        CancellationToken cancellationToken)
    {
        RefreshCount += 1;
        if (refreshToken != "refresh-secret")
        {
            throw new InvalidOperationException("refresh token drifted");
        }
        return Task.FromResult(Refreshes.Dequeue());
    }

    public Task AcknowledgeAsync(
        string accessToken,
        CancellationToken cancellationToken)
    {
        AcknowledgeCount += 1;
        if (accessToken != "access-secret")
        {
            throw new InvalidOperationException("handoff access token drifted");
        }
        return Task.CompletedTask;
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
sealed class FakeAuthenticatedAccountSessionService : IAccountSessionService
{
    private readonly AccountSessionAccount _account;

    public FakeAuthenticatedAccountSessionService(AccountSessionAccount account) =>
        _account = account;

    public Task<AccountSessionStartResponse> StartAsync(
        AccountSessionStartRequest request,
        CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task<AccountSessionStatusResponse> StatusAsync(
        AccountSessionStatusRequest request,
        CancellationToken cancellationToken) =>
        Task.FromResult(new AccountSessionStatusResponse(
            LocalAgentContract.AccountSessionCapabilityId,
            LocalAgentContract.AccountSessionContractVersion,
            "AUTHENTICATED",
            _account,
            null));

    public Task<AccountSessionLogoutResponse> LogoutAsync(
        AccountSessionLogoutRequest request,
        CancellationToken cancellationToken) =>
        throw new NotSupportedException();
}

sealed class FakeSoftwareCatalogRemote(
    IReadOnlyList<RemoteSoftwareCatalogItem> items) : ISoftwareCatalogRemote
{
    public string? AccessToken { get; private set; }

    public Task<IReadOnlyList<RemoteSoftwareCatalogItem>> GetAsync(
        string accessToken,
        CancellationToken cancellationToken)
    {
        AccessToken = accessToken;
        return Task.FromResult(items);
    }
}

sealed class FakeLocalProductInventory(
    IReadOnlyDictionary<string, LocalInstalledProduct> items) : ILocalProductInventory
{
    public Task<IReadOnlyDictionary<string, LocalInstalledProduct>> ReadAsync(
        CancellationToken cancellationToken) =>
        Task.FromResult(items);
}

sealed class FakeStandaloneProvisionAuthorizationRemote(
    StandaloneProvisionAuthorizationResult result)
    : IStandaloneProvisionAuthorizationRemote
{
    public string? AccessToken { get; private set; }
    public string? ProductId { get; private set; }

    public Task<StandaloneProvisionAuthorizationResult> AuthorizeAsync(
        string accessToken,
        string productId,
        CancellationToken cancellationToken)
    {
        AccessToken = accessToken;
        ProductId = productId;
        return Task.FromResult(result);
    }
}

sealed class FakeStandaloneSoftwareProvisioner(
    StandaloneProvisioningResult result)
    : IStandaloneSoftwareProvisioner
{
    public StandaloneProvisionAuthorization? Authorization { get; private set; }

    public Task<StandaloneProvisioningResult> ProvisionAsync(
        StandaloneProvisionAuthorization authorization,
        CancellationToken cancellationToken)
    {
        Authorization = authorization;
        return Task.FromResult(result);
    }
}

sealed class FakeLocalProductLauncher(
    LocalProductLaunchResult result)
    : ILocalProductLauncher
{
    public string? ProductId { get; private set; }

    public Task<LocalProductLaunchResult> OpenAsync(
        string productId,
        CancellationToken cancellationToken)
    {
        ProductId = productId;
        return Task.FromResult(result);
    }
}

