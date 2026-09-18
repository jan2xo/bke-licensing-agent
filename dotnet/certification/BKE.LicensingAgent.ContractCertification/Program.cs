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

var notificationColumns = storage.GetProperty("tables").GetProperty("notifications")
    .EnumerateArray().Select(value => value.GetString()).ToHashSet(StringComparer.Ordinal);
Require(!notificationColumns.Contains("delivery_mode"), "EVERY_LAUNCH must not force a schema-8 delivery_mode column");

Console.WriteLine("BKE Licensing Agent .NET 10 Gen2 contract certification: PASS");
Console.WriteLine($"Routes certified: {contractRoutes.Count}");
Console.WriteLine($"SQLite schema certified: {LocalAgentContract.StorageSchemaVersion}");
return;

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
