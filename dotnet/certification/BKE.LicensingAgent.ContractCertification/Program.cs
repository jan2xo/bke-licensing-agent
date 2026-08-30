using System.Text.Json;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;

static void Require(bool condition, string message)
{
    if (!condition)
    {
        throw new InvalidOperationException(message);
    }
}

var manifestPath = Path.Combine(AppContext.BaseDirectory, "local-api-v1.json");
using var manifest = JsonDocument.Parse(File.ReadAllText(manifestPath));
var root = manifest.RootElement;

Require(root.GetProperty("contract_id").GetString() == LocalAgentContract.ContractId, "Contract id drifted.");
Require(root.GetProperty("contract_version").GetInt32() == LocalAgentContract.ContractVersion, "Contract version drifted.");
Require(root.GetProperty("bind_host").GetString() == LocalAgentContract.BindHost, "Loopback bind host drifted.");
Require(root.GetProperty("default_port").GetInt32() == LocalAgentContract.DefaultPort, "Default port drifted.");
Require(root.GetProperty("max_json_body_bytes").GetInt64() == LocalAgentContract.MaxJsonBodyBytes, "Body limit drifted.");

var expectedRoutes = new HashSet<string>(StringComparer.Ordinal)
{
    $"GET {LocalAgentContract.LicenseCenterBrowserPath}",
    $"POST {LocalAgentContract.AuthorizePath}",
    $"POST {LocalAgentContract.ActivatePath}",
    $"POST {LocalAgentContract.OpenLicenseCenterPath}",
    $"POST {LocalAgentContract.CheckUpdatesPath}",
    $"POST {LocalAgentContract.OpenUpdateCenterPath}",
};

var manifestRoutes = root.GetProperty("routes")
    .EnumerateArray()
    .Select(route => $"{route.GetProperty("method").GetString()} {route.GetProperty("path").GetString()}")
    .ToHashSet(StringComparer.Ordinal);
Require(expectedRoutes.SetEquals(manifestRoutes), "Product-facing route set drifted.");

var updateCapability = root.GetProperty("update_capability");
Require(updateCapability.GetProperty("capability_id").GetString() == LocalAgentContract.UpdateCapabilityId, "BKE.Updater capability id drifted.");
Require(updateCapability.GetProperty("contract_version").GetInt32() == LocalAgentContract.UpdateContractVersion, "BKE.Updater contract version drifted.");

using var authorizeJson = JsonDocument.Parse(JsonSerializer.Serialize(
    new AuthorizeRequest("bke-render-dock", "1.0.1", "installation")));
Require(authorizeJson.RootElement.TryGetProperty("product_id", out _), "AuthorizeRequest must emit product_id.");
Require(authorizeJson.RootElement.TryGetProperty("installation_id", out _), "AuthorizeRequest must emit installation_id.");
Require(!authorizeJson.RootElement.TryGetProperty("productId", out _), "AuthorizeRequest leaked CLR naming.");

using var authorizationJson = JsonDocument.Parse(JsonSerializer.Serialize(
    new AuthorizationResponse(false, "activation_required", "http://127.0.0.1:43873/license-center")));
Require(authorizationJson.RootElement.TryGetProperty("license_center_url", out _), "AuthorizationResponse must preserve license_center_url.");

using var updateJson = JsonDocument.Parse(JsonSerializer.Serialize(
    new UpdateCheckResponse(
        LocalAgentContract.UpdateCapabilityId,
        LocalAgentContract.UpdateContractVersion,
        "UpdateAvailable",
        "1.0.2",
        null)));
Require(updateJson.RootElement.GetProperty("capability_id").GetString() == "bke.updates.check", "Update response capability identity drifted.");
Require(updateJson.RootElement.GetProperty("contract_version").GetInt32() == 1, "Update response contract version drifted.");
Require(updateJson.RootElement.GetProperty("available_version").GetString() == "1.0.2", "Update response available_version drifted.");
Require(updateJson.RootElement.TryGetProperty("error", out var updateError) && updateError.ValueKind == JsonValueKind.Null, "Update response must retain nullable error field.");

var runtimeMethods = typeof(ILicensingAgentRuntime).GetMethods().Select(method => method.Name).ToHashSet(StringComparer.Ordinal);
Require(runtimeMethods.SetEquals(new[]
{
    nameof(ILicensingAgentRuntime.AuthorizeAsync),
    nameof(ILicensingAgentRuntime.ActivateAsync),
    nameof(ILicensingAgentRuntime.OpenLicenseCenterAsync),
    nameof(ILicensingAgentRuntime.CheckUpdatesAsync),
    nameof(ILicensingAgentRuntime.OpenUpdateCenterAsync),
}), "Runtime port changed without updating certification.");

Console.WriteLine("BKE Licensing Agent .NET 10 contract certification: PASS");
