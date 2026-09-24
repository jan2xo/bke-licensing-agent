using System.Net;
using System.Reflection;
using System.Text;
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
    $"POST {LocalAgentContract.AccountSessionDeviceContextPath}",
    $"POST {LocalAgentContract.AccountSessionCompletePath}",
    $"POST {LocalAgentContract.AccountSessionStartPath}",
    $"POST {LocalAgentContract.AccountSessionStatusPath}",
    $"POST {LocalAgentContract.AccountSessionLogoutPath}",
    $"POST {LocalAgentContract.SoftwareCatalogPath}",
    $"POST {LocalAgentContract.SoftwareInstallPath}",
    $"POST {LocalAgentContract.SoftwareUpdatePath}",
    $"POST {LocalAgentContract.SoftwareRepairPath}",
    $"POST {LocalAgentContract.SoftwareOpenPath}",
    $"POST {LocalAgentContract.SoftwareRemovePath}",
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
Require(accountSession.GetProperty("native_credentials_owner").GetString() == "bke-launcher-to-digital-solutions", "native credential ownership drifted");
Require(accountSession.GetProperty("device_context_exposes_cloud_secrets").GetBoolean() == false, "device context secret boundary drifted");
Require(accountSession.GetProperty("native_complete_request_fields").EnumerateArray().Select(value => value.GetString()).ToArray()
    .SequenceEqual(["correlation_id", "handoff_code"]), "native complete request widened");

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

var softwareUpdate = capabilities.GetProperty("software_update");
Require(softwareUpdate.GetProperty("capability_id").GetString() == LocalAgentContract.SoftwareUpdateCapabilityId, "software-update capability id mismatch");
Require(softwareUpdate.GetProperty("contract_version").GetInt32() == LocalAgentContract.SoftwareUpdateContractVersion, "software-update contract version mismatch");
Require(softwareUpdate.GetProperty("account_session_required").GetBoolean(), "software-update account-session requirement drifted");
Require(softwareUpdate.GetProperty("cloud_authorization_owner").GetString() == "bke-digital-solutions", "software-update cloud authority drifted");
Require(softwareUpdate.GetProperty("release_authority").GetString() == "github-releases", "software-update release authority drifted");
Require(softwareUpdate.GetProperty("privileged_update_owner").GetString() == "bke-licensing-agent", "software-update privileged owner drifted");
Require(softwareUpdate.GetProperty("update_policy_schema").GetString() == "bke.update-policy.v2", "software-update policy schema drifted");
Require(softwareUpdate.GetProperty("local_request_fields").EnumerateArray().Select(value => value.GetString()).ToArray()
    .SequenceEqual(["correlation_id", "product_id"]), "software-update local request widened");
Require(softwareUpdate.GetProperty("supported_install_provenance").EnumerateArray().Select(value => value.GetString()).ToArray()
    .SequenceEqual(["BKE_MANAGED_PACKAGE"]), "software-update provenance boundary drifted");
Require(softwareUpdate.GetProperty("local_responses_expose_cloud_tokens").GetBoolean() == false, "software-update cloud token exposure drifted");
Require(softwareUpdate.GetProperty("local_responses_expose_download_urls").GetBoolean() == false, "software-update download URL exposure drifted");
Require(softwareUpdate.GetProperty("local_responses_expose_install_paths").GetBoolean() == false, "software-update install path exposure drifted");
Require(softwareUpdate.GetProperty("rollback_required").GetBoolean(), "software-update rollback requirement drifted");

var softwareRepair = capabilities.GetProperty("software_repair");
Require(softwareRepair.GetProperty("capability_id").GetString() == LocalAgentContract.SoftwareRepairCapabilityId, "software-repair capability id mismatch");
Require(softwareRepair.GetProperty("contract_version").GetInt32() == LocalAgentContract.SoftwareRepairContractVersion, "software-repair contract version mismatch");
Require(softwareRepair.GetProperty("account_session_required").GetBoolean(), "software-repair account-session requirement drifted");
Require(softwareRepair.GetProperty("cloud_authorization_owner").GetString() == "bke-digital-solutions", "software-repair cloud authority drifted");
Require(softwareRepair.GetProperty("release_authority").GetString() == "github-releases", "software-repair release authority drifted");
Require(softwareRepair.GetProperty("privileged_repair_owner").GetString() == "bke-licensing-agent", "software-repair privileged owner drifted");
Require(softwareRepair.GetProperty("repair_policy_schema").GetString() == "bke.repair-policy.v1", "software-repair policy schema drifted");
Require(softwareRepair.GetProperty("repair_semantics").GetString() == "restore-current-installed-version", "software-repair semantics drifted");
Require(softwareRepair.GetProperty("local_request_fields").EnumerateArray().Select(value => value.GetString()).ToArray()
    .SequenceEqual(["correlation_id", "product_id"]), "software-repair local request widened");
Require(softwareRepair.GetProperty("supported_install_provenance").EnumerateArray().Select(value => value.GetString()).ToArray()
    .SequenceEqual(["BKE_MANAGED_PACKAGE"]), "software-repair provenance boundary drifted");
Require(softwareRepair.GetProperty("local_responses_expose_cloud_tokens").GetBoolean() == false, "software-repair cloud token exposure drifted");
Require(softwareRepair.GetProperty("local_responses_expose_download_urls").GetBoolean() == false, "software-repair download URL exposure drifted");
Require(softwareRepair.GetProperty("local_responses_expose_install_paths").GetBoolean() == false, "software-repair install path exposure drifted");
Require(softwareRepair.GetProperty("update_policy_reuse_allowed").GetBoolean() == false, "software-repair silently reused Update authority");
Require(softwareRepair.GetProperty("rollback_required").GetBoolean(), "software-repair rollback requirement drifted");

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

var softwareRemove = capabilities.GetProperty("software_remove");
Require(softwareRemove.GetProperty("capability_id").GetString() == LocalAgentContract.SoftwareRemoveCapabilityId, "software-remove capability id mismatch");
Require(softwareRemove.GetProperty("contract_version").GetInt32() == LocalAgentContract.SoftwareRemoveContractVersion, "software-remove contract version mismatch");
Require(softwareRemove.GetProperty("account_session_required").GetBoolean(), "software-remove account-session requirement drifted");
Require(softwareRemove.GetProperty("target_authority").GetString() == "signed-install-target-policy+recorded-install-provenance", "software-remove target authority drifted");
Require(softwareRemove.GetProperty("install_provenance_required").GetBoolean(), "software-remove provenance requirement drifted");
Require(softwareRemove.GetProperty("supported_uninstall_strategies").EnumerateArray().Select(value => value.GetString()).ToHashSet(StringComparer.Ordinal)
    .SetEquals(["MANAGED_DIRECTORY", "INSTALLER_EXECUTABLE"]), "software-remove strategies drifted");
Require(softwareRemove.GetProperty("legacy_unknown_removal_allowed").GetBoolean() == false, "legacy-unknown removal became destructive");
Require(softwareRemove.GetProperty("privileged_remove_owner").GetString() == "bke-licensing-agent", "software-remove privileged ownership drifted");
Require(softwareRemove.GetProperty("local_request_fields").EnumerateArray().Select(value => value.GetString()).ToArray()
    .SequenceEqual(["correlation_id", "product_id"]), "software-remove local request widened");
Require(softwareRemove.GetProperty("user_data_outside_install_root_preserved").GetBoolean(), "software-remove user-data preservation drifted");
Require(softwareRemove.GetProperty("protected_platform_roots").EnumerateArray().Select(value => value.GetString()).ToHashSet(StringComparer.Ordinal)
    .SetEquals(["BKE", "Licensing Agent"]), "software-remove protected roots drifted");
Require(softwareRemove.GetProperty("local_responses_expose_install_paths").GetBoolean() == false, "software-remove install-path exposure drifted");

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
Require(JsonName<AccountSessionDeviceContextRequest>(nameof(AccountSessionDeviceContextRequest.CorrelationId)) == "correlation_id", "account-session device context correlation_id wire name mismatch");
Require(JsonName<AccountSessionCompleteRequest>(nameof(AccountSessionCompleteRequest.CorrelationId)) == "correlation_id", "account-session complete correlation_id wire name mismatch");
Require(JsonName<AccountSessionCompleteRequest>(nameof(AccountSessionCompleteRequest.HandoffCode)) == "handoff_code", "account-session complete handoff_code wire name mismatch");
Require(JsonName<AccountSessionStartRequest>(nameof(AccountSessionStartRequest.CorrelationId)) == "correlation_id", "account-session start correlation_id wire name mismatch");
Require(JsonName<AccountSessionStatusRequest>(nameof(AccountSessionStatusRequest.CorrelationId)) == "correlation_id", "account-session status correlation_id wire name mismatch");
Require(JsonName<AccountSessionLogoutRequest>(nameof(AccountSessionLogoutRequest.CorrelationId)) == "correlation_id", "account-session logout correlation_id wire name mismatch");
Require(JsonName<ClaimCodeRedeemRequest>(nameof(ClaimCodeRedeemRequest.CorrelationId)) == "correlation_id", "claim-code redemption correlation_id wire name mismatch");
Require(JsonName<ClaimCodeRedeemRequest>(nameof(ClaimCodeRedeemRequest.Code)) == "code", "claim-code redemption code wire name mismatch");
Require(JsonName<StoreCatalogRequest>(nameof(StoreCatalogRequest.CorrelationId)) == "correlation_id", "Store catalog correlation_id wire name mismatch");
Require(JsonName<StoreCatalogPlan>(nameof(StoreCatalogPlan.PurchasePlanId)) == "purchase_plan_id", "Store catalog purchase_plan_id wire name mismatch");
Require(JsonName<StoreCatalogPlan>(nameof(StoreCatalogPlan.AmountMinor)) == "amount_minor", "Store catalog amount_minor wire name mismatch");
Require(JsonName<StoreCheckoutReviewRequest>(nameof(StoreCheckoutReviewRequest.CorrelationId)) == "correlation_id", "Store checkout-review correlation_id wire name mismatch");
Require(JsonName<StoreCheckoutReviewRequest>(nameof(StoreCheckoutReviewRequest.PurchasePlanId)) == "purchase_plan_id", "Store checkout-review purchase_plan_id wire name mismatch");
Require(JsonName<StoreCheckoutReviewLegalDocument>(nameof(StoreCheckoutReviewLegalDocument.DocumentVersionId)) == "document_version_id", "Store checkout-review legal document_version_id wire name mismatch");
Require(JsonName<StoreCheckoutStartRequest>(nameof(StoreCheckoutStartRequest.CorrelationId)) == "correlation_id", "Store checkout-start correlation_id wire name mismatch");
Require(JsonName<StoreCheckoutStartRequest>(nameof(StoreCheckoutStartRequest.PurchasePlanId)) == "purchase_plan_id", "Store checkout-start purchase_plan_id wire name mismatch");
Require(JsonName<StoreCheckoutStartRequest>(nameof(StoreCheckoutStartRequest.PurchaseMode)) == "purchase_mode", "Store checkout-start purchase_mode wire name mismatch");
Require(JsonName<StoreCheckoutStartRequest>(nameof(StoreCheckoutStartRequest.LegalVersionIds)) == "legal_version_ids", "Store checkout-start legal_version_ids wire name mismatch");
Require(JsonName<StoreCheckoutStartResponse>(nameof(StoreCheckoutStartResponse.CheckoutUrl)) == "checkout_url", "Store checkout-start checkout_url wire name mismatch");
Require(JsonName<StoreCheckoutStatusRequest>(nameof(StoreCheckoutStatusRequest.CorrelationId)) == "correlation_id", "Store checkout-status correlation_id wire name mismatch");
Require(JsonName<StoreCheckoutStatusResponse>(nameof(StoreCheckoutStatusResponse.PaymentStatus)) == "payment_status", "Store checkout-status payment_status wire name mismatch");
Require(JsonName<StoreCheckoutStatusResponse>(nameof(StoreCheckoutStatusResponse.CheckoutUrl)) == "checkout_url", "Store checkout-status checkout_url wire name mismatch");
Require(JsonName<StoreCheckoutStatusResponse>(nameof(StoreCheckoutStatusResponse.PaidAt)) == "paid_at", "Store checkout-status paid_at wire name mismatch");
Require(JsonName<SoftwareCatalogRequest>(nameof(SoftwareCatalogRequest.CorrelationId)) == "correlation_id", "software-catalog correlation_id wire name mismatch");
Require(JsonName<SoftwareCatalogItem>(nameof(SoftwareCatalogItem.ExecutionType)) == "execution_type", "software-catalog execution_type wire name mismatch");
Require(JsonName<SoftwareCatalogItem>(nameof(SoftwareCatalogItem.InstalledVersion)) == "installed_version", "software-catalog installed_version wire name mismatch");
Require(JsonName<SoftwareInstallRequest>(nameof(SoftwareInstallRequest.CorrelationId)) == "correlation_id", "software-install correlation_id wire name mismatch");
Require(JsonName<SoftwareInstallRequest>(nameof(SoftwareInstallRequest.ProductId)) == "product_id", "software-install product_id wire name mismatch");
Require(JsonName<SoftwareUpdateRequest>(nameof(SoftwareUpdateRequest.CorrelationId)) == "correlation_id", "software-update correlation_id wire name mismatch");
Require(JsonName<SoftwareUpdateRequest>(nameof(SoftwareUpdateRequest.ProductId)) == "product_id", "software-update product_id wire name mismatch");
Require(JsonName<SoftwareRepairRequest>(nameof(SoftwareRepairRequest.CorrelationId)) == "correlation_id", "software-repair correlation_id wire name mismatch");
Require(JsonName<SoftwareRepairRequest>(nameof(SoftwareRepairRequest.ProductId)) == "product_id", "software-repair product_id wire name mismatch");
Require(JsonName<SoftwareOpenRequest>(nameof(SoftwareOpenRequest.CorrelationId)) == "correlation_id", "software-open correlation_id wire name mismatch");
Require(JsonName<SoftwareOpenRequest>(nameof(SoftwareOpenRequest.ProductId)) == "product_id", "software-open product_id wire name mismatch");
Require(JsonName<SoftwareRemoveRequest>(nameof(SoftwareRemoveRequest.CorrelationId)) == "correlation_id", "software-remove correlation_id wire name mismatch");
Require(JsonName<SoftwareRemoveRequest>(nameof(SoftwareRemoveRequest.ProductId)) == "product_id", "software-remove product_id wire name mismatch");

Require(MethodNames<IAuthorizationService>().SetEquals(["AuthorizeAsync"]), "authorization port drifted");
Require(MethodNames<IActivationService>().SetEquals(["ActivateAsync"]), "activation port drifted");
Require(MethodNames<ILicenseCenterService>().SetEquals(["OpenAsync"]), "License Center port drifted");
Require(MethodNames<INotificationService>().SetEquals(["RequestAsync", "FeedAsync", "MarkReadAsync", "DismissAsync", "UnreadCountAsync"]), "notification port drifted");
Require(MethodNames<IUpdateService>().SetEquals(["CheckAsync", "OpenCenterAsync"]), "update port drifted");
Require(MethodNames<IAccountSessionService>().SetEquals(["CompleteAsync", "StartAsync", "StatusAsync", "LogoutAsync"]), "account-session port drifted");
Require(MethodNames<IClaimCodeRedemptionService>().SetEquals(["RedeemAsync"]), "claim-code redemption port drifted");
Require(MethodNames<IStoreCatalogService>().SetEquals(["GetAsync"]), "Store catalog port drifted");
Require(MethodNames<IStoreCheckoutReviewService>().SetEquals(["ReviewAsync"]), "Store checkout-review port drifted");
Require(MethodNames<IStoreCheckoutStartService>().SetEquals(["StartAsync"]), "Store checkout-start port drifted");
Require(MethodNames<IStoreCheckoutStatusService>().SetEquals(["CheckAsync"]), "Store checkout-status port drifted");
Require(MethodNames<ISoftwareCatalogService>().SetEquals(["GetAsync"]), "software-catalog port drifted");
Require(MethodNames<ISoftwareUpdateService>().SetEquals(["UpdateAsync"]), "software-update port drifted");
Require(MethodNames<ISoftwareRepairService>().SetEquals(["RepairAsync"]), "software-repair port drifted");
Require(MethodNames<ISoftwareInstallService>().SetEquals(["InstallAsync"]), "software-install port drifted");
Require(MethodNames<ISoftwareOpenService>().SetEquals(["OpenAsync"]), "software-open port drifted");
Require(MethodNames<ISoftwareRemoveService>().SetEquals(["RemoveAsync"]), "software-remove port drifted");

CertifyRuntimeEnvironmentBoundary();
CertifyFreshStorageBootstrap(storage);
CertifyNotificationSchemaUpgrade();
await CertifyAuthenticatedAccountNotificationSync();
await CertifyAccountSessionStateMachine();
await CertifyClaimCodeRedemptionBoundary();
await CertifyStoreCatalogBoundary();
await CertifyStoreCheckoutReviewBoundary();
await CertifyStoreCheckoutStartBoundary();
await CertifyStoreCheckoutStatusBoundary();
await CertifySoftwareCatalogBoundary();
await CertifySoftwareInstallBoundary();
await CertifySoftwareUpdateBoundary();
await CertifySoftwareRepairBoundary();
await CertifySoftwareOpenBoundary();
await CertifySoftwareRemoveBoundary();

var notificationColumns = storage.GetProperty("tables").GetProperty("notifications")
    .EnumerateArray().Select(value => value.GetString()).ToHashSet(StringComparer.Ordinal);
Require(!notificationColumns.Contains("delivery_mode"), "EVERY_LAUNCH must not force a durable delivery_mode column");
Require(notificationColumns.Contains("title") && notificationColumns.Contains("body") && notificationColumns.Contains("source") && notificationColumns.Contains("category"),
    "notification presentation ownership columns are missing");

Console.WriteLine("BKE Licensing Agent .NET 10 Gen2 contract certification: PASS");
Console.WriteLine($"Routes certified: {contractRoutes.Count}");
Console.WriteLine($"SQLite schema certified: {LocalAgentContract.StorageSchemaVersion}");
Console.WriteLine("Account-session device authorization state machine certified");
Console.WriteLine("Claim Code redemption session, secret, and single-attempt boundary certified");
Console.WriteLine("Store catalog pricing-presentation, strict-parser, and secret boundary certified");
Console.WriteLine("Store checkout-review pricing, Legal, retry, strict-parser, and secret boundary certified");
Console.WriteLine("Store checkout-start intent, no-retry mutation, strict-parser, and secret boundary certified");
Console.WriteLine("Store checkout-status read-only recovery, strict-parser, and secret boundary certified");
Console.WriteLine("Software catalog authority and secret boundary certified");
Console.WriteLine("Software install authority, release-source, and secret boundary certified");
Console.WriteLine("Software Update newer-version authority and rollback boundary certified");
Console.WriteLine("Software Repair same-version authority and rollback boundary certified");
Console.WriteLine("Software open entitlement, execution-type, and path-hiding boundary certified");
Console.WriteLine("Software remove authentication, target, and path-hiding boundary certified");
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

        var expectedProductColumns = storage.GetProperty("tables")
            .GetProperty("discovered_products")
            .EnumerateArray()
            .Select(value => value.GetString()!)
            .ToArray();
        using var productColumns = connection.CreateCommand();
        productColumns.CommandText = "PRAGMA table_info(discovered_products)";
        using var productReader = productColumns.ExecuteReader();
        var actualProductColumns = new List<string>();
        while (productReader.Read())
        {
            actualProductColumns.Add(productReader.GetString(1));
        }
        Require(
            actualProductColumns.SequenceEqual(expectedProductColumns),
            "fresh discovered-product storage columns drifted");
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
                CREATE TABLE discovered_products (
                    product_id TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    version TEXT NOT NULL,
                    manifest_path TEXT NOT NULL,
                    product_root TEXT NOT NULL,
                    entry_point_path TEXT NOT NULL,
                    discovered_at TEXT NOT NULL,
                    PRIMARY KEY (manifest_path)
                );
                INSERT INTO discovered_products (
                    product_id, display_name, version, manifest_path,
                    product_root, entry_point_path, discovered_at
                ) VALUES (
                    'legacy-product',
                    'Legacy Product',
                    '1.0.0',
                    'C:\\legacy\\bke.manifest.json',
                    'C:\\legacy',
                    'C:\\legacy\\legacy.exe',
                    '2026-09-19T00:00:00.0000000+00:00'
                );
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

        using (var legacyProduct = upgraded.CreateCommand())
        {
            legacyProduct.CommandText = """
                SELECT install_provenance, uninstall_strategy,
                       uninstall_executable, uninstall_arguments_json
                FROM discovered_products
                WHERE product_id='legacy-product'
                """;
            using var reader = legacyProduct.ExecuteReader();
            Require(reader.Read(), "legacy discovered product was not preserved");
            Require(reader.GetString(0) == "LEGACY_UNKNOWN", "legacy product gained unsafe install provenance");
            Require(reader.GetString(1) == "NONE", "legacy product gained unsafe uninstall strategy");
            Require(reader.IsDBNull(2) && reader.IsDBNull(3),
                "legacy product gained fabricated uninstall command metadata");
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

static async Task CertifyAuthenticatedAccountNotificationSync()
{
    var root = Path.Combine(
        Path.GetTempPath(),
        "bke-agent-account-notification-sync-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(root);
    var originalDataDir = Environment.GetEnvironmentVariable("BKE_AGENT_DATA_DIR");

    try
    {
        Environment.SetEnvironmentVariable(
            "BKE_AGENT_DATA_DIR",
            root,
            EnvironmentVariableTarget.Process);
        AgentDatabase.EnsureInitialized(root);

        var productRoot = Path.Combine(root, "notification-sync-product");
        Directory.CreateDirectory(productRoot);
        var manifestPath = Path.Combine(productRoot, "bke.manifest.json");
        var entryPointPath = Path.Combine(productRoot, "RENDER DOCK.exe");
        File.WriteAllText(entryPointPath, "notification sync fixture", new UTF8Encoding(false));
        File.WriteAllText(
            manifestPath,
            """
            {"schemaVersion":1,"productId":"bke-render-dock","displayName":"Render Dock","version":"1.0.2","entryPoint":"RENDER DOCK.exe","updateChannel":"stable","minimumAgentVersion":"2.0.0","platform":"windows","architecture":"arm64"}
            """,
            new UTF8Encoding(false));

        var databasePath = AgentDatabase.DatabasePath(root);
        using (var connection = new SqliteConnection(
            new SqliteConnectionStringBuilder
            {
                DataSource = databasePath,
                Mode = SqliteOpenMode.ReadWrite,
            }.ToString()))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = """
                INSERT INTO discovered_products (
                    product_id, display_name, version, manifest_path,
                    product_root, entry_point_path, discovered_at
                ) VALUES (
                    'bke-render-dock',
                    'Render Dock',
                    '1.0.2',
                    $manifest_path,
                    $product_root,
                    $entry_point_path,
                    '2026-09-20T12:00:00.0000000+00:00'
                )
                """;
            command.Parameters.AddWithValue("$manifest_path", manifestPath);
            command.Parameters.AddWithValue("$product_root", productRoot);
            command.Parameters.AddWithValue("$entry_point_path", entryPointPath);
            command.ExecuteNonQuery();
        }

        var account = new AccountSessionAccount(
            "user-1",
            "user@example.com",
            "account-1",
            "INDIVIDUAL",
            "Account One");
        var store = new FakeAccountSessionStore();
        await store.WriteAsync(
            new ActiveAccountSessionState(
                "account-access-secret",
                "refresh-secret",
                "session-1",
                new DateTimeOffset(2026, 9, 21, 12, 0, 0, TimeSpan.Zero),
                new DateTimeOffset(2026, 10, 20, 12, 0, 0, TimeSpan.Zero),
                account),
            CancellationToken.None);

        var handler = new FakeNotificationAuthorityHandler();
        using var http = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(5),
        };
        var provider = new NotificationProvider(
            new AuthorizationProvider(),
            new FakeAuthenticatedAccountSessionService(account),
            store,
            http,
            "https://utm-digital.example");

        var request = new NotificationFeedRequest(
            "bke-render-dock",
            "1.0.2",
            "notification-sync-installation",
            50,
            false);
        var first = await provider.FeedAsync(request, CancellationToken.None);

        Require(first.Status == "Succeeded", "authenticated account notification feed failed");
        var received = first.Items.SingleOrDefault(item =>
            item.Id == "bke-11111111-2222-3333-4444-555555555555")
            ?? throw new InvalidOperationException("account notification was not synchronized");
        Require(received.Source == "payments", "account notification source drifted");
        Require(received.Title == "Payment received", "Digital Solutions notification title drifted");
        Require(received.Body == "Payment for order TEST-1 was confirmed.", "Digital Solutions notification body drifted");
        Require(received.Category == "General", "transactional notification category mapping drifted");
        Require(received.Severity == "Information", "normal account notification severity drifted");
        Require(received.State == "Unread", "new account notification was not unread");
        Require(handler.SawBearer, "account notification sync omitted Agent-owned bearer token");
        Require(handler.SawProtocol, "account notification sync omitted account-session protocol version");

        var marked = await provider.MarkReadAsync(
            new NotificationMutationRequest(
                "bke-render-dock",
                "1.0.2",
                "notification-sync-installation",
                received.Id),
            CancellationToken.None);
        Require(marked.Status == "Succeeded", "account notification mark-read failed");

        var second = await provider.FeedAsync(request, CancellationToken.None);
        var resynchronized = second.Items.Single(item => item.Id == received.Id);
        Require(
            resynchronized.State == "Read",
            "account notification re-sync reset local read state");

        using var verification = new SqliteConnection(
            new SqliteConnectionStringBuilder
            {
                DataSource = databasePath,
                Mode = SqliteOpenMode.ReadOnly,
            }.ToString());
        verification.Open();
        using var verify = verification.CreateCommand();
        verify.CommandText = """
            SELECT code, source, title, body, category, state
            FROM notifications
            WHERE id='bke-11111111-2222-3333-4444-555555555555'
            """;
        using var reader = verify.ExecuteReader();
        Require(reader.Read(), "synchronized account notification was not persisted");
        Require(reader.GetString(0) == "PAYMENT_RECEIVED", "persisted account notification event drifted");
        Require(reader.GetString(1) == "payments", "persisted account notification source drifted");
        Require(reader.GetString(2) == "Payment received", "persisted account notification title drifted");
        Require(reader.GetString(3) == "Payment for order TEST-1 was confirmed.", "persisted account notification body drifted");
        Require(reader.GetString(4) == "General", "persisted account notification category drifted");
        Require(reader.GetString(5) == "read", "persisted local notification state drifted");
    }
    finally
    {
        Environment.SetEnvironmentVariable(
            "BKE_AGENT_DATA_DIR",
            originalDataDir,
            EnvironmentVariableTarget.Process);
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

    var nativeRemote = new FakeAccountSessionRemote();
    nativeRemote.NativeExchanges.Enqueue(new RemoteAccountSessionPoll(
        "approved",
        AccessToken: "native-access-secret",
        RefreshToken: "native-refresh-secret",
        SessionId: "native-session-1",
        ExpiresIn: TimeSpan.FromMinutes(15),
        RefreshExpiresIn: TimeSpan.FromDays(30),
        Account: new AccountSessionAccount(
            "user-native",
            "native@example.com",
            "account-native",
            "ORGANIZATION",
            "Native Organization")));
    var nativeStore = new FakeAccountSessionStore();
    var nativeService = new AccountSessionService(nativeRemote, nativeStore, clock);
    var native = await nativeService.CompleteAsync(
        new AccountSessionCompleteRequest(
            "cert-native-complete",
            "native-handoff-secret"),
        CancellationToken.None);
    Require(native.Status == "AUTHENTICATED", "native handoff did not authenticate");
    Require(native.Account?.AccountId == "account-native", "native handoff account drifted");
    Require(nativeRemote.NativeExchangeCount == 1, "native handoff was not exchanged exactly once");
    Require(nativeRemote.LastNativeHandoff == "native-handoff-secret", "native handoff value drifted before remote exchange");
    var nativeWire = JsonSerializer.Serialize(native);
    Require(!nativeWire.Contains("native-handoff-secret", StringComparison.Ordinal), "native handoff leaked to local response");
    Require(!nativeWire.Contains("native-access-secret", StringComparison.Ordinal), "native access token leaked to local response");
    Require(!nativeWire.Contains("native-refresh-secret", StringComparison.Ordinal), "native refresh token leaked to local response");
    Require(nativeStore.State is ActiveAccountSessionState nativeActive &&
            nativeActive.AccessToken == "native-access-secret" &&
            nativeActive.RefreshToken == "native-refresh-secret",
        "native session material did not enter secret-store custody");
    Require(nativeRemote.AcknowledgeCount == 1, "native handoff was not acknowledged after secure-store write");
}


static async Task CertifyClaimCodeRedemptionBoundary()
{
    const string claimCode =
        "BKE-CLM-AAAAA-BBBBB-CCCCC-DDDDD-EEEEE-FFFFF";
    var account = new AccountSessionAccount(
        "user-claim",
        "claimer@example.com",
        "account-claim",
        "INDIVIDUAL",
        "Claim Recipient");
    var store = new FakeAccountSessionStore();
    await store.WriteAsync(
        new ActiveAccountSessionState(
            "claim-access-secret",
            "claim-refresh-secret",
            "claim-session",
            DateTimeOffset.UtcNow.AddMinutes(15),
            DateTimeOffset.UtcNow.AddDays(30),
            account),
        CancellationToken.None);

    var remote = new FakeClaimCodeRedemptionRemote(
        new RemoteClaimCodeRedemptionResult(
            "claimed",
            "account-claim",
            "entitlement-claim"));
    var service = new ClaimCodeRedemptionService(
        new FakeAuthenticatedAccountSessionService(account),
        store,
        remote);

    var response = await service.RedeemAsync(
        new ClaimCodeRedeemRequest(
            "cert-claim",
            claimCode),
        CancellationToken.None);

    Require(response.Status == "CLAIMED", "Claim Code redemption did not become CLAIMED");
    Require(response.AccountId == "account-claim", "Claim Code redemption account drifted");
    Require(response.EntitlementId == "entitlement-claim", "Claim Code redemption entitlement drifted");
    Require(remote.AccessToken == "claim-access-secret", "Claim Code redemption remote did not receive Agent-owned access token");
    Require(remote.Code == claimCode, "Claim Code redemption remote did not receive the transient Claim Code");

    var wire = JsonSerializer.Serialize(response);
    Require(!wire.Contains(claimCode, StringComparison.Ordinal), "Claim Code leaked into local redemption response");
    Require(!wire.Contains("claim-access-secret", StringComparison.Ordinal), "Claim Code redemption leaked access token");
    Require(!wire.Contains("claim-refresh-secret", StringComparison.Ordinal), "Claim Code redemption leaked refresh token");

    var deniedRemote = new FakeClaimCodeRedemptionRemote(
        new RemoteClaimCodeRedemptionResult("claimed", "account-claim", "unexpected"));
    var denied = new ClaimCodeRedemptionService(
        new FakeUnauthenticatedAccountSessionService(),
        store,
        deniedRemote);
    var deniedResponse = await denied.RedeemAsync(
        new ClaimCodeRedeemRequest("cert-claim-auth", claimCode),
        CancellationToken.None);
    Require(deniedResponse.Status == "AUTH_REQUIRED", "Claim Code redemption did not require authentication");
    Require(deniedRemote.Code is null, "Claim Code redemption called cloud authority without authentication");

    using var transportHandler = new FakeClaimCodeRedemptionAuthorityHandler(
        HttpStatusCode.Created,
        """
        {
          "status":"claimed",
          "entitlement_id":"transport-entitlement",
          "account_id":"transport-account"
        }
        """);
    using var transportHttp = new HttpClient(transportHandler);
    using var transport = new ClaimCodeRedemptionRemote(
        transportHttp,
        "https://jl-bke.com");

    var transportResult = await transport.RedeemAsync(
        "transport-access-secret",
        claimCode,
        CancellationToken.None);
    Require(transportResult.Status == "claimed", "Claim Code transport status drifted");
    Require(transportResult.AccountId == "transport-account", "Claim Code transport account drifted");
    Require(transportResult.EntitlementId == "transport-entitlement", "Claim Code transport entitlement drifted");
    Require(transportHandler.RequestCount == 1, "Claim Code transport retried a successful mutation");
    Require(transportHandler.SawBearer, "Claim Code transport omitted Agent-owned bearer token");
    Require(transportHandler.SawProtocol, "Claim Code transport omitted account-session protocol");
    Require(transportHandler.SawExpectedPath, "Claim Code transport endpoint drifted");
    Require(transportHandler.SawClaimCode, "Claim Code transport body drifted");

    using var unavailableHandler = new FakeClaimCodeRedemptionAuthorityHandler(
        HttpStatusCode.ServiceUnavailable,
        """{"error":"TEMPORARILY_UNAVAILABLE"}""",
        includeProtocol: false);
    using var unavailableHttp = new HttpClient(unavailableHandler);
    using var unavailable = new ClaimCodeRedemptionRemote(
        unavailableHttp,
        "https://jl-bke.com");
    try
    {
        _ = await unavailable.RedeemAsync(
            "transport-access-secret",
            claimCode,
            CancellationToken.None);
        throw new InvalidOperationException(
            "Claim Code redemption accepted a service-unavailable response");
    }
    catch (HttpRequestException)
    {
        Require(
            unavailableHandler.RequestCount == 1,
            "Claim Code redemption mutation was automatically retried after an ambiguous failure");
    }
}


static async Task CertifyStoreCatalogBoundary()
{
    var account = new AccountSessionAccount(
        "user-store",
        "buyer@example.com",
        "account-store",
        "INDIVIDUAL",
        "Store Buyer");
    var store = new FakeAccountSessionStore();
    await store.WriteAsync(
        new ActiveAccountSessionState(
            "store-access-secret",
            "store-refresh-secret",
            "store-session",
            DateTimeOffset.UtcNow.AddMinutes(15),
            DateTimeOffset.UtcNow.AddDays(30),
            account),
        CancellationToken.None);

    var product = new StoreCatalogProduct(
        "bke-render-dock",
        "render-dock",
        "Render Dock",
        "Rendering software",
        "Standalone rendering software",
        "SOFTWARE",
        "STANDALONE",
        [
            new StoreCatalogEdition(
                "edition-pro",
                "pro",
                "Pro",
                "Professional edition",
                ["Feature A"],
                1,
                2,
                "LIFETIME",
                [
                    new StoreCatalogPlan(
                        "plan-perpetual",
                        "PERPETUAL",
                        "PHP",
                        30000000,
                        "ONE_TIME",
                        null,
                        null,
                        "NONE",
                        0,
                        null),
                ]),
        ]);

    var remote = new FakeStoreCatalogRemote(
        new RemoteStoreCatalogSnapshot(
            true,
            [product]));
    var service = new StoreCatalogService(
        new FakeAuthenticatedAccountSessionService(account),
        store,
        remote);

    var response = await service.GetAsync(
        new StoreCatalogRequest("cert-store"),
        CancellationToken.None);

    Require(response.Status == "READY", "Store catalog did not become READY");
    Require(response.GiftCheckoutEnabled, "Store catalog gift-checkout flag drifted");
    Require(response.Products.Count == 1, "Store catalog product count drifted");
    Require(remote.AccessToken == "store-access-secret", "Store catalog remote did not receive Agent-owned access token");

    var wire = JsonSerializer.Serialize(response);
    Require(!wire.Contains("store-access-secret", StringComparison.Ordinal), "Store catalog leaked access token");
    Require(!wire.Contains("store-refresh-secret", StringComparison.Ordinal), "Store catalog leaked refresh token");
    Require(!wire.Contains("account-store", StringComparison.Ordinal), "Store catalog leaked cloud account identifier");

    var deniedRemote = new FakeStoreCatalogRemote(
        new RemoteStoreCatalogSnapshot(true, [product]));
    var denied = new StoreCatalogService(
        new FakeUnauthenticatedAccountSessionService(),
        store,
        deniedRemote);
    var deniedResponse = await denied.GetAsync(
        new StoreCatalogRequest("cert-store-auth"),
        CancellationToken.None);
    Require(deniedResponse.Status == "AUTH_REQUIRED", "Store catalog did not require authentication");
    Require(deniedRemote.AccessToken is null, "Store catalog called cloud authority without authentication");

    using var handler = new FakeStoreCatalogAuthorityHandler(
        """
        {
          "status":"ok",
          "account_id":"cloud-account",
          "gift_checkout_enabled":true,
          "products":[
            {
              "product_id":"bke-render-dock",
              "slug":"render-dock",
              "display_name":"Render Dock",
              "summary":"Rendering software",
              "description":"Standalone rendering software",
              "product_type":"SOFTWARE",
              "execution_type":"STANDALONE",
              "editions":[
                {
                  "edition_id":"edition-pro",
                  "slug":"pro",
                  "name":"Pro",
                  "description":"Professional edition",
                  "features":["Feature A"],
                  "max_users":1,
                  "max_devices_per_user":2,
                  "update_policy":"LIFETIME",
                  "plans":[
                    {
                      "purchase_plan_id":"plan-perpetual",
                      "type":"PERPETUAL",
                      "currency":"PHP",
                      "amount_minor":30000000,
                      "billing_type":"ONE_TIME",
                      "interval_unit":null,
                      "interval_count":null,
                      "renewal_behavior":"NONE",
                      "savings_minor":0,
                      "effective_monthly_minor":null
                    }
                  ]
                }
              ]
            }
          ]
        }
        """);
    using var http = new HttpClient(handler);
    using var transport = new StoreCatalogRemote(
        http,
        "https://jl-bke.com");
    var snapshot = await transport.GetAsync(
        "transport-store-secret",
        CancellationToken.None);

    Require(snapshot.GiftCheckoutEnabled, "Store transport gift-checkout flag drifted");
    Require(snapshot.Products.Single().Editions.Single().Plans.Single().AmountMinor == 30000000, "Store transport amount drifted");
    Require(handler.SawBearer, "Store transport omitted Agent-owned bearer token");
    Require(handler.SawProtocol, "Store transport omitted account-session protocol");
    Require(handler.SawExpectedPath, "Store transport endpoint drifted");

    using var widenedHandler = new FakeStoreCatalogAuthorityHandler(
        """
        {
          "status":"ok",
          "account_id":"cloud-account",
          "gift_checkout_enabled":false,
          "checkout_url":"https://example.invalid/pay",
          "products":[]
        }
        """);
    using var widenedHttp = new HttpClient(widenedHandler);
    using var widenedTransport = new StoreCatalogRemote(
        widenedHttp,
        "https://jl-bke.com");
    try
    {
        _ = await widenedTransport.GetAsync(
            "transport-store-secret",
            CancellationToken.None);
        throw new InvalidOperationException(
            "Store transport accepted a widened payment-authority response");
    }
    catch (InvalidDataException)
    {
        // Strict root keys intentionally reject checkout/payment authority.
    }
}

static async Task CertifyStoreCheckoutReviewBoundary()
{
    var account = new AccountSessionAccount(
        "user-review",
        "buyer@example.com",
        "account-review",
        "INDIVIDUAL",
        "Review Buyer");
    var store = new FakeAccountSessionStore();
    await store.WriteAsync(
        new ActiveAccountSessionState(
            "review-access-secret",
            "review-refresh-secret",
            "review-session",
            DateTimeOffset.UtcNow.AddMinutes(15),
            DateTimeOffset.UtcNow.AddDays(30),
            account),
        CancellationToken.None);

    var product = new StoreCheckoutReviewProduct(
        "bke-render-dock",
        "render-dock",
        "Render Dock",
        "Rendering software");
    var edition = new StoreCheckoutReviewEdition(
        "edition-pro",
        "pro",
        "Pro",
        1,
        2,
        "LIFETIME");
    var plan = new StoreCatalogPlan(
        "plan-perpetual",
        "PERPETUAL",
        "PHP",
        30000000,
        "ONE_TIME",
        null,
        null,
        "NONE",
        0,
        null);
    var legal = new StoreCheckoutReviewLegalDocument(
        "TERMS",
        "Terms of Service",
        "terms",
        "terms-v3",
        "3",
        null,
        false);

    var remote = new FakeStoreCheckoutReviewRemote(
        new RemoteStoreCheckoutReviewResult(
            "ready",
            ["SELF", "GIFT"],
            product,
            edition,
            plan,
            [legal],
            []));
    var service = new StoreCheckoutReviewService(
        new FakeAuthenticatedAccountSessionService(account),
        store,
        remote);

    var response = await service.ReviewAsync(
        new StoreCheckoutReviewRequest(
            "cert-review",
            "plan-perpetual"),
        CancellationToken.None);

    Require(response.Status == "READY", "Store checkout-review did not become READY");
    Require(response.PurchaseModes.ToHashSet(StringComparer.Ordinal).SetEquals(["SELF", "GIFT"]), "Store checkout-review purchase modes drifted");
    Require(response.Plan?.AmountMinor == 30000000, "Store checkout-review amount drifted");
    Require(response.LegalDocuments.Count == 1, "Store checkout-review Legal requirements drifted");
    Require(remote.AccessToken == "review-access-secret", "Store checkout-review remote did not receive Agent-owned access token");
    Require(remote.PurchasePlanId == "plan-perpetual", "Store checkout-review remote did not receive selected plan");

    var wire = JsonSerializer.Serialize(response);
    Require(!wire.Contains("review-access-secret", StringComparison.Ordinal), "Store checkout-review leaked access token");
    Require(!wire.Contains("review-refresh-secret", StringComparison.Ordinal), "Store checkout-review leaked refresh token");
    Require(!wire.Contains("account-review", StringComparison.Ordinal), "Store checkout-review leaked cloud account identifier");
    Require(!wire.Contains("checkout_url", StringComparison.OrdinalIgnoreCase), "Store checkout-review leaked checkout URL authority");
    Require(!wire.Contains("paymongo", StringComparison.OrdinalIgnoreCase), "Store checkout-review leaked provider authority");

    var deniedRemote = new FakeStoreCheckoutReviewRemote(
        new RemoteStoreCheckoutReviewResult(
            "ready",
            ["SELF"],
            product,
            edition,
            plan,
            [legal],
            []));
    var denied = new StoreCheckoutReviewService(
        new FakeUnauthenticatedAccountSessionService(),
        store,
        deniedRemote);
    var deniedResponse = await denied.ReviewAsync(
        new StoreCheckoutReviewRequest(
            "cert-review-auth",
            "plan-perpetual"),
        CancellationToken.None);
    Require(deniedResponse.Status == "AUTH_REQUIRED", "Store checkout-review did not require authentication");
    Require(deniedRemote.AccessToken is null, "Store checkout-review called cloud authority without authentication");

    const string readyJson = """
        {
          "status":"ready",
          "purchase_modes":["SELF","GIFT"],
          "product":{
            "product_id":"bke-render-dock",
            "slug":"render-dock",
            "display_name":"Render Dock",
            "summary":"Rendering software"
          },
          "edition":{
            "edition_id":"edition-pro",
            "slug":"pro",
            "name":"Pro",
            "max_users":1,
            "max_devices_per_user":2,
            "update_policy":"LIFETIME"
          },
          "plan":{
            "purchase_plan_id":"plan-perpetual",
            "type":"PERPETUAL",
            "currency":"PHP",
            "amount_minor":30000000,
            "billing_type":"ONE_TIME",
            "interval_unit":null,
            "interval_count":null,
            "renewal_behavior":"NONE",
            "savings_minor":0,
            "effective_monthly_minor":null
          },
          "legal_documents":[
            {
              "document_type":"TERMS",
              "title":"Terms of Service",
              "slug":"terms",
              "document_version_id":"terms-v3",
              "version":"3",
              "sla_version":null,
              "requires_reacceptance":false
            }
          ]
        }
        """;

    using var handler = new FakeStoreCheckoutReviewAuthorityHandler(
        HttpStatusCode.OK,
        readyJson);
    using var http = new HttpClient(handler);
    using var transport = new StoreCheckoutReviewRemote(
        http,
        "https://jl-bke.com");
    var snapshot = await transport.ReviewAsync(
        "transport-review-secret",
        "plan-perpetual",
        CancellationToken.None);

    Require(snapshot.Status == "ready", "Store checkout-review transport status drifted");
    Require(snapshot.Plan?.AmountMinor == 30000000, "Store checkout-review transport amount drifted");
    Require(handler.SawBearer, "Store checkout-review transport omitted Agent-owned bearer token");
    Require(handler.SawProtocol, "Store checkout-review transport omitted account-session protocol");
    Require(handler.SawExpectedPath, "Store checkout-review transport endpoint drifted");
    Require(handler.SawPlanQuery, "Store checkout-review transport omitted selected purchase plan");

    using var retryHandler = new FakeStoreCheckoutReviewAuthorityHandler(
        HttpStatusCode.OK,
        readyJson,
        transientFailures: 1);
    using var retryHttp = new HttpClient(retryHandler);
    using var retryTransport = new StoreCheckoutReviewRemote(
        retryHttp,
        "https://jl-bke.com");
    var retrySnapshot = await retryTransport.ReviewAsync(
        "transport-review-secret",
        "plan-perpetual",
        CancellationToken.None);
    Require(retrySnapshot.Status == "ready", "Store checkout-review did not recover from a transient read failure");
    Require(retryHandler.RequestCount == 2, "Store checkout-review read retry policy drifted");

    using var widenedHandler = new FakeStoreCheckoutReviewAuthorityHandler(
        HttpStatusCode.OK,
        """
        {
          "status":"ready",
          "purchase_modes":["SELF"],
          "product":{
            "product_id":"bke-render-dock",
            "slug":"render-dock",
            "display_name":"Render Dock",
            "summary":"Rendering software"
          },
          "edition":{
            "edition_id":"edition-pro",
            "slug":"pro",
            "name":"Pro",
            "max_users":1,
            "max_devices_per_user":2,
            "update_policy":"LIFETIME"
          },
          "plan":{
            "purchase_plan_id":"plan-perpetual",
            "type":"PERPETUAL",
            "currency":"PHP",
            "amount_minor":30000000,
            "billing_type":"ONE_TIME",
            "interval_unit":null,
            "interval_count":null,
            "renewal_behavior":"NONE",
            "savings_minor":0,
            "effective_monthly_minor":null
          },
          "legal_documents":[],
          "checkout_url":"https://example.invalid/pay"
        }
        """);
    using var widenedHttp = new HttpClient(widenedHandler);
    using var widenedTransport = new StoreCheckoutReviewRemote(
        widenedHttp,
        "https://jl-bke.com");
    try
    {
        _ = await widenedTransport.ReviewAsync(
            "transport-review-secret",
            "plan-perpetual",
            CancellationToken.None);
        throw new InvalidOperationException(
            "Store checkout-review accepted widened payment authority");
    }
    catch (InvalidDataException)
    {
        // Strict root keys intentionally reject checkout/payment authority.
    }
}

static async Task CertifyStoreCheckoutStartBoundary()
{
    var account = new AccountSessionAccount(
        "user-checkout",
        "buyer@example.com",
        "account-checkout",
        "INDIVIDUAL",
        "Checkout Buyer");
    var store = new FakeAccountSessionStore();
    await store.WriteAsync(
        new ActiveAccountSessionState(
            "checkout-access-secret",
            "checkout-refresh-secret",
            "checkout-session",
            DateTimeOffset.UtcNow.AddMinutes(15),
            DateTimeOffset.UtcNow.AddDays(30),
            account),
        CancellationToken.None);

    var request = new StoreCheckoutStartRequest(
        "cert-checkout-correlation",
        "plan-perpetual",
        "GIFT",
        ["terms-v3", "privacy-v2"]);

    var remote = new FakeStoreCheckoutStartRemote(
        new RemoteStoreCheckoutStartResult(
            "ready",
            request.CorrelationId,
            "order-cert",
            "https://checkout.example.test/pay/order-cert",
            false,
            null));
    var service = new StoreCheckoutStartService(
        new FakeAuthenticatedAccountSessionService(account),
        store,
        remote);

    var response = await service.StartAsync(
        request,
        CancellationToken.None);

    Require(response.Status == "READY", "Store checkout-start did not become READY");
    Require(response.CorrelationId == request.CorrelationId, "Store checkout-start correlation drifted");
    Require(response.OrderId == "order-cert", "Store checkout-start order id drifted");
    Require(response.CheckoutUrl == "https://checkout.example.test/pay/order-cert", "Store checkout-start checkout URL drifted");
    Require(response.Complimentary == false, "Store checkout-start complimentary flag drifted");
    Require(remote.AccessToken == "checkout-access-secret", "Store checkout-start remote did not receive Agent-owned access token");
    Require(remote.Request?.PurchaseMode == "GIFT", "Store checkout-start purchase mode drifted");
    Require(remote.Request?.LegalVersionIds.SequenceEqual(["terms-v3", "privacy-v2"]) == true, "Store checkout-start Legal versions drifted");

    var wire = JsonSerializer.Serialize(response);
    Require(!wire.Contains("checkout-access-secret", StringComparison.Ordinal), "Store checkout-start leaked access token");
    Require(!wire.Contains("checkout-refresh-secret", StringComparison.Ordinal), "Store checkout-start leaked refresh token");
    Require(!wire.Contains("account-checkout", StringComparison.Ordinal), "Store checkout-start leaked cloud account identifier");
    Require(!wire.Contains("paymongo", StringComparison.OrdinalIgnoreCase), "Store checkout-start leaked provider authority");

    var deniedRemote = new FakeStoreCheckoutStartRemote(
        new RemoteStoreCheckoutStartResult(
            "ready",
            request.CorrelationId,
            "order-denied",
            "https://checkout.example.test/pay/order-denied",
            false,
            null));
    var denied = new StoreCheckoutStartService(
        new FakeUnauthenticatedAccountSessionService(),
        store,
        deniedRemote);
    var deniedResponse = await denied.StartAsync(
        request with { CorrelationId = "cert-checkout-auth" },
        CancellationToken.None);
    Require(deniedResponse.Status == "AUTH_REQUIRED", "Store checkout-start did not require authentication");
    Require(deniedRemote.AccessToken is null, "Store checkout-start called cloud mutation without authentication");

    const string readyJson = """
        {
          "status":"ready",
          "correlation_id":"cert-checkout-correlation",
          "order_id":"order-cert",
          "checkout_url":"https://checkout.example.test/pay/order-cert",
          "complimentary":false
        }
        """;

    using var handler = new FakeStoreCheckoutStartAuthorityHandler(
        HttpStatusCode.Created,
        readyJson);
    using var http = new HttpClient(handler);
    using var transport = new StoreCheckoutStartRemote(
        http,
        "https://jl-bke.com");
    var snapshot = await transport.StartAsync(
        "transport-checkout-secret",
        request,
        CancellationToken.None);

    Require(snapshot.Status == "ready", "Store checkout-start transport status drifted");
    Require(snapshot.OrderId == "order-cert", "Store checkout-start transport order drifted");
    Require(handler.RequestCount == 1, "Store checkout-start mutation was retried");
    Require(handler.SawBearer, "Store checkout-start transport omitted Agent-owned bearer token");
    Require(handler.SawProtocol, "Store checkout-start transport omitted account-session protocol");
    Require(handler.SawExpectedPath, "Store checkout-start transport endpoint drifted");
    Require(handler.SawIntent, "Store checkout-start transport widened or omitted purchase intent");

    using var errorHandler = new FakeStoreCheckoutStartAuthorityHandler(
        HttpStatusCode.Conflict,
        """{"error":"LEGAL_ACCEPTANCE_REQUIRED"}""");
    using var errorHttp = new HttpClient(errorHandler);
    using var errorTransport = new StoreCheckoutStartRemote(
        errorHttp,
        "https://jl-bke.com");
    var errorResult = await errorTransport.StartAsync(
        "transport-checkout-secret",
        request,
        CancellationToken.None);
    Require(errorResult.ErrorCode == "LEGAL_ACCEPTANCE_REQUIRED", "Store checkout-start error mapping drifted");
    Require(errorHandler.RequestCount == 1, "Store checkout-start known failure was retried");

    using var ambiguousHandler = new FakeStoreCheckoutStartAuthorityHandler(
        HttpStatusCode.Created,
        readyJson,
        throwTransport: true);
    using var ambiguousHttp = new HttpClient(ambiguousHandler);
    using var ambiguousTransport = new StoreCheckoutStartRemote(
        ambiguousHttp,
        "https://jl-bke.com");
    try
    {
        _ = await ambiguousTransport.StartAsync(
            "transport-checkout-secret",
            request,
            CancellationToken.None);
        throw new InvalidOperationException(
            "Store checkout-start retried or hid an ambiguous mutation failure");
    }
    catch (HttpRequestException)
    {
        Require(ambiguousHandler.RequestCount == 1, "Store checkout-start mutation transport failure was retried");
    }

    using var widenedHandler = new FakeStoreCheckoutStartAuthorityHandler(
        HttpStatusCode.Created,
        """
        {
          "status":"ready",
          "correlation_id":"cert-checkout-correlation",
          "order_id":"order-cert",
          "checkout_url":"https://checkout.example.test/pay/order-cert",
          "complimentary":false,
          "provider":"paymongo"
        }
        """);
    using var widenedHttp = new HttpClient(widenedHandler);
    using var widenedTransport = new StoreCheckoutStartRemote(
        widenedHttp,
        "https://jl-bke.com");
    try
    {
        _ = await widenedTransport.StartAsync(
            "transport-checkout-secret",
            request,
            CancellationToken.None);
        throw new InvalidOperationException(
            "Store checkout-start accepted widened provider authority");
    }
    catch (InvalidDataException)
    {
        // Strict root keys intentionally reject provider authority.
    }
}

static async Task CertifyStoreCheckoutStatusBoundary()
{
    var account = new AccountSessionAccount(
        "user-checkout-status",
        "buyer-status@example.com",
        "account-checkout-status",
        "INDIVIDUAL",
        "Checkout Status Buyer");
    var store = new FakeAccountSessionStore();
    await store.WriteAsync(
        new ActiveAccountSessionState(
            "checkout-status-access-secret",
            "checkout-status-refresh-secret",
            "checkout-status-session",
            DateTimeOffset.UtcNow.AddMinutes(15),
            DateTimeOffset.UtcNow.AddDays(30),
            account),
        CancellationToken.None);

    var request = new StoreCheckoutStatusRequest(
        "cert-checkout-status-correlation");
    var remote = new FakeStoreCheckoutStatusRemote(
        new RemoteStoreCheckoutStatusResult(
            "found",
            request.CorrelationId,
            "order-status-cert",
            "BKE-2026-STATUS",
            "PENDING",
            "CLAIM_CODE",
            "PENDING",
            "https://checkout.example.test/pay/order-status-cert",
            null,
            null));
    var service = new StoreCheckoutStatusService(
        new FakeAuthenticatedAccountSessionService(account),
        store,
        remote);

    var response = await service.CheckAsync(
        request,
        CancellationToken.None);

    Require(response.Status == "FOUND", "Store checkout-status did not become FOUND");
    Require(response.CorrelationId == request.CorrelationId, "Store checkout-status correlation drifted");
    Require(response.OrderId == "order-status-cert", "Store checkout-status order id drifted");
    Require(response.OrderNumber == "BKE-2026-STATUS", "Store checkout-status order number drifted");
    Require(response.OrderStatus == "PENDING", "Store checkout-status order state drifted");
    Require(response.FulfillmentMode == "CLAIM_CODE", "Store checkout-status fulfillment mode drifted");
    Require(response.PaymentStatus == "PENDING", "Store checkout-status payment state drifted");
    Require(response.CheckoutUrl == "https://checkout.example.test/pay/order-status-cert", "Store checkout-status checkout URL drifted");
    Require(remote.AccessToken == "checkout-status-access-secret", "Store checkout-status remote did not receive Agent-owned access token");
    Require(remote.CorrelationId == request.CorrelationId, "Store checkout-status remote correlation drifted");

    var wire = JsonSerializer.Serialize(response);
    Require(!wire.Contains("checkout-status-access-secret", StringComparison.Ordinal), "Store checkout-status leaked access token");
    Require(!wire.Contains("checkout-status-refresh-secret", StringComparison.Ordinal), "Store checkout-status leaked refresh token");
    Require(!wire.Contains("account-checkout-status", StringComparison.Ordinal), "Store checkout-status leaked cloud account identifier");
    Require(!wire.Contains("paymongo", StringComparison.OrdinalIgnoreCase), "Store checkout-status leaked provider authority");

    var deniedRemote = new FakeStoreCheckoutStatusRemote(
        new RemoteStoreCheckoutStatusResult(
            "not_found",
            request.CorrelationId,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null));
    var denied = new StoreCheckoutStatusService(
        new FakeUnauthenticatedAccountSessionService(),
        store,
        deniedRemote);
    var deniedResponse = await denied.CheckAsync(
        request with { CorrelationId = "cert-checkout-status-auth" },
        CancellationToken.None);
    Require(deniedResponse.Status == "AUTH_REQUIRED", "Store checkout-status did not require authentication");
    Require(deniedRemote.AccessToken is null, "Store checkout-status called cloud authority without authentication");

    const string foundJson = """
        {
          "status":"found",
          "correlation_id":"cert-checkout-status-correlation",
          "order_id":"order-status-cert",
          "order_number":"BKE-2026-STATUS",
          "order_status":"PENDING",
          "fulfillment_mode":"CLAIM_CODE",
          "payment_status":"PENDING",
          "checkout_url":"https://checkout.example.test/pay/order-status-cert",
          "paid_at":null
        }
        """;

    using var handler = new FakeStoreCheckoutStatusAuthorityHandler(
        HttpStatusCode.OK,
        foundJson);
    using var http = new HttpClient(handler);
    using var transport = new StoreCheckoutStatusRemote(
        http,
        "https://jl-bke.com");
    var snapshot = await transport.CheckAsync(
        "transport-checkout-status-secret",
        request.CorrelationId,
        CancellationToken.None);

    Require(snapshot.Status == "found", "Store checkout-status transport state drifted");
    Require(snapshot.OrderId == "order-status-cert", "Store checkout-status transport order drifted");
    Require(snapshot.PaymentStatus == "PENDING", "Store checkout-status transport payment state drifted");
    Require(handler.RequestCount == 1, "Store checkout-status read was retried unexpectedly");
    Require(handler.SawBearer, "Store checkout-status transport omitted Agent-owned bearer token");
    Require(handler.SawProtocol, "Store checkout-status transport omitted account-session protocol");
    Require(handler.SawExpectedRequest, "Store checkout-status transport endpoint or correlation query drifted");
    Require(handler.SawNoBody, "Store checkout-status transport widened read authority with a body");

    using var notFoundHandler = new FakeStoreCheckoutStatusAuthorityHandler(
        HttpStatusCode.OK,
        """
        {
          "status":"not_found",
          "correlation_id":"cert-checkout-status-correlation"
        }
        """);
    using var notFoundHttp = new HttpClient(notFoundHandler);
    using var notFoundTransport = new StoreCheckoutStatusRemote(
        notFoundHttp,
        "https://jl-bke.com");
    var notFound = await notFoundTransport.CheckAsync(
        "transport-checkout-status-secret",
        request.CorrelationId,
        CancellationToken.None);
    Require(notFound.Status == "not_found", "Store checkout-status not_found drifted");
    Require(notFound.OrderId is null && notFound.CheckoutUrl is null, "Store checkout-status not_found invented checkout state");

    using var widenedHandler = new FakeStoreCheckoutStatusAuthorityHandler(
        HttpStatusCode.OK,
        """
        {
          "status":"found",
          "correlation_id":"cert-checkout-status-correlation",
          "order_id":"order-status-cert",
          "order_number":"BKE-2026-STATUS",
          "order_status":"PENDING",
          "fulfillment_mode":"CLAIM_CODE",
          "payment_status":"PENDING",
          "checkout_url":"https://checkout.example.test/pay/order-status-cert",
          "paid_at":null,
          "provider":"paymongo"
        }
        """);
    using var widenedHttp = new HttpClient(widenedHandler);
    using var widenedTransport = new StoreCheckoutStatusRemote(
        widenedHttp,
        "https://jl-bke.com");
    try
    {
        _ = await widenedTransport.CheckAsync(
            "transport-checkout-status-secret",
            request.CorrelationId,
            CancellationToken.None);
        throw new InvalidOperationException(
            "Store checkout-status accepted widened provider authority");
    }
    catch (InvalidDataException)
    {
        // Strict root keys intentionally reject provider authority.
    }
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

static async Task CertifySoftwareUpdateBoundary()
{
    var account = new AccountSessionAccount(
        "user-update",
        "updater@example.com",
        "account-update",
        "INDIVIDUAL",
        "Update Buyer");
    var store = new FakeAccountSessionStore();
    await store.WriteAsync(
        new ActiveAccountSessionState(
            "update-access-secret",
            "update-refresh-secret",
            "update-session",
            DateTimeOffset.UtcNow.AddMinutes(15),
            DateTimeOffset.UtcNow.AddDays(30),
            account),
        CancellationToken.None);

    var inventory = new FakeLocalProductInventory(
        new Dictionary<string, LocalInstalledProduct>(StringComparer.Ordinal)
        {
            ["bke-render-dock"] = new(
                "bke-render-dock",
                "1.0.1",
                "BKE_MANAGED_PACKAGE",
                "MANAGED_DIRECTORY"),
        });
    var authorization = new StandaloneUpdateAuthorization(
        "bke-render-dock",
        "1.0.1",
        "1.0.2",
        "jan2xo/BKE_RENDER_DOCK",
        "v1.0.2",
        """{"schema":"bke.update-policy.v2","signature":"hidden"}""");
    var remote = new FakeStandaloneUpdateAuthorizationRemote(
        new StandaloneUpdateAuthorizationResult(
            "UPDATE_AVAILABLE",
            authorization));
    var updater = new FakeStandaloneSoftwareUpdater(
        new StandaloneUpdateResult(
            "STARTED",
            "update_started",
            false));
    var service = new SoftwareUpdateService(
        new FakeAuthenticatedAccountSessionService(account),
        store,
        inventory,
        remote,
        updater);

    var response = await service.UpdateAsync(
        new SoftwareUpdateRequest(
            "cert-update",
            "bke-render-dock"),
        CancellationToken.None);

    Require(response.Status == "STARTED", "software update did not enter STARTED");
    Require(response.State == "update_started", "software update state drifted");
    Require(remote.AccessToken == "update-access-secret", "software update remote did not receive Agent-owned access token");
    Require(remote.ProductId == "bke-render-dock", "software update remote product drifted");
    Require(remote.CurrentVersion == "1.0.1", "software update remote current version drifted");
    Require(updater.ProductId == "bke-render-dock", "software update privileged product drifted");
    Require(updater.CurrentVersion == "1.0.1", "software update privileged current version drifted");
    Require(updater.Authorization?.TargetVersion == "1.0.2", "software update target authority drifted");

    var wire = JsonSerializer.Serialize(response);
    Require(!wire.Contains("update-access-secret", StringComparison.Ordinal), "software update access token leaked to local response");
    Require(!wire.Contains("update-refresh-secret", StringComparison.Ordinal), "software update refresh token leaked to local response");
    Require(!wire.Contains("github.com", StringComparison.OrdinalIgnoreCase), "software update release URL leaked to local response");
    Require(!wire.Contains("BKE_RENDER_DOCK", StringComparison.Ordinal), "software update repository identity leaked to local response");
    Require(!wire.Contains("Program Files", StringComparison.OrdinalIgnoreCase), "software update install path leaked to local response");

    var unsupportedRemote = new FakeStandaloneUpdateAuthorizationRemote(
        new StandaloneUpdateAuthorizationResult("UPDATE_AVAILABLE", authorization));
    var unsupportedUpdater = new FakeStandaloneSoftwareUpdater(
        new StandaloneUpdateResult("STARTED", "update_started", false));
    var unsupported = new SoftwareUpdateService(
        new FakeAuthenticatedAccountSessionService(account),
        store,
        new FakeLocalProductInventory(
            new Dictionary<string, LocalInstalledProduct>(StringComparer.Ordinal)
            {
                ["bke-render-dock"] = new(
                    "bke-render-dock",
                    "1.0.1",
                    "PRODUCT_INSTALLER",
                    "INSTALLER_EXECUTABLE"),
            }),
        unsupportedRemote,
        unsupportedUpdater);
    var unsupportedResponse = await unsupported.UpdateAsync(
        new SoftwareUpdateRequest(
            "cert-update-provenance",
            "bke-render-dock"),
        CancellationToken.None);
    Require(unsupportedResponse.Error?.Code == "UNSUPPORTED_PROVENANCE", "software update accepted installer-owned provenance");
    Require(unsupportedRemote.ProductId is null, "software update called cloud authority for unsupported provenance");
    Require(unsupportedUpdater.ProductId is null, "software update invoked privileged updater for unsupported provenance");

    var denied = new SoftwareUpdateService(
        new FakeAuthenticatedAccountSessionService(account),
        store,
        inventory,
        new FakeStandaloneUpdateAuthorizationRemote(
            new StandaloneUpdateAuthorizationResult("NOT_ENTITLED")),
        updater);
    var deniedResponse = await denied.UpdateAsync(
        new SoftwareUpdateRequest(
            "cert-update-denied",
            "bke-render-dock"),
        CancellationToken.None);
    Require(deniedResponse.Error?.Code == "NOT_ENTITLED", "truthful update denial was flattened");
}

static async Task CertifySoftwareRepairBoundary()
{
    var account = new AccountSessionAccount(
        "user-repair",
        "repairer@example.com",
        "account-repair",
        "INDIVIDUAL",
        "Repair Buyer");
    var store = new FakeAccountSessionStore();
    await store.WriteAsync(
        new ActiveAccountSessionState(
            "repair-access-secret",
            "repair-refresh-secret",
            "repair-session",
            DateTimeOffset.UtcNow.AddMinutes(15),
            DateTimeOffset.UtcNow.AddDays(30),
            account),
        CancellationToken.None);

    var inventory = new FakeLocalProductInventory(
        new Dictionary<string, LocalInstalledProduct>(StringComparer.Ordinal)
        {
            ["bke-render-dock"] = new(
                "bke-render-dock",
                "1.0.2",
                "BKE_MANAGED_PACKAGE",
                "MANAGED_DIRECTORY"),
        });
    var authorization = new StandaloneRepairAuthorization(
        "bke-render-dock",
        "1.0.2",
        "jan2xo/BKE_RENDER_DOCK",
        "v1.0.2",
        """{"schema":"bke.repair-policy.v1","signature":"hidden"}""");
    var remote = new FakeStandaloneRepairAuthorizationRemote(
        new StandaloneRepairAuthorizationResult(
            "REPAIR_AUTHORIZED",
            authorization));
    var repairer = new FakeStandaloneSoftwareRepairer(
        new StandaloneRepairResult(
            "STARTED",
            "repair_started",
            false));
    var service = new SoftwareRepairService(
        new FakeAuthenticatedAccountSessionService(account),
        store,
        inventory,
        remote,
        repairer);

    var response = await service.RepairAsync(
        new SoftwareRepairRequest(
            "cert-repair",
            "bke-render-dock"),
        CancellationToken.None);

    Require(response.Status == "STARTED", "software Repair did not enter STARTED");
    Require(response.State == "repair_started", "software Repair state drifted");
    Require(remote.AccessToken == "repair-access-secret", "software Repair remote did not receive Agent-owned access token");
    Require(remote.ProductId == "bke-render-dock", "software Repair remote product drifted");
    Require(remote.CurrentVersion == "1.0.2", "software Repair did not authorize installed version");
    Require(repairer.ProductId == "bke-render-dock", "software Repair privileged product drifted");
    Require(repairer.CurrentVersion == "1.0.2", "software Repair privileged current version drifted");
    Require(repairer.Authorization?.RepairVersion == "1.0.2", "software Repair version authority drifted");

    var wire = JsonSerializer.Serialize(response);
    Require(!wire.Contains("repair-access-secret", StringComparison.Ordinal), "software Repair access token leaked to local response");
    Require(!wire.Contains("repair-refresh-secret", StringComparison.Ordinal), "software Repair refresh token leaked to local response");
    Require(!wire.Contains("github.com", StringComparison.OrdinalIgnoreCase), "software Repair release URL leaked to local response");
    Require(!wire.Contains("BKE_RENDER_DOCK", StringComparison.Ordinal), "software Repair repository identity leaked to local response");
    Require(!wire.Contains("Program Files", StringComparison.OrdinalIgnoreCase), "software Repair install path leaked to local response");

    var unsupportedRemote = new FakeStandaloneRepairAuthorizationRemote(
        new StandaloneRepairAuthorizationResult("REPAIR_AUTHORIZED", authorization));
    var unsupportedRepairer = new FakeStandaloneSoftwareRepairer(
        new StandaloneRepairResult("STARTED", "repair_started", false));
    var unsupported = new SoftwareRepairService(
        new FakeAuthenticatedAccountSessionService(account),
        store,
        new FakeLocalProductInventory(
            new Dictionary<string, LocalInstalledProduct>(StringComparer.Ordinal)
            {
                ["bke-render-dock"] = new(
                    "bke-render-dock",
                    "1.0.2",
                    "PRODUCT_INSTALLER",
                    "INSTALLER_EXECUTABLE"),
            }),
        unsupportedRemote,
        unsupportedRepairer);
    var unsupportedResponse = await unsupported.RepairAsync(
        new SoftwareRepairRequest(
            "cert-repair-provenance",
            "bke-render-dock"),
        CancellationToken.None);
    Require(unsupportedResponse.Error?.Code == "UNSUPPORTED_PROVENANCE", "software Repair accepted installer-owned provenance");
    Require(unsupportedRemote.ProductId is null, "software Repair called cloud authority for unsupported provenance");
    Require(unsupportedRepairer.ProductId is null, "software Repair invoked privileged replacement for unsupported provenance");

    var denied = new SoftwareRepairService(
        new FakeAuthenticatedAccountSessionService(account),
        store,
        inventory,
        new FakeStandaloneRepairAuthorizationRemote(
            new StandaloneRepairAuthorizationResult("NOT_ENTITLED")),
        repairer);
    var deniedResponse = await denied.RepairAsync(
        new SoftwareRepairRequest(
            "cert-repair-denied",
            "bke-render-dock"),
        CancellationToken.None);
    Require(deniedResponse.Error?.Code == "NOT_ENTITLED", "truthful Repair denial was flattened");
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

static async Task CertifySoftwareRemoveBoundary()
{
    var account = new AccountSessionAccount(
        "user-remove",
        "remover@example.com",
        "account-remove",
        "INDIVIDUAL",
        "Remove Buyer");
    var inventory = new FakeLocalProductInventory(
        new Dictionary<string, LocalInstalledProduct>(StringComparer.Ordinal)
        {
            ["bke-render-dock"] = new(
                "bke-render-dock",
                "1.0.2",
                "BKE_MANAGED_PACKAGE",
                "MANAGED_DIRECTORY"),
        });
    var remover = new FakeStandaloneSoftwareRemover(
        new StandaloneRemovalResult(
            "REMOVED",
            "removed",
            false));
    var service = new SoftwareRemoveService(
        new FakeAuthenticatedAccountSessionService(account),
        inventory,
        remover);

    var response = await service.RemoveAsync(
        new SoftwareRemoveRequest(
            "cert-remove",
            "bke-render-dock"),
        CancellationToken.None);

    Require(response.Status == "REMOVED", "software remove did not enter REMOVED");
    Require(response.State == "removed", "software remove state drifted");
    Require(remover.ProductId == "bke-render-dock", "software remove product drifted");
    Require(remover.Version == "1.0.2", "software remove version drifted");

    var wire = JsonSerializer.Serialize(response);
    Require(!wire.Contains("Program Files", StringComparison.OrdinalIgnoreCase), "software remove leaked an install path");
    Require(!wire.Contains("RENDER DOCK.exe", StringComparison.OrdinalIgnoreCase), "software remove leaked an entry point");

    var missingRemover = new FakeStandaloneSoftwareRemover(
        new StandaloneRemovalResult(
            "REMOVED",
            "removed",
            false));
    var missing = new SoftwareRemoveService(
        new FakeAuthenticatedAccountSessionService(account),
        new FakeLocalProductInventory(
            new Dictionary<string, LocalInstalledProduct>(StringComparer.Ordinal)),
        missingRemover);
    var missingResponse = await missing.RemoveAsync(
        new SoftwareRemoveRequest(
            "cert-remove-missing",
            "bke-render-dock"),
        CancellationToken.None);
    Require(missingResponse.Status == "NOT_INSTALLED", "software remove missing-product state drifted");
    Require(missingRemover.ProductId is null, "software remove invoked privileged remover for absent product");

    var unauthenticatedRemover = new FakeStandaloneSoftwareRemover(
        new StandaloneRemovalResult(
            "REMOVED",
            "removed",
            false));
    var unauthenticated = new SoftwareRemoveService(
        new FakeUnauthenticatedAccountSessionService(),
        inventory,
        unauthenticatedRemover);
    var unauthenticatedResponse = await unauthenticated.RemoveAsync(
        new SoftwareRemoveRequest(
            "cert-remove-auth",
            "bke-render-dock"),
        CancellationToken.None);
    Require(unauthenticatedResponse.Status == "AUTH_REQUIRED", "software remove did not require an account session");
    Require(unauthenticatedRemover.ProductId is null, "software remove invoked privileged remover without authentication");

    var protectedRemover = new FakeStandaloneSoftwareRemover(
        new StandaloneRemovalResult(
            "PROTECTED_TARGET",
            "protected_target",
            false));
    var protectedService = new SoftwareRemoveService(
        new FakeAuthenticatedAccountSessionService(account),
        inventory,
        protectedRemover);
    var protectedResponse = await protectedService.RemoveAsync(
        new SoftwareRemoveRequest(
            "cert-remove-protected",
            "bke-render-dock"),
        CancellationToken.None);
    Require(protectedResponse.Error?.Code == "PROTECTED_TARGET", "software remove protected-target denial was flattened");
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

sealed class FakeNotificationAuthorityHandler : HttpMessageHandler
{
    public bool SawBearer { get; private set; }
    public bool SawProtocol { get; private set; }

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var path = request.RequestUri?.AbsolutePath
            ?? throw new InvalidOperationException("notification authority URI missing");

        if (path == "/api/licensing-agent/notifications")
        {
            return Task.FromResult(JsonResponse(
                """
                {
                  "capabilityId":"bke.product-broadcasts",
                  "contractVersion":1,
                  "source":"bke-digital-solutions",
                  "productId":"bke-render-dock",
                  "version":"1.0.2",
                  "broadcasts":[]
                }
                """));
        }

        if (path == "/api/agent-sessions/notifications")
        {
            SawBearer =
                request.Headers.Authorization?.Scheme == "Bearer" &&
                request.Headers.Authorization.Parameter == "account-access-secret";
            SawProtocol =
                request.Headers.TryGetValues(
                    "x-bke-account-session-version",
                    out var versions) &&
                versions.SingleOrDefault() == AccountSessionRemote.ProtocolVersion;

            if (!SawBearer || !SawProtocol ||
                request.RequestUri?.Query.Contains(
                    "product_id=bke-render-dock",
                    StringComparison.Ordinal) != true)
            {
                return Task.FromResult(
                    new HttpResponseMessage(HttpStatusCode.Unauthorized));
            }

            var response = JsonResponse(
                """
                {
                  "status":"ok",
                  "account_id":"account-1",
                  "product_id":"bke-render-dock",
                  "notifications":[
                    {
                      "id":"bke-11111111-2222-3333-4444-555555555555",
                      "source":"payments",
                      "event":"PAYMENT_RECEIVED",
                      "title":"Payment received",
                      "body":"Payment for order TEST-1 was confirmed.",
                      "category":"TRANSACTIONAL",
                      "priority":"NORMAL",
                      "created_at":"2026-09-20T12:00:00.000Z",
                      "expires_at":null,
                      "data":{"orderNumber":"TEST-1"}
                    }
                  ]
                }
                """);
            response.Headers.TryAddWithoutValidation(
                "x-bke-account-session-version",
                AccountSessionRemote.ProtocolVersion);
            return Task.FromResult(response);
        }

        return Task.FromResult(
            new HttpResponseMessage(HttpStatusCode.NotFound));
    }

    private static HttpResponseMessage JsonResponse(string json) =>
        new(HttpStatusCode.OK)
        {
            Content = new StringContent(
                json,
                Encoding.UTF8,
                "application/json"),
        };
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
    public int NativeExchangeCount { get; private set; }
    public string? LastNativeHandoff { get; private set; }
    public int RefreshCount { get; private set; }
    public int AcknowledgeCount { get; private set; }
    public bool ThrowOnRevoke { get; set; }
    public Queue<RemoteAccountSessionPoll> Polls { get; } = new();
    public Queue<RemoteAccountSessionPoll> NativeExchanges { get; } = new();
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

    public Task<RemoteAccountSessionPoll> ExchangeNativeAsync(
        string handoffCode,
        CancellationToken cancellationToken)
    {
        NativeExchangeCount += 1;
        LastNativeHandoff = handoffCode;
        return Task.FromResult(NativeExchanges.Dequeue());
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

    public Task<AccountSessionCompleteResponse> CompleteAsync(
        AccountSessionCompleteRequest request,
        CancellationToken cancellationToken) =>
        throw new NotSupportedException();

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

sealed class FakeUnauthenticatedAccountSessionService : IAccountSessionService
{
    public Task<AccountSessionCompleteResponse> CompleteAsync(
        AccountSessionCompleteRequest request,
        CancellationToken cancellationToken) =>
        throw new NotSupportedException();

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
            "AUTH_REQUIRED",
            null,
            new AccountSessionError(
                "AUTH_REQUIRED",
                "Sign in with a BKE account.",
                false)));

    public Task<AccountSessionLogoutResponse> LogoutAsync(
        AccountSessionLogoutRequest request,
        CancellationToken cancellationToken) =>
        throw new NotSupportedException();
}


sealed class FakeClaimCodeRedemptionRemote(
    RemoteClaimCodeRedemptionResult result) : IClaimCodeRedemptionRemote
{
    public string? AccessToken { get; private set; }
    public string? Code { get; private set; }

    public Task<RemoteClaimCodeRedemptionResult> RedeemAsync(
        string accessToken,
        string code,
        CancellationToken cancellationToken)
    {
        AccessToken = accessToken;
        Code = code;
        return Task.FromResult(result);
    }
}

sealed class FakeClaimCodeRedemptionAuthorityHandler : HttpMessageHandler, IDisposable
{
    private readonly HttpStatusCode _statusCode;
    private readonly string _json;
    private readonly bool _includeProtocol;

    public FakeClaimCodeRedemptionAuthorityHandler(
        HttpStatusCode statusCode,
        string json,
        bool includeProtocol = true)
    {
        _statusCode = statusCode;
        _json = json;
        _includeProtocol = includeProtocol;
    }

    public int RequestCount { get; private set; }
    public bool SawBearer { get; private set; }
    public bool SawProtocol { get; private set; }
    public bool SawExpectedPath { get; private set; }
    public bool SawClaimCode { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        RequestCount += 1;
        SawBearer =
            request.Headers.Authorization?.Scheme == "Bearer" &&
            request.Headers.Authorization.Parameter == "transport-access-secret";
        SawProtocol =
            request.Headers.TryGetValues(
                "x-bke-account-session-version",
                out var versions) &&
            versions.SingleOrDefault() == AccountSessionRemote.ProtocolVersion;
        SawExpectedPath =
            request.Method == HttpMethod.Post &&
            request.RequestUri?.AbsolutePath ==
                "/api/agent-sessions/claims/redeem";

        var body = request.Content is null
            ? string.Empty
            : await request.Content.ReadAsStringAsync(cancellationToken);
        SawClaimCode = body.Contains(
            "BKE-CLM-AAAAA-BBBBB-CCCCC-DDDDD-EEEEE-FFFFF",
            StringComparison.Ordinal);

        var response = new HttpResponseMessage(_statusCode)
        {
            Content = new StringContent(
                _json,
                Encoding.UTF8,
                "application/json"),
        };
        if (_includeProtocol)
        {
            response.Headers.TryAddWithoutValidation(
                "x-bke-account-session-version",
                AccountSessionRemote.ProtocolVersion);
        }
        return response;
    }
}


sealed class FakeStoreCatalogRemote(
    RemoteStoreCatalogSnapshot snapshot) : IStoreCatalogRemote
{
    public string? AccessToken { get; private set; }

    public Task<RemoteStoreCatalogSnapshot> GetAsync(
        string accessToken,
        CancellationToken cancellationToken)
    {
        AccessToken = accessToken;
        return Task.FromResult(snapshot);
    }
}

sealed class FakeStoreCatalogAuthorityHandler(
    string json) : HttpMessageHandler
{
    public bool SawBearer { get; private set; }
    public bool SawProtocol { get; private set; }
    public bool SawExpectedPath { get; private set; }

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        SawBearer =
            request.Headers.Authorization?.Scheme == "Bearer" &&
            request.Headers.Authorization.Parameter == "transport-store-secret";
        SawProtocol =
            request.Headers.TryGetValues(
                "x-bke-account-session-version",
                out var versions) &&
            versions.SingleOrDefault() == AccountSessionRemote.ProtocolVersion;
        SawExpectedPath =
            request.Method == HttpMethod.Get &&
            request.RequestUri?.AbsolutePath == "/api/agent-sessions/store";

        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(
                json,
                Encoding.UTF8,
                "application/json"),
        };
        response.Headers.TryAddWithoutValidation(
            "x-bke-account-session-version",
            AccountSessionRemote.ProtocolVersion);
        return Task.FromResult(response);
    }
}

sealed class FakeStoreCheckoutReviewRemote(
    RemoteStoreCheckoutReviewResult result) : IStoreCheckoutReviewRemote
{
    public string? AccessToken { get; private set; }
    public string? PurchasePlanId { get; private set; }

    public Task<RemoteStoreCheckoutReviewResult> ReviewAsync(
        string accessToken,
        string purchasePlanId,
        CancellationToken cancellationToken)
    {
        AccessToken = accessToken;
        PurchasePlanId = purchasePlanId;
        return Task.FromResult(result);
    }
}

sealed class FakeStoreCheckoutReviewAuthorityHandler(
    HttpStatusCode statusCode,
    string json,
    int transientFailures = 0) : HttpMessageHandler
{
    public int RequestCount { get; private set; }
    public bool SawBearer { get; private set; }
    public bool SawProtocol { get; private set; }
    public bool SawExpectedPath { get; private set; }
    public bool SawPlanQuery { get; private set; }

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        RequestCount += 1;
        SawBearer =
            request.Headers.Authorization?.Scheme == "Bearer" &&
            request.Headers.Authorization.Parameter == "transport-review-secret";
        SawProtocol =
            request.Headers.TryGetValues(
                "x-bke-account-session-version",
                out var versions) &&
            versions.SingleOrDefault() == AccountSessionRemote.ProtocolVersion;
        SawExpectedPath =
            request.Method == HttpMethod.Get &&
            request.RequestUri?.AbsolutePath ==
                "/api/agent-sessions/store/checkout-review";
        SawPlanQuery =
            request.RequestUri?.Query.Contains(
                "purchase_plan_id=plan-perpetual",
                StringComparison.Ordinal) == true;

        var transient = RequestCount <= transientFailures;
        var response = new HttpResponseMessage(
            transient
                ? HttpStatusCode.ServiceUnavailable
                : statusCode)
        {
            Content = new StringContent(
                transient
                    ? """{"status":"catalog_unavailable"}"""
                    : json,
                Encoding.UTF8,
                "application/json"),
        };
        response.Headers.TryAddWithoutValidation(
            "x-bke-account-session-version",
            AccountSessionRemote.ProtocolVersion);
        return Task.FromResult(response);
    }
}

sealed class FakeStoreCheckoutStartRemote(
    RemoteStoreCheckoutStartResult result) : IStoreCheckoutStartRemote
{
    public string? AccessToken { get; private set; }
    public StoreCheckoutStartRequest? Request { get; private set; }

    public Task<RemoteStoreCheckoutStartResult> StartAsync(
        string accessToken,
        StoreCheckoutStartRequest request,
        CancellationToken cancellationToken)
    {
        AccessToken = accessToken;
        Request = request;
        return Task.FromResult(result);
    }
}

sealed class FakeStoreCheckoutStartAuthorityHandler(
    HttpStatusCode statusCode,
    string json,
    bool throwTransport = false) : HttpMessageHandler
{
    public int RequestCount { get; private set; }
    public bool SawBearer { get; private set; }
    public bool SawProtocol { get; private set; }
    public bool SawExpectedPath { get; private set; }
    public bool SawIntent { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        RequestCount += 1;
        SawBearer =
            request.Headers.Authorization?.Scheme == "Bearer" &&
            request.Headers.Authorization.Parameter == "transport-checkout-secret";
        SawProtocol =
            request.Headers.TryGetValues(
                "x-bke-account-session-version",
                out var versions) &&
            versions.SingleOrDefault() == AccountSessionRemote.ProtocolVersion;
        SawExpectedPath =
            request.Method == HttpMethod.Post &&
            request.RequestUri?.AbsolutePath ==
                "/api/agent-sessions/store/checkout-start";

        if (request.Content is not null)
        {
            var body = await request.Content.ReadAsStringAsync(cancellationToken);
            using var document = JsonDocument.Parse(body);
            var root = document.RootElement;
            var keys = root.EnumerateObject()
                .Select(property => property.Name)
                .ToHashSet(StringComparer.Ordinal);
            SawIntent =
                keys.SetEquals([
                    "correlation_id",
                    "purchase_plan_id",
                    "purchase_mode",
                    "legal_version_ids",
                ]) &&
                root.GetProperty("correlation_id").GetString() ==
                    "cert-checkout-correlation" &&
                root.GetProperty("purchase_plan_id").GetString() ==
                    "plan-perpetual" &&
                root.GetProperty("purchase_mode").GetString() ==
                    "GIFT" &&
                root.GetProperty("legal_version_ids")
                    .EnumerateArray()
                    .Select(value => value.GetString())
                    .SequenceEqual(["terms-v3", "privacy-v2"]);
        }

        if (throwTransport)
        {
            throw new HttpRequestException(
                "certified ambiguous checkout-start transport failure");
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

sealed class FakeStoreCheckoutStatusRemote(
    RemoteStoreCheckoutStatusResult result) : IStoreCheckoutStatusRemote
{
    public string? AccessToken { get; private set; }
    public string? CorrelationId { get; private set; }

    public Task<RemoteStoreCheckoutStatusResult> CheckAsync(
        string accessToken,
        string correlationId,
        CancellationToken cancellationToken)
    {
        AccessToken = accessToken;
        CorrelationId = correlationId;
        return Task.FromResult(result);
    }
}

sealed class FakeStoreCheckoutStatusAuthorityHandler(
    HttpStatusCode statusCode,
    string json) : HttpMessageHandler
{
    public int RequestCount { get; private set; }
    public bool SawBearer { get; private set; }
    public bool SawProtocol { get; private set; }
    public bool SawExpectedRequest { get; private set; }
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
                "transport-checkout-status-secret";
        SawProtocol =
            request.Headers.TryGetValues(
                "x-bke-account-session-version",
                out var versions) &&
            versions.SingleOrDefault() == AccountSessionRemote.ProtocolVersion;
        SawExpectedRequest =
            request.Method == HttpMethod.Get &&
            request.RequestUri?.AbsolutePath ==
                "/api/agent-sessions/store/checkout-status" &&
            request.RequestUri?.Query ==
                "?correlation_id=cert-checkout-status-correlation";
        SawNoBody = request.Content is null;

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
        return Task.FromResult(response);
    }
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

sealed class FakeStandaloneRepairAuthorizationRemote(
    StandaloneRepairAuthorizationResult result)
    : IStandaloneRepairAuthorizationRemote
{
    public string? AccessToken { get; private set; }
    public string? ProductId { get; private set; }
    public string? CurrentVersion { get; private set; }

    public Task<StandaloneRepairAuthorizationResult> AuthorizeAsync(
        string accessToken,
        string productId,
        string currentVersion,
        CancellationToken cancellationToken)
    {
        AccessToken = accessToken;
        ProductId = productId;
        CurrentVersion = currentVersion;
        return Task.FromResult(result);
    }
}

sealed class FakeStandaloneSoftwareRepairer(
    StandaloneRepairResult result)
    : IStandaloneSoftwareRepairer
{
    public string? ProductId { get; private set; }
    public string? CurrentVersion { get; private set; }
    public StandaloneRepairAuthorization? Authorization { get; private set; }

    public Task<StandaloneRepairResult> RepairAsync(
        LocalInstalledProduct installed,
        StandaloneRepairAuthorization authorization,
        CancellationToken cancellationToken)
    {
        ProductId = installed.ProductId;
        CurrentVersion = installed.Version;
        Authorization = authorization;
        return Task.FromResult(result);
    }
}

sealed class FakeStandaloneUpdateAuthorizationRemote(
    StandaloneUpdateAuthorizationResult result)
    : IStandaloneUpdateAuthorizationRemote
{
    public string? AccessToken { get; private set; }
    public string? ProductId { get; private set; }
    public string? CurrentVersion { get; private set; }

    public Task<StandaloneUpdateAuthorizationResult> AuthorizeAsync(
        string accessToken,
        string productId,
        string currentVersion,
        CancellationToken cancellationToken)
    {
        AccessToken = accessToken;
        ProductId = productId;
        CurrentVersion = currentVersion;
        return Task.FromResult(result);
    }
}

sealed class FakeStandaloneSoftwareUpdater(
    StandaloneUpdateResult result)
    : IStandaloneSoftwareUpdater
{
    public string? ProductId { get; private set; }
    public string? CurrentVersion { get; private set; }
    public StandaloneUpdateAuthorization? Authorization { get; private set; }

    public Task<StandaloneUpdateResult> UpdateAsync(
        LocalInstalledProduct installed,
        StandaloneUpdateAuthorization authorization,
        CancellationToken cancellationToken)
    {
        ProductId = installed.ProductId;
        CurrentVersion = installed.Version;
        Authorization = authorization;
        return Task.FromResult(result);
    }
}

sealed class FakeStandaloneSoftwareRemover(
    StandaloneRemovalResult result)
    : IStandaloneSoftwareRemover
{
    public string? ProductId { get; private set; }
    public string? Version { get; private set; }

    public Task<StandaloneRemovalResult> RemoveAsync(
        LocalInstalledProduct product,
        CancellationToken cancellationToken)
    {
        ProductId = product.ProductId;
        Version = product.Version;
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

