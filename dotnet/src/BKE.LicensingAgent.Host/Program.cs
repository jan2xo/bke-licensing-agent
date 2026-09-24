using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;
using BKE.LicensingAgent.Host;
using BKE.LicensingAgent.Infrastructure;
using BKE.LicensingAgent.Storage;

try
{
    var runtimeEnvironment =
        AgentRuntimeEnvironmentLoader.LoadDefault();
    Console.WriteLine(
        $"BKE Licensing Agent environment: {runtimeEnvironment.Name}");
}
catch (Exception exception)
{
    Console.Error.WriteLine(
        $"BKE Licensing Agent environment bootstrap failed: {exception.Message}");
    return 78;
}

var agentDataDir =
    Environment.GetEnvironmentVariable("BKE_AGENT_DATA_DIR") ??
    Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        ".local",
        "share",
        "bke_licensing_agent");
agentDataDir = Path.GetFullPath(agentDataDir);

try
{
    AgentDatabase.EnsureInitialized(agentDataDir);
    Environment.SetEnvironmentVariable(
        "BKE_AGENT_DATA_DIR",
        agentDataDir,
        EnvironmentVariableTarget.Process);
}
catch (Exception exception)
{
    Console.Error.WriteLine(
        $"BKE Licensing Agent storage bootstrap failed: {exception.Message}");
    return 70;
}

var port = LocalAgentContract.DefaultPort;
var configuredPort = Environment.GetEnvironmentVariable("BKE_AGENT_PORT");
if (!string.IsNullOrWhiteSpace(configuredPort))
{
    if (!int.TryParse(configuredPort, out port) || port is < 1 or > 65535)
    {
        Console.Error.WriteLine("BKE_AGENT_PORT must be an integer between 1 and 65535.");
        return 78;
    }
}

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.MaxRequestBodySize = LocalAgentContract.MaxJsonBodyBytes;
    options.ListenLocalhost(port);
});

builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.PropertyNamingPolicy = null;
});

builder.Services.AddSingleton<AuthorizationProvider>();
builder.Services.AddSingleton<IAuthorizationService>(services => services.GetRequiredService<AuthorizationProvider>());
builder.Services.AddSingleton<ActivationProvider>();
builder.Services.AddSingleton<IActivationService>(services => services.GetRequiredService<ActivationProvider>());
builder.Services.AddSingleton<LicenseCenterProvider>();
builder.Services.AddSingleton<ILicenseCenterService>(services => services.GetRequiredService<LicenseCenterProvider>());
builder.Services.AddSingleton<NotificationProvider>();
builder.Services.AddSingleton<INotificationService>(services => services.GetRequiredService<NotificationProvider>());
builder.Services.AddSingleton<UpdateProvider>();
builder.Services.AddSingleton<PrivilegedUpdateCenterProvider>();
builder.Services.AddSingleton<IStandaloneSoftwareProvisioner>(services =>
    services.GetRequiredService<PrivilegedUpdateCenterProvider>());
builder.Services.AddSingleton<IStandaloneSoftwareUpdater>(services =>
    services.GetRequiredService<PrivilegedUpdateCenterProvider>());
builder.Services.AddSingleton<IStandaloneSoftwareRepairer>(services =>
    services.GetRequiredService<PrivilegedUpdateCenterProvider>());
builder.Services.AddSingleton<IStandaloneSoftwareRemover>(services =>
    services.GetRequiredService<PrivilegedUpdateCenterProvider>());
builder.Services.AddSingleton<IUpdateService, Gen2UpdateService>();
builder.Services.AddSingleton<IAccountSessionRemote>(_ => new AccountSessionRemote());
builder.Services.AddSingleton<IAccountSessionSecretStore>(_ => new WindowsDpapiAccountSessionSecretStore());
builder.Services.AddSingleton<IAccountSessionService>(services => new AccountSessionService(
    services.GetRequiredService<IAccountSessionRemote>(),
    services.GetRequiredService<IAccountSessionSecretStore>()));
builder.Services.AddSingleton<SoftwareCatalogRemote>();
builder.Services.AddSingleton<ISoftwareCatalogRemote>(services =>
    services.GetRequiredService<SoftwareCatalogRemote>());
builder.Services.AddSingleton<SqliteProductInventory>();
builder.Services.AddSingleton<ILocalProductInventory>(services =>
    services.GetRequiredService<SqliteProductInventory>());
builder.Services.AddSingleton<ISoftwareCatalogService>(services => new SoftwareCatalogService(
    services.GetRequiredService<IAccountSessionService>(),
    services.GetRequiredService<IAccountSessionSecretStore>(),
    services.GetRequiredService<ISoftwareCatalogRemote>(),
    services.GetRequiredService<ILocalProductInventory>()));
builder.Services.AddSingleton<ClaimCodeRedemptionRemote>();
builder.Services.AddSingleton<IClaimCodeRedemptionRemote>(services =>
    services.GetRequiredService<ClaimCodeRedemptionRemote>());
builder.Services.AddSingleton<IClaimCodeRedemptionService>(services => new ClaimCodeRedemptionService(
    services.GetRequiredService<IAccountSessionService>(),
    services.GetRequiredService<IAccountSessionSecretStore>(),
    services.GetRequiredService<IClaimCodeRedemptionRemote>()));
builder.Services.AddSingleton<StoreCatalogRemote>();
builder.Services.AddSingleton<IStoreCatalogRemote>(services =>
    services.GetRequiredService<StoreCatalogRemote>());
builder.Services.AddSingleton<IStoreCatalogService>(services => new StoreCatalogService(
    services.GetRequiredService<IAccountSessionService>(),
    services.GetRequiredService<IAccountSessionSecretStore>(),
    services.GetRequiredService<IStoreCatalogRemote>()));
builder.Services.AddSingleton<StoreCheckoutReviewRemote>();
builder.Services.AddSingleton<IStoreCheckoutReviewRemote>(services =>
    services.GetRequiredService<StoreCheckoutReviewRemote>());
builder.Services.AddSingleton<IStoreCheckoutReviewService>(services => new StoreCheckoutReviewService(
    services.GetRequiredService<IAccountSessionService>(),
    services.GetRequiredService<IAccountSessionSecretStore>(),
    services.GetRequiredService<IStoreCheckoutReviewRemote>()));
builder.Services.AddSingleton<StoreCheckoutStartRemote>();
builder.Services.AddSingleton<IStoreCheckoutStartRemote>(services =>
    services.GetRequiredService<StoreCheckoutStartRemote>());
builder.Services.AddSingleton<IStoreCheckoutStartService>(services => new StoreCheckoutStartService(
    services.GetRequiredService<IAccountSessionService>(),
    services.GetRequiredService<IAccountSessionSecretStore>(),
    services.GetRequiredService<IStoreCheckoutStartRemote>()));
builder.Services.AddSingleton<StoreCheckoutStatusRemote>();
builder.Services.AddSingleton<IStoreCheckoutStatusRemote>(services =>
    services.GetRequiredService<StoreCheckoutStatusRemote>());
builder.Services.AddSingleton<IStoreCheckoutStatusService>(services => new StoreCheckoutStatusService(
    services.GetRequiredService<IAccountSessionService>(),
    services.GetRequiredService<IAccountSessionSecretStore>(),
    services.GetRequiredService<IStoreCheckoutStatusRemote>()));
builder.Services.AddSingleton<StandaloneProvisionAuthorizationRemote>();
builder.Services.AddSingleton<IStandaloneProvisionAuthorizationRemote>(services =>
    services.GetRequiredService<StandaloneProvisionAuthorizationRemote>());
builder.Services.AddSingleton<ISoftwareInstallService>(services => new SoftwareInstallService(
    services.GetRequiredService<IAccountSessionService>(),
    services.GetRequiredService<IAccountSessionSecretStore>(),
    services.GetRequiredService<ILocalProductInventory>(),
    services.GetRequiredService<IStandaloneProvisionAuthorizationRemote>(),
    services.GetRequiredService<IStandaloneSoftwareProvisioner>()));
builder.Services.AddSingleton<StandaloneUpdateAuthorizationRemote>();
builder.Services.AddSingleton<IStandaloneUpdateAuthorizationRemote>(services =>
    services.GetRequiredService<StandaloneUpdateAuthorizationRemote>());
builder.Services.AddSingleton<ISoftwareUpdateService>(services => new SoftwareUpdateService(
    services.GetRequiredService<IAccountSessionService>(),
    services.GetRequiredService<IAccountSessionSecretStore>(),
    services.GetRequiredService<ILocalProductInventory>(),
    services.GetRequiredService<IStandaloneUpdateAuthorizationRemote>(),
    services.GetRequiredService<IStandaloneSoftwareUpdater>()));
builder.Services.AddSingleton<StandaloneRepairAuthorizationRemote>();
builder.Services.AddSingleton<IStandaloneRepairAuthorizationRemote>(services =>
    services.GetRequiredService<StandaloneRepairAuthorizationRemote>());
builder.Services.AddSingleton<ISoftwareRepairService>(services => new SoftwareRepairService(
    services.GetRequiredService<IAccountSessionService>(),
    services.GetRequiredService<IAccountSessionSecretStore>(),
    services.GetRequiredService<ILocalProductInventory>(),
    services.GetRequiredService<IStandaloneRepairAuthorizationRemote>(),
    services.GetRequiredService<IStandaloneSoftwareRepairer>()));
builder.Services.AddSingleton<SqliteProductLauncher>();
builder.Services.AddSingleton<ILocalProductLauncher>(services =>
    services.GetRequiredService<SqliteProductLauncher>());
builder.Services.AddSingleton<ISoftwareOpenService>(services => new SoftwareOpenService(
    services.GetRequiredService<ISoftwareCatalogService>(),
    services.GetRequiredService<ILocalProductLauncher>()));
builder.Services.AddSingleton<ISoftwareRemoveService>(services => new SoftwareRemoveService(
    services.GetRequiredService<IAccountSessionService>(),
    services.GetRequiredService<ILocalProductInventory>(),
    services.GetRequiredService<IStandaloneSoftwareRemover>()));
builder.Services.AddSingleton<UnavailableProviders>();

var app = builder.Build();

app.UseMiddleware<NotificationEndpointMiddleware>();

app.Use(async (context, next) =>
{
    context.Response.Headers.CacheControl = "no-store";

    if (!HttpMethods.IsPost(context.Request.Method))
    {
        await next(context);
        return;
    }

    var isInboxRoute = IsNotificationInboxRoute(context.Request.Path);

    if (context.Request.Headers.ContainsKey("Origin"))
    {
        await WriteRequestFailure(context, StatusCodes.Status403Forbidden, "browser_origin_rejected", isInboxRoute);
        return;
    }

    var mediaType = context.Request.ContentType?.Split(';', 2)[0].Trim();
    if (!string.Equals(mediaType, "application/json", StringComparison.OrdinalIgnoreCase))
    {
        await WriteRequestFailure(context, StatusCodes.Status415UnsupportedMediaType, "unsupported_content_type", isInboxRoute);
        return;
    }

    var hasContentLength = context.Request.Headers.ContainsKey("Content-Length");
    var hasTransferEncoding = context.Request.Headers.ContainsKey("Transfer-Encoding");
    if (hasContentLength && hasTransferEncoding)
    {
        await WriteRequestFailure(context, StatusCodes.Status400BadRequest, "ambiguous_request_framing", isInboxRoute);
        return;
    }

    if (hasTransferEncoding)
    {
        var codings = context.Request.Headers.TransferEncoding
            .SelectMany(value => value?.Split(',') ?? Array.Empty<string>())
            .Select(value => value.Trim())
            .Where(value => value.Length > 0)
            .ToArray();
        if (codings.Length != 1 || !string.Equals(codings[0], "chunked", StringComparison.OrdinalIgnoreCase))
        {
            await WriteRequestFailure(context, StatusCodes.Status400BadRequest, "unsupported_transfer_encoding", isInboxRoute);
            return;
        }
    }
    else if (!hasContentLength)
    {
        await WriteRequestFailure(context, StatusCodes.Status411LengthRequired, "content_length_required", isInboxRoute);
        return;
    }

    if (context.Request.ContentLength is < 0)
    {
        await WriteRequestFailure(context, StatusCodes.Status400BadRequest, "invalid_content_length", isInboxRoute);
        return;
    }

    if (context.Request.ContentLength > LocalAgentContract.MaxJsonBodyBytes)
    {
        await WriteRequestFailure(context, StatusCodes.Status413PayloadTooLarge, "payload_too_large", isInboxRoute);
        return;
    }

    await next(context);
});

app.MapGet(LocalAgentContract.LicenseCenterBrowserPath, (HttpRequest request) =>
{
    var productId = request.Query["product_id"].ToString();
    var version = request.Query["version"].ToString();
    var installationId = request.Query["installation_id"].ToString();
    if (!ValidProductContext(productId, version, installationId))
    {
        return Results.Text("missing product context", statusCode: StatusCodes.Status400BadRequest);
    }
    return Results.Content(
        LicenseCenterPage(productId, version, installationId),
        "text/html; charset=utf-8",
        statusCode: StatusCodes.Status200OK);
});

app.MapPost(LocalAgentContract.AuthorizePath, async (
    AuthorizeRequest request,
    IAuthorizationService service,
    CancellationToken cancellationToken) =>
{
    if (!ValidProductContext(request.ProductId, request.Version, request.InstallationId))
    {
        return Results.Json(new { outcome = "failed", reason = "invalid_request" }, statusCode: 400);
    }
    var response = await service.AuthorizeAsync(request, cancellationToken);
    return Results.Json(response, statusCode: 200);
});

app.MapPost(LocalAgentContract.ActivatePath, async (
    ActivateRequest request,
    IActivationService service,
    CancellationToken cancellationToken) =>
{
    if (!ValidProductContext(request.ProductId, request.Version, request.InstallationId) || string.IsNullOrWhiteSpace(request.LicenseKey))
    {
        return Results.Json(new { outcome = "failed", reason = "invalid_request" }, statusCode: 400);
    }
    var response = await service.ActivateAsync(request, cancellationToken);
    return Results.Json(response, statusCode: 200);
});

app.MapPost(LocalAgentContract.OpenLicenseCenterPath, async (
    OpenLicenseCenterRequest request,
    ILicenseCenterService service,
    CancellationToken cancellationToken) =>
{
    if (!ValidProductContext(request.ProductId, request.Version, request.InstallationId) || !ValidCorrelationId(request.CorrelationId))
    {
        return Results.Json(new { authorized = false, reason = "invalid_request" }, statusCode: 400);
    }
    var response = await service.OpenAsync(request, cancellationToken);
    return Results.Json(response, statusCode: 200);
});

app.MapPost(LocalAgentContract.RequestNotificationPath, async (
    TypedNotificationRequest request,
    INotificationService service,
    CancellationToken cancellationToken) =>
{
    if (!ValidProductContext(request.ProductId, request.Version, request.InstallationId) ||
        string.IsNullOrWhiteSpace(request.Code) || request.ProductId.Length > 128 || request.Version.Length > 64 ||
        request.InstallationId.Length > 256 || request.Code.Length > 64)
    {
        return Results.Json(new { outcome = "failed", reason = "invalid_request" }, statusCode: 400);
    }
    var response = await service.RequestAsync(request, cancellationToken);
    return Results.Json(response, statusCode: 200);
});

app.MapPost(LocalAgentContract.NotificationFeedPath, async (
    NotificationFeedRequest request,
    INotificationService service,
    CancellationToken cancellationToken) =>
{
    if (!ValidNotificationContext(request.ProductId, request.Version, request.InstallationId) || request.Limit is < 1 or > 200)
    {
        return NotificationInvalidRequest();
    }
    var response = await service.FeedAsync(request, cancellationToken);
    return Results.Json(response, statusCode: 200);
});

app.MapPost(LocalAgentContract.NotificationMarkReadPath, async (
    NotificationMutationRequest request,
    INotificationService service,
    CancellationToken cancellationToken) =>
{
    if (!ValidNotificationContext(request.ProductId, request.Version, request.InstallationId) ||
        string.IsNullOrWhiteSpace(request.NotificationId) || request.NotificationId.Length > 128)
    {
        return NotificationInvalidRequest();
    }
    var response = await service.MarkReadAsync(request, cancellationToken);
    return Results.Json(response, statusCode: 200);
});

app.MapPost(LocalAgentContract.NotificationDismissPath, async (
    NotificationMutationRequest request,
    INotificationService service,
    CancellationToken cancellationToken) =>
{
    if (!ValidNotificationContext(request.ProductId, request.Version, request.InstallationId) ||
        string.IsNullOrWhiteSpace(request.NotificationId) || request.NotificationId.Length > 128)
    {
        return NotificationInvalidRequest();
    }
    var response = await service.DismissAsync(request, cancellationToken);
    return Results.Json(response, statusCode: 200);
});

app.MapPost(LocalAgentContract.NotificationUnreadCountPath, async (
    NotificationContextRequest request,
    INotificationService service,
    CancellationToken cancellationToken) =>
{
    if (!ValidNotificationContext(request.ProductId, request.Version, request.InstallationId))
    {
        return NotificationInvalidRequest();
    }
    var response = await service.UnreadCountAsync(request, cancellationToken);
    return Results.Json(response, statusCode: 200);
});

app.MapPost(LocalAgentContract.CheckUpdatesPath, async (
    UpdateCheckRequest request,
    IUpdateService service,
    CancellationToken cancellationToken) =>
{
    if (string.IsNullOrWhiteSpace(request.ProductId) || string.IsNullOrWhiteSpace(request.CurrentVersion) ||
        request.ProductId.Length > 128 || request.CurrentVersion.Length > 64 ||
        (request.RequestedVersion is not null && (string.IsNullOrWhiteSpace(request.RequestedVersion) || request.RequestedVersion.Length > 64)))
    {
        return Results.Json(new UpdateCheckResponse(
            LocalAgentContract.UpdateCapabilityId,
            LocalAgentContract.UpdateContractVersion,
            "Failed",
            null,
            new UpdateCapabilityError("InvalidRequest", "Invalid BKE.Updater check request.", false)), statusCode: 400);
    }
    var response = await service.CheckAsync(request, cancellationToken);
    return Results.Json(response, statusCode: 200);
});

app.MapPost(LocalAgentContract.OpenUpdateCenterPath, async (
    OpenUpdateCenterRequest request,
    IUpdateService service,
    CancellationToken cancellationToken) =>
{
    if (string.IsNullOrWhiteSpace(request.ProductId) || string.IsNullOrWhiteSpace(request.Version) || string.IsNullOrWhiteSpace(request.CorrelationId))
    {
        return Results.Json(new { outcome = "failed", reason = "invalid_request" }, statusCode: 400);
    }
    var response = await service.OpenCenterAsync(request, cancellationToken);
    return Results.Json(response, statusCode: 200);
});

app.MapPost(LocalAgentContract.AccountSessionDeviceContextPath, (
    AccountSessionDeviceContextRequest request) =>
{
    if (!ValidAccountSessionCorrelationId(request.CorrelationId))
    {
        return AccountSessionDeviceContextInvalidRequest();
    }

    var identity = MachineIdentityProvider.Calculate();
    return Results.Json(new AccountSessionDeviceContextResponse(
        LocalAgentContract.AccountSessionCapabilityId,
        LocalAgentContract.AccountSessionContractVersion,
        "READY",
        identity.DeviceId,
        Environment.MachineName,
        MachineIdentityProvider.ProtocolPlatform(identity.Platform),
        MachineIdentityProvider.ProtocolArchitecture(identity.Architecture),
        null), statusCode: 200);
});

app.MapPost(LocalAgentContract.AccountSessionCompletePath, async (
    AccountSessionCompleteRequest request,
    IAccountSessionService service,
    CancellationToken cancellationToken) =>
{
    if (!ValidAccountSessionCorrelationId(request.CorrelationId) ||
        string.IsNullOrWhiteSpace(request.HandoffCode) ||
        request.HandoffCode.Length is < 32 or > 256)
    {
        return AccountSessionCompleteInvalidRequest();
    }

    var response = await service.CompleteAsync(request, cancellationToken);
    return Results.Json(response, statusCode: 200);
});

app.MapPost(LocalAgentContract.AccountSessionStartPath, async (
    AccountSessionStartRequest request,
    IAccountSessionService service,
    CancellationToken cancellationToken) =>
{
    if (!ValidAccountSessionCorrelationId(request.CorrelationId))
    {
        return AccountSessionStartInvalidRequest();
    }

    var response = await service.StartAsync(request, cancellationToken);
    return Results.Json(response, statusCode: 200);
});

app.MapPost(LocalAgentContract.AccountSessionStatusPath, async (
    AccountSessionStatusRequest request,
    IAccountSessionService service,
    CancellationToken cancellationToken) =>
{
    if (!ValidAccountSessionCorrelationId(request.CorrelationId))
    {
        return AccountSessionStatusInvalidRequest();
    }

    var response = await service.StatusAsync(request, cancellationToken);
    return Results.Json(response, statusCode: 200);
});

app.MapPost(LocalAgentContract.AccountSessionLogoutPath, async (
    AccountSessionLogoutRequest request,
    IAccountSessionService service,
    CancellationToken cancellationToken) =>
{
    if (!ValidAccountSessionCorrelationId(request.CorrelationId))
    {
        return AccountSessionLogoutInvalidRequest();
    }

    var response = await service.LogoutAsync(request, cancellationToken);
    return Results.Json(response, statusCode: 200);
});

app.MapPost(LocalAgentContract.ClaimCodeRedeemPath, async (
    ClaimCodeRedeemRequest request,
    IClaimCodeRedemptionService service,
    CancellationToken cancellationToken) =>
{
    if (!ValidAccountSessionCorrelationId(request.CorrelationId) ||
        !ValidClaimCode(request.Code))
    {
        return ClaimCodeRedeemInvalidRequest();
    }

    var response = await service.RedeemAsync(request, cancellationToken);
    return Results.Json(response, statusCode: 200);
});

app.MapPost(LocalAgentContract.StoreCatalogPath, async (
    StoreCatalogRequest request,
    IStoreCatalogService service,
    CancellationToken cancellationToken) =>
{
    if (!ValidAccountSessionCorrelationId(request.CorrelationId))
    {
        return StoreCatalogInvalidRequest();
    }

    var response = await service.GetAsync(request, cancellationToken);
    return Results.Json(response, statusCode: 200);
});

app.MapPost(LocalAgentContract.StoreCheckoutReviewPath, async (
    StoreCheckoutReviewRequest request,
    IStoreCheckoutReviewService service,
    CancellationToken cancellationToken) =>
{
    if (!ValidAccountSessionCorrelationId(request.CorrelationId) ||
        !ValidPurchasePlanId(request.PurchasePlanId))
    {
        return StoreCheckoutReviewInvalidRequest();
    }

    var response = await service.ReviewAsync(request, cancellationToken);
    return Results.Json(response, statusCode: 200);
});

app.MapPost(LocalAgentContract.StoreCheckoutStartPath, async (
    StoreCheckoutStartRequest request,
    IStoreCheckoutStartService service,
    CancellationToken cancellationToken) =>
{
    if (!ValidAccountSessionCorrelationId(request.CorrelationId) ||
        !ValidPurchasePlanId(request.PurchasePlanId) ||
        request.PurchaseMode is not ("SELF" or "GIFT") ||
        !ValidLegalVersionIds(request.LegalVersionIds))
    {
        return StoreCheckoutStartInvalidRequest(
            request.CorrelationId ?? string.Empty);
    }

    var response = await service.StartAsync(request, cancellationToken);
    return Results.Json(response, statusCode: 200);
});

app.MapPost(LocalAgentContract.StoreCheckoutStatusPath, async (
    StoreCheckoutStatusRequest request,
    IStoreCheckoutStatusService service,
    CancellationToken cancellationToken) =>
{
    if (!ValidAccountSessionCorrelationId(request.CorrelationId))
    {
        return StoreCheckoutStatusInvalidRequest(
            request.CorrelationId ?? string.Empty);
    }

    var response = await service.CheckAsync(request, cancellationToken);
    return Results.Json(response, statusCode: 200);
});

app.MapPost(LocalAgentContract.SoftwareCatalogPath, async (
    SoftwareCatalogRequest request,
    ISoftwareCatalogService service,
    CancellationToken cancellationToken) =>
{
    if (!ValidAccountSessionCorrelationId(request.CorrelationId))
    {
        return SoftwareCatalogInvalidRequest();
    }

    var response = await service.GetAsync(request, cancellationToken);
    return Results.Json(response, statusCode: 200);
});

app.MapPost(LocalAgentContract.SoftwareInstallPath, async (
    SoftwareInstallRequest request,
    ISoftwareInstallService service,
    CancellationToken cancellationToken) =>
{
    if (!ValidAccountSessionCorrelationId(request.CorrelationId) ||
        !ValidSoftwareProductId(request.ProductId))
    {
        return SoftwareInstallInvalidRequest();
    }

    var response = await service.InstallAsync(request, cancellationToken);
    return Results.Json(response, statusCode: 200);
});

app.MapPost(LocalAgentContract.SoftwareUpdatePath, async (
    SoftwareUpdateRequest request,
    ISoftwareUpdateService service,
    CancellationToken cancellationToken) =>
{
    if (!ValidAccountSessionCorrelationId(request.CorrelationId) ||
        !ValidSoftwareProductId(request.ProductId))
    {
        return SoftwareUpdateInvalidRequest();
    }

    var response = await service.UpdateAsync(request, cancellationToken);
    return Results.Json(response, statusCode: 200);
});

app.MapPost(LocalAgentContract.SoftwareRepairPath, async (
    SoftwareRepairRequest request,
    ISoftwareRepairService service,
    CancellationToken cancellationToken) =>
{
    if (!ValidAccountSessionCorrelationId(request.CorrelationId) ||
        !ValidSoftwareProductId(request.ProductId))
    {
        return SoftwareRepairInvalidRequest();
    }

    var response = await service.RepairAsync(request, cancellationToken);
    return Results.Json(response, statusCode: 200);
});

app.MapPost(LocalAgentContract.SoftwareOpenPath, async (
    SoftwareOpenRequest request,
    ISoftwareOpenService service,
    CancellationToken cancellationToken) =>
{
    if (!ValidAccountSessionCorrelationId(request.CorrelationId) ||
        !ValidSoftwareProductId(request.ProductId))
    {
        return SoftwareOpenInvalidRequest();
    }

    var response = await service.OpenAsync(request, cancellationToken);
    return Results.Json(response, statusCode: 200);
});

app.MapPost(LocalAgentContract.SoftwareRemovePath, async (
    SoftwareRemoveRequest request,
    ISoftwareRemoveService service,
    CancellationToken cancellationToken) =>
{
    if (!ValidAccountSessionCorrelationId(request.CorrelationId) ||
        !ValidSoftwareProductId(request.ProductId))
    {
        return SoftwareRemoveInvalidRequest();
    }

    var response = await service.RemoveAsync(request, cancellationToken);
    return Results.Json(response, statusCode: 200);
});

await app.RunAsync();
return 0;

static bool ValidProductContext(string? productId, string? version, string? installationId) =>
    !string.IsNullOrWhiteSpace(productId) && !string.IsNullOrWhiteSpace(version) && !string.IsNullOrWhiteSpace(installationId);

static bool ValidCorrelationId(string? correlationId) =>
    !string.IsNullOrWhiteSpace(correlationId) && correlationId.All(character => character >= 32);

static bool ValidAccountSessionCorrelationId(string? correlationId) =>
    ValidCorrelationId(correlationId) && correlationId!.Length <= 128;

static bool ValidClaimCode(string? code)
{
    if (string.IsNullOrWhiteSpace(code))
    {
        return false;
    }

    var value = code.Trim();
    if (!value.StartsWith("BKE-CLM-", StringComparison.OrdinalIgnoreCase) ||
        value.Length != 43)
    {
        return false;
    }

    var body = value[8..];
    var groups = body.Split('-');
    return groups.Length == 6 &&
        groups.All(group =>
            group.Length == 5 &&
            group.All(character =>
                character is >= '0' and <= '9' ||
                character is >= 'A' and <= 'F' ||
                character is >= 'a' and <= 'f'));
}

static bool ValidPurchasePlanId(string? purchasePlanId) =>
    !string.IsNullOrWhiteSpace(purchasePlanId) &&
    purchasePlanId.Length <= 256 &&
    purchasePlanId.All(character => character >= 32);

static bool ValidLegalVersionIds(IReadOnlyList<string>? legalVersionIds) =>
    legalVersionIds is { Count: >= 2 and <= 3 } &&
    legalVersionIds.All(value =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length <= 256 &&
        value.All(character => character >= 32)) &&
    legalVersionIds.Distinct(StringComparer.Ordinal).Count() ==
        legalVersionIds.Count;

static bool ValidSoftwareProductId(string? productId) =>
    !string.IsNullOrWhiteSpace(productId) &&
    productId.Length <= 128 &&
    productId.All(character =>
        character is >= 'a' and <= 'z' ||
        character is >= '0' and <= '9' ||
        character == '-');

static bool ValidNotificationContext(string? productId, string? version, string? installationId) =>
    ValidProductContext(productId, version, installationId) &&
    productId!.Length <= 128 && version!.Length <= 64 && installationId!.Length <= 256;

static string LicenseCenterPage(string productId, string version, string installationId)
{
    var safeProductId = System.Net.WebUtility.HtmlEncode(productId);
    var safeVersion = System.Net.WebUtility.HtmlEncode(version);
    var contextJson = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, string>
    {
        ["product_id"] = productId,
        ["version"] = version,
        ["installation_id"] = installationId,
    });
    var template = """
        <!doctype html><html><head><meta charset='utf-8'><title>BKE License Center</title>
        <style>body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;max-width:560px;margin:48px auto;padding:24px}input,button{font-size:16px;padding:10px;width:100%;box-sizing:border-box;margin:6px 0}#status{white-space:pre-wrap}</style></head><body>
        <h1>BKE License Center</h1><p>Activate <strong>__BKE_PRODUCT_ID__</strong> version __BKE_VERSION__ on this device.</p>
        <label>License key</label><input id='key' type='password' autocomplete='off' autofocus><button id='activate'>Activate License</button><p id='status'>Waiting for license key.</p>
        <script>const context=__BKE_CONTEXT__;document.getElementById('activate').onclick=async()=>{const b=document.getElementById('activate'),s=document.getElementById('status'),k=document.getElementById('key');b.disabled=true;s.textContent='Activating…';try{const r=await fetch('/v1/activate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({...context,license_key:k.value})});const d=await r.json();s.textContent=d.authorized?'Activation successful. Return to the product and refresh authorization.':('Activation failed: '+(d.reason||'denied'));if(d.authorized)k.value='';}catch(e){s.textContent='Activation failed: Agent unavailable';}finally{b.disabled=false;}};</script></body></html>
        """;
    return template
        .Replace("__BKE_PRODUCT_ID__", safeProductId, StringComparison.Ordinal)
        .Replace("__BKE_VERSION__", safeVersion, StringComparison.Ordinal)
        .Replace("__BKE_CONTEXT__", contextJson, StringComparison.Ordinal);
}

static IResult AccountSessionDeviceContextInvalidRequest() =>
    Results.Json(new AccountSessionDeviceContextResponse(
        LocalAgentContract.AccountSessionCapabilityId,
        LocalAgentContract.AccountSessionContractVersion,
        "FAILED",
        null,
        null,
        null,
        null,
        new AccountSessionError("INVALID_REQUEST", "The account-session device-context request is invalid.", false)),
        statusCode: StatusCodes.Status400BadRequest);

static IResult AccountSessionCompleteInvalidRequest() =>
    Results.Json(new AccountSessionCompleteResponse(
        LocalAgentContract.AccountSessionCapabilityId,
        LocalAgentContract.AccountSessionContractVersion,
        "FAILED",
        null,
        new AccountSessionError("INVALID_REQUEST", "The account-session completion request is invalid.", false)),
        statusCode: StatusCodes.Status400BadRequest);

static IResult AccountSessionStartInvalidRequest() =>
    Results.Json(new AccountSessionStartResponse(
        LocalAgentContract.AccountSessionCapabilityId,
        LocalAgentContract.AccountSessionContractVersion,
        "FAILED",
        null,
        null,
        null,
        new AccountSessionError("INVALID_REQUEST", "The account-session request is invalid.", false)),
        statusCode: StatusCodes.Status400BadRequest);

static IResult AccountSessionStatusInvalidRequest() =>
    Results.Json(new AccountSessionStatusResponse(
        LocalAgentContract.AccountSessionCapabilityId,
        LocalAgentContract.AccountSessionContractVersion,
        "FAILED",
        null,
        new AccountSessionError("INVALID_REQUEST", "The account-session request is invalid.", false)),
        statusCode: StatusCodes.Status400BadRequest);

static IResult AccountSessionLogoutInvalidRequest() =>
    Results.Json(new AccountSessionLogoutResponse(
        LocalAgentContract.AccountSessionCapabilityId,
        LocalAgentContract.AccountSessionContractVersion,
        "FAILED",
        new AccountSessionError("INVALID_REQUEST", "The account-session request is invalid.", false)),
        statusCode: StatusCodes.Status400BadRequest);

static IResult ClaimCodeRedeemInvalidRequest() =>
    Results.Json(new ClaimCodeRedeemResponse(
        LocalAgentContract.ClaimCodeRedemptionCapabilityId,
        LocalAgentContract.ClaimCodeRedemptionContractVersion,
        "FAILED",
        null,
        null,
        new ClaimCodeRedeemError(
            "INVALID_REQUEST",
            "The Claim Code redemption request is invalid.",
            false)),
        statusCode: StatusCodes.Status400BadRequest);

static IResult StoreCatalogInvalidRequest() =>
    Results.Json(new StoreCatalogResponse(
        LocalAgentContract.StoreCatalogCapabilityId,
        LocalAgentContract.StoreCatalogContractVersion,
        "FAILED",
        false,
        Array.Empty<StoreCatalogProduct>(),
        new StoreCatalogError(
            "INVALID_REQUEST",
            "The Store catalog request is invalid.",
            false)),
        statusCode: StatusCodes.Status400BadRequest);

static IResult StoreCheckoutReviewInvalidRequest() =>
    Results.Json(new StoreCheckoutReviewResponse(
        LocalAgentContract.StoreCheckoutReviewCapabilityId,
        LocalAgentContract.StoreCheckoutReviewContractVersion,
        "FAILED",
        Array.Empty<string>(),
        null,
        null,
        null,
        Array.Empty<StoreCheckoutReviewLegalDocument>(),
        Array.Empty<StoreCheckoutReviewPendingLegalDocument>(),
        new StoreCheckoutReviewError(
            "INVALID_REQUEST",
            "The Store checkout-review request is invalid.",
            false)),
        statusCode: StatusCodes.Status400BadRequest);

static IResult StoreCheckoutStartInvalidRequest(string correlationId) =>
    Results.Json(new StoreCheckoutStartResponse(
        LocalAgentContract.StoreCheckoutStartCapabilityId,
        LocalAgentContract.StoreCheckoutStartContractVersion,
        "FAILED",
        correlationId,
        null,
        null,
        null,
        new StoreCheckoutStartError(
            "INVALID_REQUEST",
            "The Store checkout-start request is invalid.",
            false)),
        statusCode: StatusCodes.Status400BadRequest);

static IResult StoreCheckoutStatusInvalidRequest(string correlationId) =>
    Results.Json(new StoreCheckoutStatusResponse(
        LocalAgentContract.StoreCheckoutStatusCapabilityId,
        LocalAgentContract.StoreCheckoutStatusContractVersion,
        "FAILED",
        correlationId,
        null,
        null,
        null,
        null,
        null,
        null,
        null,
        new StoreCheckoutStatusError(
            "INVALID_REQUEST",
            "The Store checkout-status request is invalid.",
            false)),
        statusCode: StatusCodes.Status400BadRequest);

static IResult SoftwareCatalogInvalidRequest() =>
    Results.Json(new SoftwareCatalogResponse(
        LocalAgentContract.SoftwareCatalogCapabilityId,
        LocalAgentContract.SoftwareCatalogContractVersion,
        "FAILED",
        Array.Empty<SoftwareCatalogItem>(),
        new SoftwareCatalogError(
            "INVALID_REQUEST",
            "The software catalog request is invalid.",
            false)),
        statusCode: StatusCodes.Status400BadRequest);

static IResult SoftwareInstallInvalidRequest() =>
    Results.Json(new SoftwareInstallResponse(
        LocalAgentContract.SoftwareInstallCapabilityId,
        LocalAgentContract.SoftwareInstallContractVersion,
        "FAILED",
        "invalid_request",
        new SoftwareInstallError(
            "INVALID_REQUEST",
            "The software install request is invalid.",
            false)),
        statusCode: StatusCodes.Status400BadRequest);

static IResult SoftwareUpdateInvalidRequest() =>
    Results.Json(new SoftwareUpdateResponse(
        LocalAgentContract.SoftwareUpdateCapabilityId,
        LocalAgentContract.SoftwareUpdateContractVersion,
        "FAILED",
        "invalid_request",
        new SoftwareUpdateError(
            "INVALID_REQUEST",
            "The software update request is invalid.",
            false)),
        statusCode: StatusCodes.Status400BadRequest);

static IResult SoftwareRepairInvalidRequest() =>
    Results.Json(new SoftwareRepairResponse(
        LocalAgentContract.SoftwareRepairCapabilityId,
        LocalAgentContract.SoftwareRepairContractVersion,
        "FAILED",
        "invalid_request",
        new SoftwareRepairError(
            "INVALID_REQUEST",
            "The software Repair request is invalid.",
            false)),
        statusCode: StatusCodes.Status400BadRequest);

static IResult SoftwareOpenInvalidRequest() =>
    Results.Json(new SoftwareOpenResponse(
        LocalAgentContract.SoftwareOpenCapabilityId,
        LocalAgentContract.SoftwareOpenContractVersion,
        "FAILED",
        "invalid_request",
        new SoftwareOpenError(
            "INVALID_REQUEST",
            "The software open request is invalid.",
            false)),
        statusCode: StatusCodes.Status400BadRequest);

static IResult SoftwareRemoveInvalidRequest() =>
    Results.Json(new SoftwareRemoveResponse(
        LocalAgentContract.SoftwareRemoveCapabilityId,
        LocalAgentContract.SoftwareRemoveContractVersion,
        "FAILED",
        "invalid_request",
        new SoftwareRemoveError(
            "INVALID_REQUEST",
            "The software remove request is invalid.",
            false)),
        statusCode: StatusCodes.Status400BadRequest);

static IResult NotificationInvalidRequest() =>
    Results.Json(new NotificationMutationResponse(
        LocalAgentContract.NotificationInboxCapabilityId,
        LocalAgentContract.NotificationInboxContractVersion,
        "Failed",
        new NotificationCapabilityError("InvalidRequest", "The notification request is invalid.", false)), statusCode: 400);

static bool IsNotificationInboxRoute(PathString path) =>
    path == LocalAgentContract.NotificationFeedPath ||
    path == LocalAgentContract.NotificationMarkReadPath ||
    path == LocalAgentContract.NotificationDismissPath ||
    path == LocalAgentContract.NotificationUnreadCountPath;

static async Task WriteRequestFailure(HttpContext context, int statusCode, string reason, bool inboxRoute)
{
    context.Response.StatusCode = statusCode;
    context.Response.ContentType = "application/json";
    if (inboxRoute)
    {
        await context.Response.WriteAsJsonAsync(new NotificationMutationResponse(
            LocalAgentContract.NotificationInboxCapabilityId,
            LocalAgentContract.NotificationInboxContractVersion,
            "Failed",
            new NotificationCapabilityError(RequestFailureCode(reason), RequestFailureMessage(reason), false)));
        return;
    }

    await context.Response.WriteAsJsonAsync(new { outcome = "failed", reason });
}

static string RequestFailureCode(string reason) => reason switch
{
    "browser_origin_rejected" => "BrowserOriginRejected",
    "unsupported_content_type" => "UnsupportedContentType",
    "payload_too_large" => "PayloadTooLarge",
    _ => "InvalidRequest",
};

static string RequestFailureMessage(string reason) => reason.Replace('_', ' ');
