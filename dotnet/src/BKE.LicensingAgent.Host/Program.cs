using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;
using BKE.LicensingAgent.Host;
using BKE.LicensingAgent.Infrastructure;

if (Environment.GetEnvironmentVariable("BKE_AGENT_VNEXT_ENABLE") != "1")
{
    Console.Error.WriteLine(
        "BKE Licensing Agent .NET 10 Gen2 is migration-only. Python remains canonical. " +
        "Set BKE_AGENT_VNEXT_ENABLE=1 only for isolated development/certification.");
    return 78;
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
builder.Services.AddSingleton<IUpdateService, Gen2UpdateService>();
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

await app.RunAsync();
return 0;

static bool ValidProductContext(string? productId, string? version, string? installationId) =>
    !string.IsNullOrWhiteSpace(productId) && !string.IsNullOrWhiteSpace(version) && !string.IsNullOrWhiteSpace(installationId);

static bool ValidCorrelationId(string? correlationId) =>
    !string.IsNullOrWhiteSpace(correlationId) && correlationId.All(character => character >= 32);

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
