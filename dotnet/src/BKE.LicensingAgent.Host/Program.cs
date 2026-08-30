using System.Net;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;
using BKE.LicensingAgent.Host;

if (!string.Equals(
        Environment.GetEnvironmentVariable("BKE_AGENT_VNEXT_ENABLE"),
        "1",
        StringComparison.Ordinal))
{
    Console.Error.WriteLine(
        "BKE Licensing Agent .NET 10 vNext is not promoted. " +
        "Generation 1 Python remains canonical. Set BKE_AGENT_VNEXT_ENABLE=1 only for controlled migration tests.");
    Environment.ExitCode = 78;
    return;
}

var port = LocalAgentContract.DefaultPort;
var configuredPort = Environment.GetEnvironmentVariable("BKE_AGENT_PORT");
if (!string.IsNullOrWhiteSpace(configuredPort))
{
    if (!int.TryParse(configuredPort, out port) || port is < 1 or > 65535)
    {
        Console.Error.WriteLine("BKE_AGENT_PORT must be an integer from 1 through 65535.");
        Environment.ExitCode = 78;
        return;
    }
}

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.MaxRequestBodySize = LocalAgentContract.MaxJsonBodyBytes;
    options.Listen(IPAddress.Loopback, port);
});

builder.Services.AddSingleton<ILicensingAgentRuntime, UnavailableLicensingAgentRuntime>();

var app = builder.Build();

app.Use(async (context, next) =>
{
    context.Response.Headers["Cache-Control"] = "no-store";

    if (HttpMethods.IsPost(context.Request.Method) && context.Request.Headers.ContainsKey("Origin"))
    {
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        await context.Response.WriteAsJsonAsync(
            new Dictionary<string, object>
            {
                ["outcome"] = "failed",
                ["reason"] = "browser_origin_rejected",
            },
            cancellationToken: context.RequestAborted);
        return;
    }

    await next();
});

app.MapGet(LocalAgentContract.LicenseCenterBrowserPath, () =>
    Results.Text(
        "The .NET 10 License Center UI has not been migrated. Generation 1 Python remains canonical.",
        "text/plain",
        statusCode: StatusCodes.Status503ServiceUnavailable));

app.MapPost(
    LocalAgentContract.AuthorizePath,
    (AuthorizeRequest request, ILicensingAgentRuntime runtime, CancellationToken cancellationToken) =>
        runtime.AuthorizeAsync(request, cancellationToken));

app.MapPost(
    LocalAgentContract.ActivatePath,
    (ActivateRequest request, ILicensingAgentRuntime runtime, CancellationToken cancellationToken) =>
        runtime.ActivateAsync(request, cancellationToken));

app.MapPost(
    LocalAgentContract.OpenLicenseCenterPath,
    (OpenLicenseCenterRequest request, ILicensingAgentRuntime runtime, CancellationToken cancellationToken) =>
        runtime.OpenLicenseCenterAsync(request, cancellationToken));

app.MapPost(
    LocalAgentContract.CheckUpdatesPath,
    (UpdateCheckRequest request, ILicensingAgentRuntime runtime, CancellationToken cancellationToken) =>
        runtime.CheckUpdatesAsync(request, cancellationToken));

app.MapPost(
    LocalAgentContract.OpenUpdateCenterPath,
    (OpenUpdateCenterRequest request, ILicensingAgentRuntime runtime, CancellationToken cancellationToken) =>
        runtime.OpenUpdateCenterAsync(request, cancellationToken));

await app.RunAsync();
