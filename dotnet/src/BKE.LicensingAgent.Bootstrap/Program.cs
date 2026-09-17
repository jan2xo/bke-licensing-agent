using BKE.LicensingAgent.Bootstrap;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options =>
{
    options.ServiceName = RuntimeBridgeContract.WindowsServiceName;
});
builder.Services.AddHostedService<AgentRuntimeSupervisor>();
builder.Services.AddHostedService<AgentSelfUpdateWorker>();

await builder.Build().RunAsync();
