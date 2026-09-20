using BKE.LicensingAgent.Bootstrap;

// The runtime bridge is canonical on this production-installer candidate branch.
// The certification marker remains only to suppress external self-update polling
// while isolated bridge tests run; production packaging deletes it before startup.
var bridgeCertificationMarker = Path.Combine(RuntimeBridgeContract.InstallRoot, "bridge-cert.enable");
if (File.Exists(bridgeCertificationMarker))
{
    Environment.SetEnvironmentVariable("BKE_AGENT_SELF_UPDATE_DISABLE", "1");
}

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options =>
{
    options.ServiceName = RuntimeBridgeContract.WindowsServiceName;
});
builder.Services.AddHostedService<AgentRuntimeSupervisor>();
builder.Services.AddHostedService<AgentSelfUpdateWorker>();

await builder.Build().RunAsync();
