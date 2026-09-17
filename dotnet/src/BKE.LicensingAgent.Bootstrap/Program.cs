using BKE.LicensingAgent.Bootstrap;

// Certification-only seam for proving an installed legacy Python Agent can hand off
// to the guarded .NET Gen2 runtime without weakening the canonical production path.
// The marker lives under Program Files and is emitted only by the bridge candidate
// installer. Production cutover removes the Gen2 guard instead of shipping this marker.
var bridgeCertificationMarker = Path.Combine(RuntimeBridgeContract.InstallRoot, "bridge-cert.enable");
if (File.Exists(bridgeCertificationMarker))
{
    Environment.SetEnvironmentVariable("BKE_AGENT_BOOTSTRAP_ALLOW_GEN2", "1");
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
