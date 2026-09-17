namespace BKE.LicensingAgent.Bootstrap;

internal static class RuntimeBridgeContract
{
    internal const string WindowsServiceName = "BKE-Licensing-Agent";
    internal const string AgentProductId = "bke-licensing-agent";
    internal const string CatalogRepository = "jan2xo/bke-software-catalog";
    internal const int DefaultPort = 43873;

    internal static string InstallRoot =>
        Directory.GetParent(Path.GetFullPath(AppContext.BaseDirectory))?.FullName
        ?? throw new InvalidOperationException("Bootstrap install root is unavailable");

    internal static string RuntimeExecutable =>
        Environment.GetEnvironmentVariable("BKE_AGENT_RUNTIME_EXECUTABLE")
        ?? Path.Combine(InstallRoot, "runtime", "bke-licensing-agent-runtime.exe");

    internal static string LicenseCenterExecutable =>
        Environment.GetEnvironmentVariable("BKE_LICENSE_CENTER_EXECUTABLE")
        ?? Path.Combine(InstallRoot, "license-center", "bke-license-center.exe");

    internal static string DataRoot =>
        Environment.GetEnvironmentVariable("BKE_AGENT_DATA_DIR")
        ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "BKE Digital Solutions", "Licensing Agent");
}
