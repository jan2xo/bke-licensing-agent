using BKE.LicensingAgent.Infrastructure;

namespace BKE.LicensingAgent.RootCleanup;

internal static class Program
{
    private const string RemoveManagedProducts = "--remove-managed-products";
    private const string Smoke = "--smoke";

    public static async Task<int> Main(string[] args)
    {
        try
        {
            if (!OperatingSystem.IsWindows())
            {
                throw new PlatformNotSupportedException(
                    "BKE root cleanup is supported only on Windows.");
            }

            if (args.Length == 1 &&
                string.Equals(args[0], Smoke, StringComparison.Ordinal))
            {
                Console.WriteLine("BKE root cleanup smoke: PASS");
                return 0;
            }

            if (args.Length != 1 ||
                !string.Equals(
                    args[0],
                    RemoveManagedProducts,
                    StringComparison.Ordinal))
            {
                Console.Error.WriteLine(
                    "Usage: bke-root-cleanup.exe --remove-managed-products");
                return 64;
            }

            var dataRoot = Path.Combine(
                Environment.GetFolderPath(
                    Environment.SpecialFolder.CommonApplicationData),
                "BKE Digital Solutions",
                "Licensing Agent");

            Environment.SetEnvironmentVariable(
                "BKE_AGENT_DATA_DIR",
                dataRoot,
                EnvironmentVariableTarget.Process);

            var inventory = new SqliteProductInventory(dataRoot);
            var installed = await inventory.ReadAsync(
                CancellationToken.None);

            if (installed.Count == 0)
            {
                Console.WriteLine("BKE root cleanup: no managed products installed.");
                return 0;
            }

            var remover = new PrivilegedUpdateCenterProvider();

            foreach (var product in installed.Values
                         .OrderBy(
                             item => item.ProductId,
                             StringComparer.Ordinal))
            {
                if (product.InstallProvenance == "LEGACY_UNKNOWN" ||
                    product.UninstallStrategy == "NONE")
                {
                    Console.Error.WriteLine(
                        $"BKE root cleanup refused unknown uninstall authority for {product.ProductId}.");
                    return 20;
                }

                var result = await remover.RemoveAsync(
                    product,
                    CancellationToken.None);

                if (result.Status is not ("REMOVED" or "NOT_INSTALLED"))
                {
                    Console.Error.WriteLine(
                        $"BKE root cleanup failed for {product.ProductId}: {result.Status}/{result.Reason}");
                    return 21;
                }

                Console.WriteLine(
                    $"BKE root cleanup removed {product.ProductId}: {result.Status}/{result.Reason}");
            }

            var remaining = await inventory.ReadAsync(
                CancellationToken.None);
            if (remaining.Count != 0)
            {
                Console.Error.WriteLine(
                    "BKE root cleanup verification failed: managed products remain.");
                return 22;
            }

            Console.WriteLine(
                "BKE root cleanup: all managed products removed.");
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(
                $"BKE root cleanup failed: {exception.Message}");
            return 1;
        }
    }
}
