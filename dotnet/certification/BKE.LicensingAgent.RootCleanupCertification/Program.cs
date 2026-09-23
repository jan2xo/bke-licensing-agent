using System.Text.Json;
using BKE.LicensingAgent.Storage;

namespace BKE.LicensingAgent.RootCleanupCertification;

internal static class Program
{
    public static int Main(string[] args)
    {
        try
        {
            if (!OperatingSystem.IsWindows())
            {
                throw new PlatformNotSupportedException(
                    "Root cleanup certification is Windows-only.");
            }

            if (args.Length != 1 ||
                args[0] != "--seed-managed-product")
            {
                throw new InvalidDataException(
                    "Usage: --seed-managed-product");
            }

            var programFiles = Environment.GetFolderPath(
                Environment.SpecialFolder.ProgramFiles);
            var programData = Environment.GetFolderPath(
                Environment.SpecialFolder.CommonApplicationData);

            var productRoot = Path.Combine(
                programFiles,
                "BKE Digital Solutions",
                "Certification Product");
            var manifestPath = Path.Combine(
                productRoot,
                "bke.manifest.json");
            var entryPointPath = Path.Combine(
                productRoot,
                "product.exe");
            var dataRoot = Path.Combine(
                programData,
                "BKE Digital Solutions",
                "Licensing Agent");

            Directory.CreateDirectory(productRoot);
            File.WriteAllBytes(
                entryPointPath,
                [0x42, 0x4B, 0x45]);

            var manifest = new
            {
                schemaVersion = 1,
                productId = "bke-certification-product",
                displayName = "BKE Certification Product",
                publisher = "BKE Digital Solutions",
                version = "1.0.0",
                entryPoint = "product.exe",
                icon = "product.exe",
                updateChannel = "stable",
                minimumAgentVersion = "2.0.0",
                platform = "windows",
                architecture = "x64",
            };
            File.WriteAllText(
                manifestPath,
                JsonSerializer.Serialize(
                    manifest,
                    new JsonSerializerOptions
                    {
                        WriteIndented = true,
                    }));

            AgentDatabase.RegisterDiscoveredProduct(
                dataRoot,
                new DiscoveredProductRegistration(
                    "bke-certification-product",
                    "BKE Certification Product",
                    "1.0.0",
                    manifestPath,
                    productRoot,
                    entryPointPath,
                    DateTimeOffset.UtcNow,
                    "BKE_MANAGED_PACKAGE",
                    "MANAGED_DIRECTORY",
                    null,
                    null));

            Console.WriteLine(
                $"Seeded managed certification product: {productRoot}");
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(
                $"Root cleanup certification seed failed: {exception.Message}");
            return 1;
        }
    }
}
