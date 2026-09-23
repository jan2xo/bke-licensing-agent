using System.Text.Json;
using BKE.LicensingAgent.Storage;
using Microsoft.Data.Sqlite;

namespace BKE.LicensingAgent.RootCleanupCertification;

internal static class Program
{
    private const string ManagedProductId = "bke-certification-product";
    private const string LegacyProductId = "bke-certification-legacy";

    public static int Main(string[] args)
    {
        try
        {
            if (!OperatingSystem.IsWindows())
            {
                throw new PlatformNotSupportedException(
                    "Root cleanup certification is Windows-only.");
            }

            if (args.Length == 1 && args[0] == "--seed-managed-product")
            {
                SeedProduct(
                    ManagedProductId,
                    "BKE Certification Product",
                    "Certification Product",
                    "BKE_MANAGED_PACKAGE",
                    "MANAGED_DIRECTORY");
                return 0;
            }

            if (args.Length == 1 && args[0] == "--seed-legacy-product")
            {
                SeedProduct(
                    LegacyProductId,
                    "BKE Certification Legacy Product",
                    "Certification Legacy Product",
                    "LEGACY_UNKNOWN",
                    "NONE");
                return 0;
            }

            if (args.Length == 2 && args[0] == "--assert-product-absent")
            {
                AssertInventory(args[1], expectedPresent: false);
                return 0;
            }

            if (args.Length == 2 && args[0] == "--assert-product-present")
            {
                AssertInventory(args[1], expectedPresent: true);
                return 0;
            }

            throw new InvalidDataException(
                "Usage: --seed-managed-product | --seed-legacy-product | " +
                "--assert-product-absent <product-id> | --assert-product-present <product-id>");
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(
                $"Root cleanup certification failed: {exception.Message}");
            return 1;
        }
    }

    private static void SeedProduct(
        string productId,
        string displayName,
        string directoryName,
        string installProvenance,
        string uninstallStrategy)
    {
        var programFiles = Environment.GetFolderPath(
            Environment.SpecialFolder.ProgramFiles);
        var programData = Environment.GetFolderPath(
            Environment.SpecialFolder.CommonApplicationData);

        var productRoot = Path.Combine(
            programFiles,
            "BKE Digital Solutions",
            directoryName);
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

        if (Directory.Exists(productRoot))
        {
            Directory.Delete(productRoot, recursive: true);
        }

        Directory.CreateDirectory(productRoot);
        File.WriteAllBytes(
            entryPointPath,
            [0x42, 0x4B, 0x45]);

        var manifest = new
        {
            schemaVersion = 1,
            productId,
            displayName,
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
                productId,
                displayName,
                "1.0.0",
                manifestPath,
                productRoot,
                entryPointPath,
                DateTimeOffset.UtcNow,
                installProvenance,
                uninstallStrategy,
                null,
                null));

        AssertInventory(productId, expectedPresent: true);

        Console.WriteLine(
            $"Seeded root-cleanup certification product: {productId} -> {productRoot}");
    }

    private static void AssertInventory(
        string productId,
        bool expectedPresent)
    {
        var dataRoot = Path.Combine(
            Environment.GetFolderPath(
                Environment.SpecialFolder.CommonApplicationData),
            "BKE Digital Solutions",
            "Licensing Agent");
        var databasePath = Path.Combine(dataRoot, "agent.db");

        if (!File.Exists(databasePath))
        {
            if (!expectedPresent)
            {
                Console.WriteLine(
                    $"Inventory assertion PASS: {productId} absent.");
                return;
            }

            throw new InvalidDataException(
                $"Agent database is missing while asserting {productId}.");
        }

        using var connection = new SqliteConnection(
            new SqliteConnectionStringBuilder
            {
                DataSource = databasePath,
                Mode = SqliteOpenMode.ReadOnly,
                Cache = SqliteCacheMode.Private,
            }.ToString());
        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT COUNT(*)
            FROM discovered_products
            WHERE product_id = $product_id
            """;
        command.Parameters.AddWithValue(
            "$product_id",
            productId);

        var count = Convert.ToInt32(command.ExecuteScalar());
        var present = count > 0;
        if (present != expectedPresent)
        {
            throw new InvalidDataException(
                $"Inventory assertion failed for {productId}: present={present}, expected={expectedPresent}.");
        }

        Console.WriteLine(
            $"Inventory assertion PASS: {productId} present={present}.");
    }
}
