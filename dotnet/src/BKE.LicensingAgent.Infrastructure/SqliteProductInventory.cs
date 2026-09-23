using BKE.LicensingAgent.Application;
using Microsoft.Data.Sqlite;

namespace BKE.LicensingAgent.Infrastructure;

public sealed class SqliteProductInventory : ILocalProductInventory
{
    private readonly string _databasePath;

    public SqliteProductInventory(string? dataDirectory = null)
    {
        var dataDir = dataDirectory ??
            Environment.GetEnvironmentVariable("BKE_AGENT_DATA_DIR") ??
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                ".local",
                "share",
                "bke_licensing_agent");

        _databasePath = Path.Combine(dataDir, "agent.db");
    }

    public Task<IReadOnlyDictionary<string, LocalInstalledProduct>> ReadAsync(
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!File.Exists(_databasePath))
        {
            return Task.FromResult<IReadOnlyDictionary<string, LocalInstalledProduct>>(
                new Dictionary<string, LocalInstalledProduct>(StringComparer.Ordinal));
        }

        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = _databasePath,
            Mode = SqliteOpenMode.ReadOnly,
            Cache = SqliteCacheMode.Private,
        }.ToString());
        connection.Open();

        using var schema = connection.CreateCommand();
        schema.CommandText = "SELECT version FROM schema_version LIMIT 1";
        var schemaVersion = Convert.ToInt32(schema.ExecuteScalar());
        if (schemaVersion != BKE.LicensingAgent.Contracts.LocalAgentContract.StorageSchemaVersion)
        {
            throw new InvalidDataException("Local product inventory schema is unsupported.");
        }

        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT product_id, version, entry_point_path,
                   install_provenance, uninstall_strategy,
                   uninstall_executable, uninstall_arguments_json
            FROM discovered_products
            ORDER BY discovered_at DESC
            """;

        using var reader = command.ExecuteReader();
        var result = new Dictionary<string, LocalInstalledProduct>(StringComparer.Ordinal);

        while (reader.Read())
        {
            cancellationToken.ThrowIfCancellationRequested();

            var productId = reader.GetString(0);
            var version = reader.GetString(1);
            var entryPointPath = reader.GetString(2);
            var installProvenance = reader.GetString(3);
            var uninstallStrategy = reader.GetString(4);
            var uninstallExecutable = reader.IsDBNull(5) ? null : reader.GetString(5);
            var uninstallArgumentsJson = reader.IsDBNull(6) ? null : reader.GetString(6);
            IReadOnlyList<string> uninstallArguments = Array.Empty<string>();
            if (uninstallArgumentsJson is not null)
            {
                try
                {
                    uninstallArguments =
                        System.Text.Json.JsonSerializer.Deserialize<string[]>(uninstallArgumentsJson)
                        ?? Array.Empty<string>();
                }
                catch
                {
                    installProvenance = "LEGACY_UNKNOWN";
                    uninstallStrategy = "NONE";
                    uninstallExecutable = null;
                    uninstallArguments = Array.Empty<string>();
                }
            }

            if (result.ContainsKey(productId) ||
                string.IsNullOrWhiteSpace(productId) ||
                string.IsNullOrWhiteSpace(version) ||
                string.IsNullOrWhiteSpace(entryPointPath) ||
                !File.Exists(entryPointPath))
            {
                continue;
            }

            result[productId] = new LocalInstalledProduct(
                productId,
                version,
                installProvenance,
                uninstallStrategy,
                uninstallExecutable,
                uninstallArguments);
        }

        return Task.FromResult<IReadOnlyDictionary<string, LocalInstalledProduct>>(result);
    }
}
