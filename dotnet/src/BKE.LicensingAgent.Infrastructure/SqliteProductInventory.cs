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
        if (schemaVersion != Contracts.LocalAgentContract.StorageSchemaVersion)
        {
            throw new InvalidDataException("Local product inventory schema is unsupported.");
        }

        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT product_id, version, entry_point_path
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

            if (result.ContainsKey(productId) ||
                string.IsNullOrWhiteSpace(productId) ||
                string.IsNullOrWhiteSpace(version) ||
                string.IsNullOrWhiteSpace(entryPointPath) ||
                !File.Exists(entryPointPath))
            {
                continue;
            }

            result[productId] = new LocalInstalledProduct(productId, version);
        }

        return Task.FromResult<IReadOnlyDictionary<string, LocalInstalledProduct>>(result);
    }
}
