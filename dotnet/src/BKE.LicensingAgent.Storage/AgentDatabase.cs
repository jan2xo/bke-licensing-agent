using Microsoft.Data.Sqlite;

namespace BKE.LicensingAgent.Storage;

public sealed record DiscoveredProductRegistration(
    string ProductId,
    string DisplayName,
    string Version,
    string ManifestPath,
    string ProductRoot,
    string EntryPointPath,
    DateTimeOffset DiscoveredAt,
    string InstallProvenance = "LEGACY_UNKNOWN",
    string UninstallStrategy = "NONE",
    string? UninstallExecutable = null,
    string? UninstallArgumentsJson = null);

public static class AgentDatabase
{
    public const int CurrentSchemaVersion = 10;

    private static readonly IReadOnlyDictionary<int, string[]> Migrations =
        new Dictionary<int, string[]>
        {
            [1] =
            [
                """
                CREATE TABLE IF NOT EXISTS discovered_products (
                    product_id TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    version TEXT NOT NULL,
                    manifest_path TEXT NOT NULL,
                    product_root TEXT NOT NULL,
                    entry_point_path TEXT NOT NULL,
                    discovered_at TEXT NOT NULL,
                    PRIMARY KEY (manifest_path)
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS activation_cache (
                    product_id TEXT NOT NULL, license_id TEXT NOT NULL, device_id TEXT NOT NULL,
                    activation_id TEXT NOT NULL, status TEXT NOT NULL, updated_at TEXT NOT NULL,
                    PRIMARY KEY (product_id, device_id)
                )
                """,
            ],
            [2] =
            [
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, event_type TEXT NOT NULL,
                    product_id TEXT, device_id TEXT, activation_id TEXT,
                    result TEXT NOT NULL, created_at TEXT NOT NULL
                )
                """,
            ],
            [3] =
            [
                """
                CREATE TABLE IF NOT EXISTS lease_metadata (
                    lease_id TEXT PRIMARY KEY,
                    product_id TEXT NOT NULL,
                    installation_id TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    issuer TEXT NOT NULL,
                    issued_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    last_verified_at TEXT NOT NULL
                )
                """,
            ],
            [4] =
            [
                "ALTER TABLE lease_metadata ADD COLUMN server_revision INTEGER NOT NULL DEFAULT 0",
            ],
            [5] =
            [
                """
                CREATE TABLE IF NOT EXISTS verified_licenses (
                    license_id TEXT PRIMARY KEY,
                    product_id TEXT NOT NULL,
                    product_version TEXT NOT NULL,
                    installation_id TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    lease_id TEXT NOT NULL UNIQUE,
                    generation INTEGER NOT NULL,
                    server_revision INTEGER NOT NULL,
                    issued_at TEXT NOT NULL,
                    not_before TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS active_license_bindings (
                    product_id TEXT NOT NULL,
                    installation_id TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    active_license_id TEXT NOT NULL,
                    active_lease_id TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    server_revision INTEGER NOT NULL,
                    binding_version INTEGER NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (product_id, installation_id, device_id),
                    FOREIGN KEY (active_license_id) REFERENCES verified_licenses(license_id)
                )
                """,
            ],
            [6] =
            [
                """
                CREATE TABLE verified_licenses_v6 (
                    license_id TEXT NOT NULL,
                    product_id TEXT NOT NULL,
                    product_version TEXT NOT NULL,
                    installation_id TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    lease_id TEXT PRIMARY KEY,
                    generation INTEGER NOT NULL,
                    server_revision INTEGER NOT NULL,
                    issued_at TEXT NOT NULL,
                    not_before TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """,
                """
                INSERT INTO verified_licenses_v6 SELECT license_id, product_id, product_version,
                installation_id, device_id, lease_id, generation, server_revision, issued_at,
                not_before, expires_at, status, key_id, created_at, updated_at
                FROM verified_licenses
                """,
                "ALTER TABLE active_license_bindings RENAME TO active_license_bindings_v6",
                """
                CREATE TABLE active_license_bindings (
                    product_id TEXT NOT NULL,
                    installation_id TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    active_license_id TEXT NOT NULL,
                    active_lease_id TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    server_revision INTEGER NOT NULL,
                    binding_version INTEGER NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (product_id, installation_id, device_id)
                )
                """,
                "INSERT INTO active_license_bindings SELECT * FROM active_license_bindings_v6",
                "DROP TABLE active_license_bindings_v6",
                "DROP TABLE verified_licenses",
                "ALTER TABLE verified_licenses_v6 RENAME TO verified_licenses",
            ],
            [7] =
            [
                """
                CREATE TABLE verified_licenses_v7 (
                    license_id TEXT NOT NULL,
                    product_id TEXT NOT NULL,
                    product_version TEXT NOT NULL,
                    installation_id TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    lease_id TEXT PRIMARY KEY,
                    generation INTEGER NOT NULL,
                    server_revision INTEGER NOT NULL,
                    issued_at TEXT NOT NULL,
                    not_before TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    signed_payload TEXT,
                    signed_signature TEXT,
                    signed_algorithm TEXT
                )
                """,
                """
                INSERT INTO verified_licenses_v7
                SELECT license_id, product_id, product_version, installation_id, device_id,
                lease_id, generation, server_revision, issued_at, not_before, expires_at,
                status, key_id, created_at, updated_at, NULL, NULL, NULL
                FROM verified_licenses
                """,
                "DROP TABLE verified_licenses",
                "ALTER TABLE verified_licenses_v7 RENAME TO verified_licenses",
            ],
            [8] =
            [
                """
                CREATE TABLE IF NOT EXISTS notifications (
                    id TEXT PRIMARY KEY,
                    product_id TEXT NOT NULL,
                    code TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    state TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    dismissed_at TEXT,
                    UNIQUE(product_id, code)
                )
                """,
                """
                CREATE INDEX IF NOT EXISTS idx_notifications_product_state_created
                ON notifications(product_id, state, created_at DESC)
                """,
            ],
            [9] =
            [
                """
                CREATE TABLE notifications_v9 (
                    id TEXT PRIMARY KEY,
                    product_id TEXT NOT NULL,
                    code TEXT NOT NULL,
                    source TEXT,
                    title TEXT,
                    body TEXT,
                    category TEXT,
                    severity TEXT NOT NULL,
                    state TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    dismissed_at TEXT
                )
                """,
                """
                INSERT INTO notifications_v9 (
                    id, product_id, code, source, title, body, category,
                    severity, state, created_at, expires_at, dismissed_at
                )
                SELECT
                    id, product_id, code, NULL, NULL, NULL, NULL,
                    severity, state, created_at, expires_at, dismissed_at
                FROM notifications
                """,
                "DROP TABLE notifications",
                "ALTER TABLE notifications_v9 RENAME TO notifications",
                """
                CREATE INDEX idx_notifications_product_state_created
                ON notifications(product_id, state, created_at DESC)
                """,
                """
                CREATE INDEX idx_notifications_product_code
                ON notifications(product_id, code)
                """,
            ],
            [10] =
            [
                """
                ALTER TABLE discovered_products
                ADD COLUMN install_provenance TEXT NOT NULL DEFAULT 'LEGACY_UNKNOWN'
                CHECK (install_provenance IN ('LEGACY_UNKNOWN', 'BKE_MANAGED_PACKAGE', 'PRODUCT_INSTALLER'))
                """,
                """
                ALTER TABLE discovered_products
                ADD COLUMN uninstall_strategy TEXT NOT NULL DEFAULT 'NONE'
                CHECK (uninstall_strategy IN ('NONE', 'MANAGED_DIRECTORY', 'INSTALLER_EXECUTABLE'))
                """,
                "ALTER TABLE discovered_products ADD COLUMN uninstall_executable TEXT",
                "ALTER TABLE discovered_products ADD COLUMN uninstall_arguments_json TEXT",
            ],
        };

    public static string DatabasePath(string dataDirectory) =>
        Path.Combine(Path.GetFullPath(dataDirectory), "agent.db");

    public static void EnsureInitialized(string dataDirectory)
    {
        if (string.IsNullOrWhiteSpace(dataDirectory))
        {
            throw new ArgumentException("Agent data directory is required.", nameof(dataDirectory));
        }

        var root = Path.GetFullPath(dataDirectory);
        Directory.CreateDirectory(root);
        var databasePath = DatabasePath(root);

        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Private,
        }.ToString());
        connection.Open();

        using var transaction = connection.BeginTransaction();
        try
        {
            Execute(connection, transaction,
                "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)");

            using (var count = connection.CreateCommand())
            {
                count.Transaction = transaction;
                count.CommandText = "SELECT COUNT(*) FROM schema_version";
                var rows = Convert.ToInt64(count.ExecuteScalar());
                if (rows == 0)
                {
                    Execute(connection, transaction,
                        "INSERT INTO schema_version (version) VALUES (0)");
                }
                else if (rows != 1)
                {
                    throw new InvalidDataException(
                        "Agent schema_version must contain exactly one row.");
                }
            }

            int version;
            using (var read = connection.CreateCommand())
            {
                read.Transaction = transaction;
                read.CommandText = "SELECT version FROM schema_version LIMIT 1";
                version = Convert.ToInt32(read.ExecuteScalar());
            }

            if (version < 0 || version > CurrentSchemaVersion)
            {
                throw new InvalidDataException(
                    $"Agent database schema {version} is unsupported.");
            }

            for (var target = version + 1; target <= CurrentSchemaVersion; target++)
            {
                foreach (var statement in Migrations[target])
                {
                    Execute(connection, transaction, statement);
                }

                using var update = connection.CreateCommand();
                update.Transaction = transaction;
                update.CommandText =
                    "UPDATE schema_version SET version = $version";
                update.Parameters.AddWithValue("$version", target);
                if (update.ExecuteNonQuery() != 1)
                {
                    throw new InvalidDataException(
                        "Agent schema version update failed.");
                }
            }

            transaction.Commit();
        }
        catch
        {
            transaction.Rollback();
            throw;
        }
    }

    public static void RegisterDiscoveredProduct(
        string dataDirectory,
        DiscoveredProductRegistration registration)
    {
        ArgumentNullException.ThrowIfNull(registration);
        EnsureInitialized(dataDirectory);

        var productId = Required(registration.ProductId, nameof(registration.ProductId));
        var displayName = Required(registration.DisplayName, nameof(registration.DisplayName));
        var version = Required(registration.Version, nameof(registration.Version));
        var manifestPath = Path.GetFullPath(
            Required(registration.ManifestPath, nameof(registration.ManifestPath)));
        var productRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(
            Required(registration.ProductRoot, nameof(registration.ProductRoot))));
        var entryPointPath = Path.GetFullPath(
            Required(registration.EntryPointPath, nameof(registration.EntryPointPath)));
        var installProvenance = Required(registration.InstallProvenance, nameof(registration.InstallProvenance));
        var uninstallStrategy = Required(registration.UninstallStrategy, nameof(registration.UninstallStrategy));
        if (installProvenance is not ("LEGACY_UNKNOWN" or "BKE_MANAGED_PACKAGE" or "PRODUCT_INSTALLER"))
        {
            throw new InvalidDataException("Discovered product install provenance is unsupported.");
        }
        if (uninstallStrategy is not ("NONE" or "MANAGED_DIRECTORY" or "INSTALLER_EXECUTABLE"))
        {
            throw new InvalidDataException("Discovered product uninstall strategy is unsupported.");
        }
        if (uninstallStrategy == "MANAGED_DIRECTORY" && installProvenance != "BKE_MANAGED_PACKAGE")
        {
            throw new InvalidDataException("Managed-directory removal requires BKE-managed installation provenance.");
        }
        if (uninstallStrategy == "INSTALLER_EXECUTABLE")
        {
            if (installProvenance != "PRODUCT_INSTALLER" ||
                string.IsNullOrWhiteSpace(registration.UninstallExecutable) ||
                string.IsNullOrWhiteSpace(registration.UninstallArgumentsJson))
            {
                throw new InvalidDataException("Installer uninstall strategy requires trusted installer provenance and metadata.");
            }

            var uninstallRelative = registration.UninstallExecutable
                .Replace('/', Path.DirectorySeparatorChar)
                .Replace('\\', Path.DirectorySeparatorChar);
            if (Path.IsPathRooted(uninstallRelative) ||
                uninstallRelative.Split(Path.DirectorySeparatorChar)
                    .Any(part => part is "" or "." or ".."))
            {
                throw new InvalidDataException("Installer uninstall executable must be a safe relative path.");
            }

            using var arguments = System.Text.Json.JsonDocument.Parse(registration.UninstallArgumentsJson);
            if (arguments.RootElement.ValueKind != System.Text.Json.JsonValueKind.Array ||
                arguments.RootElement.GetArrayLength() > 32 ||
                arguments.RootElement.EnumerateArray().Any(item =>
                    item.ValueKind != System.Text.Json.JsonValueKind.String ||
                    item.GetString() is not { Length: <= 1024 }))
            {
                throw new InvalidDataException("Installer uninstall arguments are invalid.");
            }
        }
        else if (registration.UninstallExecutable is not null ||
                 registration.UninstallArgumentsJson is not null)
        {
            throw new InvalidDataException("Uninstall command metadata is only valid for installer-executable strategy.");
        }

        if (!Path.IsPathFullyQualified(manifestPath) ||
            !Path.IsPathFullyQualified(productRoot) ||
            !Path.IsPathFullyQualified(entryPointPath))
        {
            throw new InvalidDataException(
                "Discovered product paths must be fully qualified.");
        }

        if (!PathUnder(productRoot, manifestPath) ||
            !PathUnder(productRoot, entryPointPath) ||
            !File.Exists(manifestPath) ||
            !File.Exists(entryPointPath))
        {
            throw new InvalidDataException(
                "Discovered product paths are unavailable or escape the product root.");
        }

        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = DatabasePath(dataDirectory),
            Mode = SqliteOpenMode.ReadWrite,
            Cache = SqliteCacheMode.Private,
        }.ToString());
        connection.Open();

        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT OR REPLACE INTO discovered_products (
                product_id,
                display_name,
                version,
                manifest_path,
                product_root,
                entry_point_path,
                discovered_at,
                install_provenance,
                uninstall_strategy,
                uninstall_executable,
                uninstall_arguments_json
            ) VALUES (
                $product_id,
                $display_name,
                $version,
                $manifest_path,
                $product_root,
                $entry_point_path,
                $discovered_at,
                $install_provenance,
                $uninstall_strategy,
                $uninstall_executable,
                $uninstall_arguments_json
            )
            """;
        command.Parameters.AddWithValue("$product_id", productId);
        command.Parameters.AddWithValue("$display_name", displayName);
        command.Parameters.AddWithValue("$version", version);
        command.Parameters.AddWithValue("$manifest_path", manifestPath);
        command.Parameters.AddWithValue("$product_root", productRoot);
        command.Parameters.AddWithValue("$entry_point_path", entryPointPath);
        command.Parameters.AddWithValue(
            "$discovered_at",
            registration.DiscoveredAt.ToUniversalTime().ToString("O"));
        command.Parameters.AddWithValue("$install_provenance", installProvenance);
        command.Parameters.AddWithValue("$uninstall_strategy", uninstallStrategy);
        command.Parameters.AddWithValue(
            "$uninstall_executable",
            (object?)registration.UninstallExecutable ?? DBNull.Value);
        command.Parameters.AddWithValue(
            "$uninstall_arguments_json",
            (object?)registration.UninstallArgumentsJson ?? DBNull.Value);

        if (command.ExecuteNonQuery() != 1)
        {
            throw new InvalidDataException(
                "Discovered product registration failed.");
        }

        transaction.Commit();
    }

    private static void Execute(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string statement)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = statement;
        command.ExecuteNonQuery();
    }

    private static string Required(string? value, string name)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidDataException($"{name} is required.");
        }

        return value;
    }

    private static bool PathUnder(string root, string child)
    {
        var normalizedRoot =
            Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        var normalizedChild = Path.GetFullPath(child);

        return string.Equals(
                   normalizedRoot,
                   normalizedChild,
                   StringComparison.OrdinalIgnoreCase) ||
               normalizedChild.StartsWith(
                   normalizedRoot + Path.DirectorySeparatorChar,
                   StringComparison.OrdinalIgnoreCase);
    }
}
