using System.ComponentModel;
using System.Diagnostics;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;
using Microsoft.Data.Sqlite;

namespace BKE.LicensingAgent.Infrastructure;

public sealed class SqliteProductLauncher : ILocalProductLauncher
{
    private readonly string _databasePath;

    public SqliteProductLauncher(string? dataDirectory = null)
    {
        var dataDir = dataDirectory ??
            Environment.GetEnvironmentVariable("BKE_AGENT_DATA_DIR") ??
            Path.Combine(
                Environment.GetFolderPath(
                    Environment.SpecialFolder.UserProfile),
                ".local",
                "share",
                "bke_licensing_agent");

        _databasePath = Path.Combine(dataDir, "agent.db");
    }

    public Task<LocalProductLaunchResult> OpenAsync(
        string productId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult(new LocalProductLaunchResult(
                "UNSUPPORTED_PLATFORM",
                "unsupported_platform",
                false));
        }

        if (!File.Exists(_databasePath))
        {
            return Task.FromResult(new LocalProductLaunchResult(
                "NOT_INSTALLED",
                "not_installed",
                false));
        }

        try
        {
            using var connection =
                new SqliteConnection(
                    new SqliteConnectionStringBuilder
                    {
                        DataSource = _databasePath,
                        Mode = SqliteOpenMode.ReadOnly,
                        Cache = SqliteCacheMode.Private,
                    }.ToString());
            connection.Open();

            using var schema = connection.CreateCommand();
            schema.CommandText =
                "SELECT version FROM schema_version LIMIT 1";
            var schemaVersion =
                Convert.ToInt32(schema.ExecuteScalar());
            if (schemaVersion !=
                LocalAgentContract.StorageSchemaVersion)
            {
                return Task.FromResult(
                    new LocalProductLaunchResult(
                        "LAUNCH_FAILED",
                        "unsupported_local_schema",
                        false));
            }

            using var command = connection.CreateCommand();
            command.CommandText = """
                SELECT product_root, entry_point_path
                FROM discovered_products
                WHERE product_id=$product_id
                ORDER BY discovered_at DESC
                """;
            command.Parameters.AddWithValue(
                "$product_id",
                productId);

            using var reader = command.ExecuteReader();
            var sawUntrustedLocation = false;
            var sawMissingEntryPoint = false;

            while (reader.Read())
            {
                cancellationToken.ThrowIfCancellationRequested();

                var productRoot =
                    Path.GetFullPath(reader.GetString(0));
                var entryPoint =
                    Path.GetFullPath(reader.GetString(1));

                if (!TrustedProductRoot(productRoot))
                {
                    sawUntrustedLocation = true;
                    continue;
                }

                if (!PathUnder(productRoot, entryPoint))
                {
                    sawUntrustedLocation = true;
                    continue;
                }

                if (!Directory.Exists(productRoot) ||
                    !File.Exists(entryPoint))
                {
                    sawMissingEntryPoint = true;
                    continue;
                }

                try
                {
                    var process = Process.Start(
                        new ProcessStartInfo
                        {
                            FileName = entryPoint,
                            WorkingDirectory = productRoot,
                            UseShellExecute = true,
                        });

                    if (process is null)
                    {
                        return Task.FromResult(
                            new LocalProductLaunchResult(
                                "LAUNCH_FAILED",
                                "launch_failed",
                                true));
                    }

                    process.Dispose();
                    return Task.FromResult(
                        new LocalProductLaunchResult(
                            "STARTED",
                            "started",
                            false));
                }
                catch (Win32Exception)
                {
                    return Task.FromResult(
                        new LocalProductLaunchResult(
                            "LAUNCH_FAILED",
                            "launch_failed",
                            true));
                }
            }

            if (sawUntrustedLocation)
            {
                return Task.FromResult(
                    new LocalProductLaunchResult(
                        "UNTRUSTED_INSTALL_LOCATION",
                        "untrusted_install_location",
                        false));
            }

            if (sawMissingEntryPoint)
            {
                return Task.FromResult(
                    new LocalProductLaunchResult(
                        "ENTRY_POINT_UNAVAILABLE",
                        "entry_point_unavailable",
                        true));
            }

            return Task.FromResult(
                new LocalProductLaunchResult(
                    "NOT_INSTALLED",
                    "not_installed",
                    false));
        }
        catch (SqliteException)
        {
            return Task.FromResult(
                new LocalProductLaunchResult(
                    "LAUNCH_FAILED",
                    "local_inventory_unavailable",
                    true));
        }
    }

    private static bool TrustedProductRoot(string productRoot)
    {
        var programFiles =
            Environment.GetFolderPath(
                Environment.SpecialFolder.ProgramFiles);
        if (string.IsNullOrWhiteSpace(programFiles))
        {
            return false;
        }

        var approved = Path.GetFullPath(
            Path.Combine(
                programFiles,
                "BKE Digital Solutions"));

        return PathUnder(approved, productRoot);
    }

    private static bool PathUnder(
        string root,
        string child)
    {
        var normalizedRoot =
            Path.TrimEndingDirectorySeparator(
                Path.GetFullPath(root));
        var normalizedChild =
            Path.GetFullPath(child);

        if (string.Equals(
                normalizedRoot,
                normalizedChild,
                StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return normalizedChild.StartsWith(
            normalizedRoot +
            Path.DirectorySeparatorChar,
            StringComparison.OrdinalIgnoreCase);
    }
}
