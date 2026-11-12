using BKE.LicensingAgent.Application;
using Microsoft.Data.Sqlite;

namespace BKE.LicensingAgent.Infrastructure;

/// <summary>
/// Durable, fail-closed startup grant ledger under the administrator-owned
/// Program Files Agent root. The UNIQUE process identity rejects replay even
/// after the Host process restarts; no user-writable Agent cache grants access.
/// </summary>
public sealed class InstalledStandaloneStartupGrantAudit : IStandaloneStartupAudit
{
    private readonly string _databasePath;
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    private InstalledStandaloneStartupGrantAudit(string databasePath) =>
        _databasePath = databasePath;

    public static InstalledStandaloneStartupGrantAudit CreateInstalled(string environment)
    {
        if (environment is not ("development" or "certification" or "utm") ||
            !OperatingSystem.IsWindows())
            throw new InvalidOperationException("Startup audit is PREPRODUCTION Windows-only.");

        var programFiles = Environment.GetFolderPath(
            Environment.SpecialFolder.ProgramFiles);
        if (string.IsNullOrWhiteSpace(programFiles))
            throw new InvalidDataException("Installed startup audit root unavailable.");
        var root = Path.GetFullPath(Path.Combine(
            programFiles, "BKE Digital Solutions", "Licensing Agent"));
        var runtime = Path.GetFullPath(Path.Combine(root, "runtime"));
        if (!string.Equals(
                Path.TrimEndingDirectorySeparator(Path.GetFullPath(AppContext.BaseDirectory)),
                Path.TrimEndingDirectorySeparator(runtime),
                StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Startup audit cannot run from a noninstalled Host.");

        foreach (var dir in new[] { root, runtime })
        {
            var info = new DirectoryInfo(dir);
            if (!info.Exists || (info.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Installed audit parent is redirected.");
        }

        var auditDir = Path.Combine(root, "startup-grant-audit");
        Directory.CreateDirectory(auditDir);
        var installed = new DirectoryInfo(auditDir);
        if ((installed.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("Installed audit directory is redirected.");
        var database = Path.Combine(auditDir, "grants.db");
        var file = new FileInfo(database);
        if (file.Exists && (file.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("Installed audit database is redirected.");
        return new InstalledStandaloneStartupGrantAudit(database);
    }

    // The contract fixture uses a disposable path and verifies persistent
    // duplicate rejection; Host cannot inject this alternate constructor.
    internal static InstalledStandaloneStartupGrantAudit ForCertification(
        string databasePath) => new(databasePath);

    public async Task<bool> CommitGrantAsync(
        TrustedStandaloneStartupInstallation installation,
        StandaloneStartupProcessEvidence peer,
        string credential,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (credential is not ("ACCOUNT" or "LICENSE_KEY") ||
            string.IsNullOrEmpty(installation.ProductId) ||
            peer.ProcessId < 1 || peer.StartedUtcTicks < 1 ||
            !peer.WindowsKernelObserved)
            return false;

        await _writeLock.WaitAsync(cancellationToken);
        try
        {
            var file = new FileInfo(_databasePath);
            if (file.Exists && (file.Attributes & FileAttributes.ReparsePoint) != 0)
                return false;

            using var connection = new SqliteConnection(new SqliteConnectionStringBuilder {
                DataSource = _databasePath,
                Mode = SqliteOpenMode.ReadWriteCreate,
                Cache = SqliteCacheMode.Private,
                Pooling = false
            }.ToString());
            connection.Open();

            using (var configure = connection.CreateCommand())
            {
                configure.CommandText = "PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;";
                configure.ExecuteNonQuery();
            }
            using (var schema = connection.CreateCommand())
            {
                schema.CommandText = """
                    CREATE TABLE IF NOT EXISTS startup_grants (
                        pid INTEGER NOT NULL,
                        started_utc_ticks INTEGER NOT NULL,
                        user_sid TEXT NOT NULL,
                        product_id TEXT NOT NULL,
                        version TEXT NOT NULL,
                        installation_id TEXT NOT NULL,
                        image_sha256 TEXT NOT NULL,
                        credential TEXT NOT NULL,
                        granted_at TEXT NOT NULL,
                        PRIMARY KEY (pid, started_utc_ticks, user_sid)
                    )
                    """;
                schema.ExecuteNonQuery();
            }

            using var transaction = connection.BeginTransaction();
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                INSERT INTO startup_grants (
                    pid, started_utc_ticks, user_sid, product_id, version,
                    installation_id, image_sha256, credential, granted_at
                ) VALUES ($pid, $started, $sid, $product, $version,
                          $install, $sha, $credential, $now)
                ON CONFLICT(pid, started_utc_ticks, user_sid) DO NOTHING
                """;
            command.Parameters.AddWithValue("$pid", peer.ProcessId);
            command.Parameters.AddWithValue("$started", peer.StartedUtcTicks);
            command.Parameters.AddWithValue("$sid", peer.UserSid);
            command.Parameters.AddWithValue("$product", installation.ProductId);
            command.Parameters.AddWithValue("$version", installation.Version);
            command.Parameters.AddWithValue("$install", installation.InstallationId);
            command.Parameters.AddWithValue("$sha", installation.ImageSha256);
            command.Parameters.AddWithValue("$credential", credential);
            command.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));
            var inserted = command.ExecuteNonQuery();
            if (inserted != 1)
                return false;
            transaction.Commit();
            return true;
        }
        catch (SqliteException)
        {
            return false;
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
        finally
        {
            _writeLock.Release();
        }
    }
}
