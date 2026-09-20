using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;
using Microsoft.Data.Sqlite;

namespace BKE.LicensingAgent.Infrastructure;

public sealed class LicenseCenterProvider : ILicenseCenterService
{
    private const string LicenseRequiredCode = "LICENSE_REQUIRED";
    private const string LicenseRequiredSeverity = "warning";
    private readonly AuthorizationProvider _authorization;
    private readonly string _dataDir;

    public LicenseCenterProvider(AuthorizationProvider authorization)
    {
        _authorization = authorization;
        _dataDir = Environment.GetEnvironmentVariable("BKE_AGENT_DATA_DIR")
            ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "share", "bke_licensing_agent");
    }

    public async Task<OpenLicenseCenterResponse> OpenAsync(
        OpenLicenseCenterRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var context = await _authorization.AuthorizeAsync(
            new AuthorizeRequest(request.ProductId, request.Version, request.InstallationId),
            cancellationToken);

        if (context.Reason == "unknown_product_or_version")
        {
            return Result("invalid_product_context", "invalid product context", request.CorrelationId);
        }

        string? notificationCode = null;
        if (context.Reason == "activation_required")
        {
            try
            {
                EnsureLicenseRequiredNotification(request.ProductId);
                notificationCode = LicenseRequiredCode;
            }
            catch
            {
                return Result("failed", "License Center invocation failed", request.CorrelationId);
            }
        }

        var executable = ResolveExecutablePath();
        if (!File.Exists(executable))
        {
            return Result("agent_unavailable", "native License Center is not installed", request.CorrelationId);
        }

        var arguments = BuildArguments(request, notificationCode);
        try
        {
            var exitCode = OperatingSystem.IsWindows()
                ? await Task.Run(() => RunWindowsInteractive(executable, arguments, cancellationToken), cancellationToken)
                : await RunPortableAsync(executable, arguments, cancellationToken);

            return exitCode switch
            {
                0 => Result("authorization_refreshed", "", request.CorrelationId, authorizationChanged: true),
                2 => Result("cancelled", "", request.CorrelationId),
                3 => Result("activation_failed", "", request.CorrelationId),
                _ => Result("failed", "native License Center failed", request.CorrelationId),
            };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return Result("failed", "native License Center could not be started", request.CorrelationId);
        }
    }

    private void EnsureLicenseRequiredNotification(string productId)
    {
        var databasePath = Path.Combine(_dataDir, "agent.db");
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadWrite,
            Cache = SqliteCacheMode.Private,
        }.ToString());
        connection.Open();

        using var transaction = connection.BeginTransaction();
        string? existingId;
        using (var select = connection.CreateCommand())
        {
            select.Transaction = transaction;
            select.CommandText = "SELECT id FROM notifications WHERE product_id=$product_id AND code=$code";
            select.Parameters.AddWithValue("$product_id", productId);
            select.Parameters.AddWithValue("$code", LicenseRequiredCode);
            existingId = select.ExecuteScalar() as string;
        }

        if (existingId is null)
        {
            using var insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = """
                INSERT INTO notifications
                    (id, product_id, code, severity, state, created_at, expires_at, dismissed_at)
                VALUES
                    ($id, $product_id, $code, $severity, 'unread', $created_at, NULL, NULL)
                """;
            insert.Parameters.AddWithValue("$id", NotificationId(productId, LicenseRequiredCode));
            insert.Parameters.AddWithValue("$product_id", productId);
            insert.Parameters.AddWithValue("$code", LicenseRequiredCode);
            insert.Parameters.AddWithValue("$severity", LicenseRequiredSeverity);
            insert.Parameters.AddWithValue("$created_at", DateTimeOffset.UtcNow.ToString("O"));
            insert.ExecuteNonQuery();
        }
        else
        {
            using var update = connection.CreateCommand();
            update.Transaction = transaction;
            update.CommandText = """
                UPDATE notifications
                SET severity=$severity, expires_at=NULL
                WHERE product_id=$product_id AND code=$code
                """;
            update.Parameters.AddWithValue("$severity", LicenseRequiredSeverity);
            update.Parameters.AddWithValue("$product_id", productId);
            update.Parameters.AddWithValue("$code", LicenseRequiredCode);
            update.ExecuteNonQuery();
        }

        transaction.Commit();
    }

    private static string NotificationId(string productId, string code)
    {
        var namespaceBytes = Convert.FromHexString("6ba7b8119dad11d180b400c04fd430c8");
        var nameBytes = Encoding.UTF8.GetBytes($"bke-notification:{productId}:{code}");
        var data = new byte[namespaceBytes.Length + nameBytes.Length];
        Buffer.BlockCopy(namespaceBytes, 0, data, 0, namespaceBytes.Length);
        Buffer.BlockCopy(nameBytes, 0, data, namespaceBytes.Length, nameBytes.Length);
        var hash = SHA1.HashData(data);
        hash[6] = (byte)((hash[6] & 0x0f) | 0x50);
        hash[8] = (byte)((hash[8] & 0x3f) | 0x80);
        var hex = Convert.ToHexString(hash.AsSpan(0, 16)).ToLowerInvariant();
        return $"{hex[..8]}-{hex[8..12]}-{hex[12..16]}-{hex[16..20]}-{hex[20..32]}";
    }

    private static IReadOnlyList<string> BuildArguments(OpenLicenseCenterRequest request, string? notificationCode)
    {
        var arguments = new List<string>
        {
            "--product-id", request.ProductId,
            "--product-version", request.Version,
            "--installation-id", request.InstallationId,
            "--correlation-id", request.CorrelationId,
            "--action", "activation_required",
        };
        if (!string.IsNullOrWhiteSpace(notificationCode))
        {
            arguments.Add("--notification-code");
            arguments.Add(notificationCode);
        }
        return arguments;
    }

    private static string ResolveExecutablePath()
    {
        var configured = Environment.GetEnvironmentVariable("BKE_LICENSE_CENTER_EXECUTABLE");
        if (!string.IsNullOrWhiteSpace(configured))
        {
            return Path.GetFullPath(configured);
        }

        var name = OperatingSystem.IsWindows() ? "bke-license-center.exe" : "bke-license-center";
        var agentDirectory = Path.GetFullPath(AppContext.BaseDirectory);
        var parent = Directory.GetParent(agentDirectory)?.FullName;
        var candidates = new List<string>
        {
            Path.Combine(agentDirectory, name),
        };
        if (parent is not null)
        {
            if (OperatingSystem.IsWindows())
            {
                candidates.Add(Path.Combine(parent, "license-center", name));
            }
            candidates.Add(Path.Combine(parent, "bke-license-center", name));
        }
        return candidates.FirstOrDefault(File.Exists) ?? candidates[0];
    }

    private static async Task<int> RunPortableAsync(
        string executable,
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = executable,
            WorkingDirectory = Path.GetDirectoryName(Path.GetFullPath(executable))!,
            UseShellExecute = false,
        };
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Could not start native License Center");
        await process.WaitForExitAsync(cancellationToken);
        return process.ExitCode;
    }

    private static int RunWindowsInteractive(
        string executable,
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var sessionId = WindowsNative.WTSGetActiveConsoleSessionId();
        if (sessionId == uint.MaxValue)
        {
            throw new Win32Exception("No active Windows console session is available for License Center");
        }

        IntPtr token = IntPtr.Zero;
        IntPtr environment = IntPtr.Zero;
        var processInfo = new WindowsNative.PROCESS_INFORMATION();
        var environmentCreated = false;
        try
        {
            if (!WindowsNative.WTSQueryUserToken(sessionId, out token))
            {
                throw LastWindowsError("Could not obtain the active Windows user token");
            }
            if (!WindowsNative.CreateEnvironmentBlock(out environment, token, false))
            {
                throw LastWindowsError("Could not build the active Windows user environment");
            }
            environmentCreated = true;

            var startupInfo = new WindowsNative.STARTUPINFO
            {
                cb = Marshal.SizeOf<WindowsNative.STARTUPINFO>(),
                lpDesktop = "winsta0\\default",
            };
            var command = new StringBuilder(QuoteWindowsArgument(executable));
            foreach (var argument in arguments)
            {
                command.Append(' ').Append(QuoteWindowsArgument(argument));
            }

            const uint CreateUnicodeEnvironment = 0x00000400;
            if (!WindowsNative.CreateProcessAsUserW(
                    token,
                    executable,
                    command,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    CreateUnicodeEnvironment,
                    environment,
                    Path.GetDirectoryName(Path.GetFullPath(executable)),
                    ref startupInfo,
                    out processInfo))
            {
                throw LastWindowsError("Could not launch License Center in the active Windows session");
            }

            const uint Infinite = 0xffffffff;
            const uint WaitFailed = 0xffffffff;
            if (WindowsNative.WaitForSingleObject(processInfo.hProcess, Infinite) == WaitFailed)
            {
                throw LastWindowsError("Could not wait for License Center completion");
            }
            if (!WindowsNative.GetExitCodeProcess(processInfo.hProcess, out var exitCode))
            {
                throw LastWindowsError("Could not read License Center exit status");
            }
            return checked((int)exitCode);
        }
        finally
        {
            if (processInfo.hThread != IntPtr.Zero)
            {
                WindowsNative.CloseHandle(processInfo.hThread);
            }
            if (processInfo.hProcess != IntPtr.Zero)
            {
                WindowsNative.CloseHandle(processInfo.hProcess);
            }
            if (environmentCreated && environment != IntPtr.Zero)
            {
                WindowsNative.DestroyEnvironmentBlock(environment);
            }
            if (token != IntPtr.Zero)
            {
                WindowsNative.CloseHandle(token);
            }
        }
    }

    private static Exception LastWindowsError(string message)
    {
        var error = Marshal.GetLastWin32Error();
        return new Win32Exception(error, $"{message} (Windows error {error})");
    }

    private static string QuoteWindowsArgument(string value)
    {
        if (value.Length > 0 && !value.Any(char.IsWhiteSpace) && !value.Contains('"'))
        {
            return value;
        }

        var builder = new StringBuilder();
        builder.Append('"');
        var backslashes = 0;
        foreach (var character in value)
        {
            if (character == '\\')
            {
                backslashes++;
                continue;
            }
            if (character == '"')
            {
                builder.Append('\\', backslashes * 2 + 1);
                builder.Append('"');
                backslashes = 0;
                continue;
            }
            builder.Append('\\', backslashes);
            backslashes = 0;
            builder.Append(character);
        }
        builder.Append('\\', backslashes * 2);
        builder.Append('"');
        return builder.ToString();
    }

    private static OpenLicenseCenterResponse Result(
        string outcome,
        string reason,
        string correlationId,
        bool authorizationChanged = false) =>
        new(outcome, reason, authorizationChanged, correlationId);

    private static class WindowsNative
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct STARTUPINFO
        {
            internal int cb;
            internal string? lpReserved;
            internal string? lpDesktop;
            internal string? lpTitle;
            internal int dwX;
            internal int dwY;
            internal int dwXSize;
            internal int dwYSize;
            internal int dwXCountChars;
            internal int dwYCountChars;
            internal int dwFillAttribute;
            internal int dwFlags;
            internal short wShowWindow;
            internal short cbReserved2;
            internal IntPtr lpReserved2;
            internal IntPtr hStdInput;
            internal IntPtr hStdOutput;
            internal IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            internal IntPtr hProcess;
            internal IntPtr hThread;
            internal uint dwProcessId;
            internal uint dwThreadId;
        }

        [DllImport("kernel32.dll")]
        internal static extern uint WTSGetActiveConsoleSessionId();

        [DllImport("Wtsapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool WTSQueryUserToken(uint sessionId, out IntPtr token);

        [DllImport("userenv.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CreateEnvironmentBlock(out IntPtr environment, IntPtr token, bool inherit);

        [DllImport("userenv.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool DestroyEnvironmentBlock(IntPtr environment);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CreateProcessAsUserW(
            IntPtr token,
            string? applicationName,
            StringBuilder commandLine,
            IntPtr processAttributes,
            IntPtr threadAttributes,
            bool inheritHandles,
            uint creationFlags,
            IntPtr environment,
            string? currentDirectory,
            ref STARTUPINFO startupInfo,
            out PROCESS_INFORMATION processInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseHandle(IntPtr handle);
    }
}
