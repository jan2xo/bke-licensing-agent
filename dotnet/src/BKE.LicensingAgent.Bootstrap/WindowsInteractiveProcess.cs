using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace BKE.LicensingAgent.Bootstrap;

internal static class WindowsInteractiveProcess
{
    internal static int Run(string executable, IReadOnlyList<string> arguments, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        var sessionId = Native.WTSGetActiveConsoleSessionId();
        if (sessionId == uint.MaxValue) throw new Win32Exception("No active Windows console session is available");

        IntPtr token = IntPtr.Zero;
        IntPtr environment = IntPtr.Zero;
        var process = new Native.PROCESS_INFORMATION();
        var environmentCreated = false;
        try
        {
            if (!Native.WTSQueryUserToken(sessionId, out token)) throw LastError("Could not obtain active user token");
            if (!Native.CreateEnvironmentBlock(out environment, token, false)) throw LastError("Could not build active user environment");
            environmentCreated = true;
            var startup = new Native.STARTUPINFO
            {
                cb = Marshal.SizeOf<Native.STARTUPINFO>(),
                lpDesktop = "winsta0\\default",
            };
            var command = new StringBuilder(Quote(executable));
            foreach (var argument in arguments) command.Append(' ').Append(Quote(argument));
            const uint CreateUnicodeEnvironment = 0x00000400;
            if (!Native.CreateProcessAsUserW(token, executable, command, IntPtr.Zero, IntPtr.Zero, false,
                    CreateUnicodeEnvironment, environment, Path.GetDirectoryName(Path.GetFullPath(executable)),
                    ref startup, out process))
            {
                throw LastError("Could not launch interactive process");
            }
            const uint Infinite = 0xffffffff;
            const uint WaitFailed = 0xffffffff;
            if (Native.WaitForSingleObject(process.hProcess, Infinite) == WaitFailed) throw LastError("Could not wait for interactive process");
            if (!Native.GetExitCodeProcess(process.hProcess, out var exitCode)) throw LastError("Could not read interactive process status");
            return checked((int)exitCode);
        }
        finally
        {
            if (process.hThread != IntPtr.Zero) Native.CloseHandle(process.hThread);
            if (process.hProcess != IntPtr.Zero) Native.CloseHandle(process.hProcess);
            if (environmentCreated && environment != IntPtr.Zero) Native.DestroyEnvironmentBlock(environment);
            if (token != IntPtr.Zero) Native.CloseHandle(token);
        }
    }

    private static Exception LastError(string message)
    {
        var error = Marshal.GetLastWin32Error();
        return new Win32Exception(error, $"{message} (Windows error {error})");
    }

    private static string Quote(string value)
    {
        if (value.Length > 0 && !value.Any(char.IsWhiteSpace) && !value.Contains('"')) return value;
        var builder = new StringBuilder("\"");
        var backslashes = 0;
        foreach (var character in value)
        {
            if (character == '\\') { backslashes++; continue; }
            if (character == '"')
            {
                builder.Append('\\', backslashes * 2 + 1).Append('"');
                backslashes = 0;
                continue;
            }
            builder.Append('\\', backslashes);
            backslashes = 0;
            builder.Append(character);
        }
        builder.Append('\\', backslashes * 2).Append('"');
        return builder.ToString();
    }

    private static class Native
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
        internal static extern bool CreateProcessAsUserW(IntPtr token, string? applicationName, StringBuilder commandLine,
            IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint creationFlags,
            IntPtr environment, string? currentDirectory, ref STARTUPINFO startupInfo,
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
