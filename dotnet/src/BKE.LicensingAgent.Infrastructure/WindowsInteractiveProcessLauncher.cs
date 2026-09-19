using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace BKE.LicensingAgent.Infrastructure;

internal static class WindowsInteractiveProcessLauncher
{
    internal static void Start(
        string executable,
        IReadOnlyList<string>? arguments = null)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Interactive product launch requires Windows.");
        }

        var fullExecutable = Path.GetFullPath(executable);
        var sessionId = WindowsNative.WTSGetActiveConsoleSessionId();
        if (sessionId == uint.MaxValue)
        {
            throw new Win32Exception(
                "No active Windows console session is available.");
        }

        IntPtr token = IntPtr.Zero;
        IntPtr environment = IntPtr.Zero;
        var processInfo = new WindowsNative.PROCESS_INFORMATION();
        var environmentCreated = false;

        try
        {
            if (!WindowsNative.WTSQueryUserToken(sessionId, out token))
            {
                throw LastWindowsError(
                    "Could not obtain the active Windows user token");
            }

            if (!WindowsNative.CreateEnvironmentBlock(
                    out environment,
                    token,
                    false))
            {
                throw LastWindowsError(
                    "Could not build the active Windows user environment");
            }
            environmentCreated = true;

            var startupInfo = new WindowsNative.STARTUPINFO
            {
                cb = Marshal.SizeOf<WindowsNative.STARTUPINFO>(),
                lpDesktop = @"winsta0\default",
            };

            var command =
                new StringBuilder(QuoteWindowsArgument(fullExecutable));
            foreach (var argument in arguments ?? Array.Empty<string>())
            {
                command.Append(' ')
                    .Append(QuoteWindowsArgument(argument));
            }

            const uint CreateUnicodeEnvironment = 0x00000400;
            if (!WindowsNative.CreateProcessAsUserW(
                    token,
                    fullExecutable,
                    command,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    CreateUnicodeEnvironment,
                    environment,
                    Path.GetDirectoryName(fullExecutable),
                    ref startupInfo,
                    out processInfo))
            {
                throw LastWindowsError(
                    "Could not launch the product in the active Windows session");
            }
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
        return new Win32Exception(
            error,
            $"{message} (Windows error {error})");
    }

    private static string QuoteWindowsArgument(string value)
    {
        if (value.Length > 0 &&
            !value.Any(char.IsWhiteSpace) &&
            !value.Contains('"'))
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
        internal static extern bool WTSQueryUserToken(
            uint sessionId,
            out IntPtr token);

        [DllImport("userenv.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CreateEnvironmentBlock(
            out IntPtr environment,
            IntPtr token,
            bool inherit);

        [DllImport("userenv.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool DestroyEnvironmentBlock(
            IntPtr environment);

        [DllImport(
            "advapi32.dll",
            CharSet = CharSet.Unicode,
            SetLastError = true)]
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
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseHandle(IntPtr handle);
    }
}
