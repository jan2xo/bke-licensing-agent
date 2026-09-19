using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Infrastructure;

public sealed class WindowsDpapiAccountSessionSecretStore : IAccountSessionSecretStore
{
    private static readonly byte[] Entropy =
        Encoding.UTF8.GetBytes("BKE Licensing Agent account-session secret store v1");

    private readonly string _path;

    public WindowsDpapiAccountSessionSecretStore(string? dataDirectory = null)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Windows DPAPI account-session storage is available only on Windows.");
        }

        var dataDir = dataDirectory ??
            Environment.GetEnvironmentVariable("BKE_AGENT_DATA_DIR") ??
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "BKE Digital Solutions",
                "Licensing Agent");

        _path = Path.Combine(
            Path.GetFullPath(dataDir),
            "secrets",
            "account-session.dpapi");
    }

    public Task<AccountSessionStoredState?> ReadAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!File.Exists(_path))
        {
            return Task.FromResult<AccountSessionStoredState?>(null);
        }

        var protectedBytes = File.ReadAllBytes(_path);
        byte[]? plaintext = null;
        try
        {
            plaintext = Unprotect(protectedBytes);
            var envelope = JsonSerializer.Deserialize<SecretEnvelope>(plaintext)
                ?? throw new InvalidDataException("Account-session secret store is empty.");
            return Task.FromResult<AccountSessionStoredState?>(FromEnvelope(envelope));
        }
        catch (JsonException error)
        {
            throw new InvalidDataException("Account-session secret store is malformed.", error);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedBytes);
            if (plaintext is not null)
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
    }

    public Task WriteAsync(
        AccountSessionStoredState state,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(state);

        var envelope = ToEnvelope(state);
        byte[]? plaintext = null;
        byte[]? protectedBytes = null;
        string? temporaryPath = null;

        try
        {
            plaintext = JsonSerializer.SerializeToUtf8Bytes(envelope);
            protectedBytes = Protect(plaintext);

            var directory = Path.GetDirectoryName(_path)
                ?? throw new InvalidOperationException("Account-session secret directory is unavailable.");
            Directory.CreateDirectory(directory);

            temporaryPath = Path.Combine(
                directory,
                $".account-session.{Guid.NewGuid():N}.tmp");

            using (var stream = new FileStream(
                temporaryPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                4096,
                FileOptions.WriteThrough))
            {
                stream.Write(protectedBytes);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporaryPath, _path, overwrite: true);
            temporaryPath = null;
            return Task.CompletedTask;
        }
        finally
        {
            if (temporaryPath is not null)
            {
                try { File.Delete(temporaryPath); } catch { }
            }
            if (plaintext is not null)
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
            if (protectedBytes is not null)
            {
                CryptographicOperations.ZeroMemory(protectedBytes);
            }
        }
    }

    public Task ClearAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (File.Exists(_path))
        {
            File.Delete(_path);
        }
        return Task.CompletedTask;
    }

    private static SecretEnvelope ToEnvelope(AccountSessionStoredState state) =>
        state switch
        {
            PendingAccountSessionState pending => new SecretEnvelope(
                "pending",
                pending.DeviceCode,
                pending.VerificationUri,
                pending.UserCode,
                pending.ExpiresAt,
                pending.PollInterval,
                pending.NextPollAt,
                null,
                null,
                null,
                null,
                null),

            ActiveAccountSessionState active => new SecretEnvelope(
                "active",
                null,
                null,
                null,
                null,
                null,
                null,
                active.AccessToken,
                active.RefreshToken,
                active.SessionId,
                active.AccessTokenExpiresAt,
                active.RefreshTokenExpiresAt,
                active.Account),

            _ => throw new InvalidDataException("Unsupported account-session secret state."),
        };

    private static AccountSessionStoredState FromEnvelope(SecretEnvelope envelope) =>
        envelope.Kind switch
        {
            "pending" when
                !string.IsNullOrWhiteSpace(envelope.DeviceCode) &&
                !string.IsNullOrWhiteSpace(envelope.VerificationUri) &&
                !string.IsNullOrWhiteSpace(envelope.UserCode) &&
                envelope.ExpiresAt is not null &&
                envelope.PollInterval is not null &&
                envelope.NextPollAt is not null =>
                new PendingAccountSessionState(
                    envelope.DeviceCode,
                    envelope.VerificationUri,
                    envelope.UserCode,
                    envelope.ExpiresAt.Value,
                    envelope.PollInterval.Value,
                    envelope.NextPollAt.Value),

            "active" when
                !string.IsNullOrWhiteSpace(envelope.AccessToken) &&
                !string.IsNullOrWhiteSpace(envelope.RefreshToken) &&
                envelope.AccessTokenExpiresAt is not null &&
                envelope.RefreshTokenExpiresAt is not null &&
                envelope.Account is not null =>
                new ActiveAccountSessionState(
                    envelope.AccessToken,
                    envelope.RefreshToken,
                    envelope.SessionId,
                    envelope.AccessTokenExpiresAt.Value,
                    envelope.RefreshTokenExpiresAt.Value,
                    envelope.Account),

            _ => throw new InvalidDataException("Account-session secret state is invalid."),
        };

    private static byte[] Protect(byte[] plaintext)
    {
        using var data = DataBlob.FromBytes(plaintext);
        using var entropy = DataBlob.FromBytes(Entropy);

        if (!CryptProtectData(
            ref data.Value,
            "BKE Licensing Agent account session",
            ref entropy.Value,
            IntPtr.Zero,
            IntPtr.Zero,
            0,
            out var output))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "DPAPI protection failed.");
        }

        try
        {
            return output.ToBytes();
        }
        finally
        {
            if (output.Data != IntPtr.Zero)
            {
                LocalFree(output.Data);
            }
        }
    }

    private static byte[] Unprotect(byte[] ciphertext)
    {
        using var data = DataBlob.FromBytes(ciphertext);
        using var entropy = DataBlob.FromBytes(Entropy);

        if (!CryptUnprotectData(
            ref data.Value,
            IntPtr.Zero,
            ref entropy.Value,
            IntPtr.Zero,
            IntPtr.Zero,
            0,
            out var output))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "DPAPI unprotection failed.");
        }

        try
        {
            return output.ToBytes();
        }
        finally
        {
            if (output.Data != IntPtr.Zero)
            {
                var zeros = new byte[output.Size];
                try
                {
                    Marshal.Copy(zeros, 0, output.Data, output.Size);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(zeros);
                    LocalFree(output.Data);
                }
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeDataBlob
    {
        public int Size;
        public IntPtr Data;

        public readonly byte[] ToBytes()
        {
            if (Size <= 0 || Data == IntPtr.Zero)
            {
                return Array.Empty<byte>();
            }

            var result = new byte[Size];
            Marshal.Copy(Data, result, 0, Size);
            return result;
        }
    }

    private sealed class DataBlob : IDisposable
    {
        public NativeDataBlob Value;

        private DataBlob(byte[] bytes)
        {
            Value = new NativeDataBlob
            {
                Size = bytes.Length,
                Data = bytes.Length == 0
                    ? IntPtr.Zero
                    : Marshal.AllocHGlobal(bytes.Length),
            };

            if (bytes.Length > 0)
            {
                Marshal.Copy(bytes, 0, Value.Data, bytes.Length);
            }
        }

        public static DataBlob FromBytes(byte[] bytes) => new(bytes);

        public void Dispose()
        {
            if (Value.Data != IntPtr.Zero)
            {
                var zeros = new byte[Value.Size];
                try
                {
                    Marshal.Copy(zeros, 0, Value.Data, Value.Size);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(zeros);
                    Marshal.FreeHGlobal(Value.Data);
                    Value.Data = IntPtr.Zero;
                    Value.Size = 0;
                }
            }
        }
    }

    private sealed record SecretEnvelope(
        string Kind,
        string? DeviceCode,
        string? VerificationUri,
        string? UserCode,
        DateTimeOffset? ExpiresAt,
        TimeSpan? PollInterval,
        DateTimeOffset? NextPollAt,
        string? AccessToken,
        string? RefreshToken,
        string? SessionId,
        DateTimeOffset? AccessTokenExpiresAt,
        DateTimeOffset? RefreshTokenExpiresAt,
        AccountSessionAccount? Account);

    [DllImport(
        "Crypt32.dll",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptProtectData(
        ref NativeDataBlob pDataIn,
        string? szDataDescr,
        ref NativeDataBlob pOptionalEntropy,
        IntPtr pvReserved,
        IntPtr pPromptStruct,
        int dwFlags,
        out NativeDataBlob pDataOut);

    [DllImport(
        "Crypt32.dll",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptUnprotectData(
        ref NativeDataBlob pDataIn,
        IntPtr ppszDataDescr,
        ref NativeDataBlob pOptionalEntropy,
        IntPtr pvReserved,
        IntPtr pPromptStruct,
        int dwFlags,
        out NativeDataBlob pDataOut);

    [DllImport("Kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr hMem);
}
