using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using BKE.LicensingAgent.Application;

namespace BKE.LicensingAgent.Infrastructure;

/// <summary>
/// Windows-kernel peer identity for a connected named pipe, *not* a request
/// supplied pid/path/SID. The Host is not yet wired to expose this source-only
/// preproduction capability. A verified signed-install registry is still
/// mandatory before a product can receive authorization.
/// </summary>
public sealed class WindowsNamedPipeStandaloneStartupPeerAttestor
    : IStandaloneStartupPeerAttestor
{
    private readonly NamedPipeServerStream _connectedPipe;

    public WindowsNamedPipeStandaloneStartupPeerAttestor(
        NamedPipeServerStream connectedPipe)
    {
        _connectedPipe = connectedPipe ??
            throw new ArgumentNullException(nameof(connectedPipe));
    }

    public Task<StandaloneStartupProcessEvidence?> ObserveConnectedPeerAsync(
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(Capture());
    }

    public Task<bool> IsSameLivePeerAsync(
        StandaloneStartupProcessEvidence original,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var updated = Capture();
        return Task.FromResult(updated is not null &&
            updated.ProcessId == original.ProcessId &&
            updated.StartedUtcTicks == original.StartedUtcTicks &&
            updated.WindowsKernelObserved &&
            string.Equals(updated.UserSid, original.UserSid,
                StringComparison.Ordinal) &&
            string.Equals(updated.ImagePath, original.ImagePath,
                StringComparison.OrdinalIgnoreCase) &&
            string.Equals(updated.ImageSha256, original.ImageSha256,
                StringComparison.Ordinal));
    }

    private StandaloneStartupProcessEvidence? Capture()
    {
        // No Linux, mock PID, client metadata or inferred identity fallback.
        if (!OperatingSystem.IsWindows() || !_connectedPipe.IsConnected)
            return null;

        try
        {
            if (!GetNamedPipeClientProcessId(
                    _connectedPipe.SafePipeHandle, out uint pid) ||
                pid == 0 || pid > int.MaxValue)
                return null;

            string? userSid = null;
            // The OS pipe impersonation token, not product IPC, supplies SID.
            _connectedPipe.RunAsClient(() =>
            {
                // Platform analysis must see the guard inside the callback;
                // Windows reachability of the caller does not flow into it.
                if (!OperatingSystem.IsWindows())
                    return;
                using var identity = WindowsIdentity.GetCurrent();
                userSid = identity.User?.Value;
            });
            if (string.IsNullOrWhiteSpace(userSid))
                return null;

            using var process = Process.GetProcessById((int)pid);
            if (process.HasExited)
                return null;

            var startedTicks = process.StartTime.ToUniversalTime().Ticks;
            var image = process.MainModule?.FileName;
            if (string.IsNullOrWhiteSpace(image) || !File.Exists(image))
                return null;

            image = Path.GetFullPath(image);
            using var stream = new FileStream(
                image, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            var digest = Convert.ToHexString(SHA256.HashData(stream))
                .ToLowerInvariant();

            // Check process identity again after I/O to detect PID reuse.
            if (process.HasExited ||
                process.StartTime.ToUniversalTime().Ticks != startedTicks)
                return null;

            return new StandaloneStartupProcessEvidence(
                (int)pid,
                startedTicks,
                image,
                digest,
                userSid,
                DateTimeOffset.UtcNow,
                WindowsKernelObserved: true);
        }
        catch (Exception ex) when (
            ex is InvalidOperationException or ArgumentException or
            UnauthorizedAccessException or System.ComponentModel.Win32Exception or
            IOException or CryptographicException)
        {
            return null;
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(
        SafePipeHandle pipe, out uint clientProcessId);
}
