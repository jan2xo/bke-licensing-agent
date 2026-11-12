using System.IO.Pipes;
using System.Security.Principal;
using BKE.LicensingAgent.Infrastructure;

/// <summary>
/// Disposable Windows runner proof of kernel PID/path/SID observation for an
/// actual pipe peer. No customer product or installed grant is exercised.
/// </summary>
internal static class StandaloneStartupWindowsPeerCertification
{
    public static async Task RunAsync()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException(
                "Startup native peer fixture must run on Windows.");

        string name = "bke-startup-native-fixture-" + Guid.NewGuid().ToString("N");
        using var server = new NamedPipeServerStream(
            name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous);
        using var client = new NamedPipeClientStream(
            ".", name, PipeDirection.InOut, PipeOptions.Asynchronous,
            TokenImpersonationLevel.Impersonation);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));

        await Task.WhenAll(
            server.WaitForConnectionAsync(deadline.Token),
            client.ConnectAsync(deadline.Token));
        var attestor = new WindowsNamedPipeStandaloneStartupPeerAttestor(server);
        var original = await attestor.ObserveConnectedPeerAsync(deadline.Token);

        Require(original is not null &&
            original.WindowsKernelObserved &&
            original.ProcessId == Environment.ProcessId &&
            original.StartedUtcTicks > 0 &&
            original.ImagePath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) &&
            original.ImageSha256.Length == 64 &&
            original.UserSid.StartsWith("S-1-", StringComparison.Ordinal),
            "Windows named pipe did not attest its actual OS process peer");

        Require(await attestor.IsSameLivePeerAsync(original!, deadline.Token),
            "Kernel-observed peer failed exact process recheck");

        Require(!await attestor.IsSameLivePeerAsync(
            original! with { ProcessId = Environment.ProcessId + 1 },
            deadline.Token),
            "Changed PID accepted despite kernel process identity");

        Require(!await attestor.IsSameLivePeerAsync(
            original! with { ImageSha256 = new string('0', 64) },
            deadline.Token),
            "Changed executable hash accepted despite fresh fingerprint");

        Require(!await attestor.IsSameLivePeerAsync(
            original! with { StartedUtcTicks = original!.StartedUtcTicks - 1 },
            deadline.Token),
            "Changed PID-generation start time accepted");

        client.Dispose();
        server.Disconnect();
        Require(await attestor.ObserveConnectedPeerAsync(deadline.Token) is null,
            "Disconnected pipe still had startup process authority");

        Console.WriteLine("Windows standalone startup peer fixture: 6/6 PASS");
    }

    private static void Require(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException("FAIL: " + message);
    }
}
