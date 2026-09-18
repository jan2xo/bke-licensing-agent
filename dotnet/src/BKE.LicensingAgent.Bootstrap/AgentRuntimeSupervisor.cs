using System.Diagnostics;

namespace BKE.LicensingAgent.Bootstrap;

internal sealed class AgentRuntimeSupervisor(ILogger<AgentRuntimeSupervisor> logger) : BackgroundService
{
    private static readonly TimeSpan RestartDelay = TimeSpan.FromSeconds(5);
    private Process? _child;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            var executable = Path.GetFullPath(RuntimeBridgeContract.RuntimeExecutable);
            if (!File.Exists(executable))
            {
                logger.LogCritical("Agent runtime payload is missing: {RuntimeExecutable}", executable);
                await DelayOrStop(stoppingToken);
                continue;
            }

            try
            {
                using var child = StartRuntime(executable);
                _child = child;
                logger.LogInformation("Agent runtime started: pid={ProcessId} executable={RuntimeExecutable}", child.Id, executable);
                await child.WaitForExitAsync(stoppingToken);
                if (!stoppingToken.IsCancellationRequested)
                {
                    logger.LogWarning("Agent runtime exited unexpectedly with code {ExitCode}; restarting", child.ExitCode);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception exception)
            {
                logger.LogError(exception, "Agent runtime supervisor failed to launch or observe the runtime");
            }
            finally
            {
                _child = null;
            }

            await DelayOrStop(stoppingToken);
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        var child = _child;
        if (child is not null && !child.HasExited)
        {
            try
            {
                child.Kill(entireProcessTree: true);
                await child.WaitForExitAsync(cancellationToken);
            }
            catch (Exception exception) when (exception is InvalidOperationException or System.ComponentModel.Win32Exception)
            {
                logger.LogWarning(exception, "Could not stop Agent runtime child cleanly");
            }
        }
        await base.StopAsync(cancellationToken);
    }

    private static Process StartRuntime(string executable)
    {
        var start = new ProcessStartInfo
        {
            FileName = executable,
            WorkingDirectory = Path.GetDirectoryName(executable)!,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        start.Environment["BKE_AGENT_DATA_DIR"] = RuntimeBridgeContract.DataRoot;
        start.Environment["BKE_LICENSE_CENTER_EXECUTABLE"] = RuntimeBridgeContract.LicenseCenterExecutable;
        return Process.Start(start) ?? throw new InvalidOperationException("Agent runtime process did not start");
    }

    private static async Task DelayOrStop(CancellationToken stoppingToken)
    {
        try
        {
            await Task.Delay(RestartDelay, stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // normal service shutdown
        }
    }
}
