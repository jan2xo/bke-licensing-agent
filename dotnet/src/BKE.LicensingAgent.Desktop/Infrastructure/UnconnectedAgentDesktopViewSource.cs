using BKE.LicensingAgent.Presentation;

namespace BKE.LicensingAgent.Desktop.Infrastructure;

internal sealed class UnconnectedAgentDesktopViewSource : IAgentDesktopViewSource
{
    public AgentDesktopSnapshot Snapshot { get; } = new(
        RuntimeState: "UI SHELL READY",
        RuntimeDetail: "The native .NET 10 License Center is running. Runtime providers remain fail-closed when live state is unavailable.",
        SecurityState: "Fail-closed",
        SecurityDetail: "No live provider snapshot is attached to this desktop view. The Agent runtime remains the authorization authority.",
        UpdateState: "Runtime connection pending",
        UpdateDetail: "The presentation boundary is ready for BKE.Updater state. No update authority is implemented in the UI.",
        Products: [],
        Activity: []);

    public event EventHandler<AgentDesktopSnapshot>? SnapshotChanged
    {
        add { }
        remove { }
    }

    public ValueTask DispatchAsync(
        AgentDesktopAction action,
        CancellationToken cancellationToken = default) => ValueTask.CompletedTask;

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}
