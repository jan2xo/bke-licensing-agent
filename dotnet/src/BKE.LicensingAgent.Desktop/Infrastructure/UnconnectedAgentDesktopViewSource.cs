using BKE.LicensingAgent.Presentation;

namespace BKE.LicensingAgent.Desktop.Infrastructure;

internal sealed class UnconnectedAgentDesktopViewSource : IAgentDesktopViewSource
{
    public AgentDesktopSnapshot Snapshot { get; } = new(
        RuntimeState: "UI SHELL READY",
        RuntimeDetail: "The .NET 10 desktop shell is running. Licensing, discovery and updater providers remain fail-closed until each capability is migrated and certified.",
        SecurityState: "Fail-closed",
        SecurityDetail: "No trusted provider is attached to this vNext desktop shell yet. Existing Python Generation 1 remains the shipping authorization runtime.",
        UpdateState: "Provider pending",
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
