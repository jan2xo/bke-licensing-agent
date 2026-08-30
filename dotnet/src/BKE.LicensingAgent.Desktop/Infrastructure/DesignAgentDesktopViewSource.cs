using BKE.LicensingAgent.Presentation;

namespace BKE.LicensingAgent.Desktop.Infrastructure;

internal sealed class DesignAgentDesktopViewSource : IAgentDesktopViewSource
{
    public AgentDesktopSnapshot Snapshot { get; private set; } = BuildSnapshot();

    public event EventHandler<AgentDesktopSnapshot>? SnapshotChanged;

    public ValueTask DispatchAsync(
        AgentDesktopAction action,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (action is AgentDesktopAction.Refresh)
        {
            Snapshot = BuildSnapshot();
            SnapshotChanged?.Invoke(this, Snapshot);
        }

        return ValueTask.CompletedTask;
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    private static AgentDesktopSnapshot BuildSnapshot() => new(
        RuntimeState: "AGENT HEALTHY · PREVIEW",
        RuntimeDetail: "A calm desktop command center for licensing, product discovery and updates. Preview mode exercises the presentation contract only; it does not represent live authorization state.",
        SecurityState: "Trusted boundary",
        SecurityDetail: "Product applications receive typed decisions while keys, policy, trusted paths and privileged execution remain Agent-owned.",
        UpdateState: "1 update available",
        UpdateDetail: "Preview data demonstrates how BKE.Updater state can land in the desktop shell without giving the UI download or installer authority.",
        Products:
        [
            new ManagedProductSummary(
                "bke-render-dock",
                "Render Dock",
                "1.0.2",
                "AUTHORIZED · PREVIEW",
                "Up to date · preview",
                "RD"),
            new ManagedProductSummary(
                "bke-air-stack",
                "Air Stack",
                "1.0.0",
                "AUTHORIZED · PREVIEW",
                "Update available · preview",
                "AS"),
        ],
        Activity:
        [
            new AgentActivityItem(
                "Authorization decision",
                "Render Dock received an allowed preview state.",
                "just now",
                "licensing"),
            new AgentActivityItem(
                "Update discovered",
                "Air Stack preview state reports a newer version.",
                "2 min",
                "updates"),
            new AgentActivityItem(
                "Trust posture checked",
                "Presentation remains isolated from privileged execution controls.",
                "5 min",
                "security"),
        ],
        IsPreview: true);
}
