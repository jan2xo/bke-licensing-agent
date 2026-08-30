namespace BKE.LicensingAgent.Presentation;

public sealed record AgentDesktopSnapshot(
    string RuntimeState,
    string RuntimeDetail,
    string SecurityState,
    string SecurityDetail,
    string UpdateState,
    string UpdateDetail,
    IReadOnlyList<ManagedProductSummary> Products,
    IReadOnlyList<AgentActivityItem> Activity,
    bool IsPreview = false);

public sealed record ManagedProductSummary(
    string ProductId,
    string DisplayName,
    string Version,
    string AuthorizationState,
    string UpdateState,
    string AccentLabel);

public sealed record AgentActivityItem(
    string Title,
    string Detail,
    string TimestampLabel,
    string Category);

public abstract record AgentDesktopAction
{
    public sealed record Refresh : AgentDesktopAction;
    public sealed record OpenLicenseCenter(string ProductId) : AgentDesktopAction;
    public sealed record CheckUpdates(string ProductId) : AgentDesktopAction;
    public sealed record OpenSettings : AgentDesktopAction;
}

public interface IAgentDesktopViewSource : IAsyncDisposable
{
    AgentDesktopSnapshot Snapshot { get; }

    event EventHandler<AgentDesktopSnapshot>? SnapshotChanged;

    ValueTask DispatchAsync(
        AgentDesktopAction action,
        CancellationToken cancellationToken = default);
}
