using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using Avalonia.Threading;
using BKE.LicensingAgent.Presentation;

namespace BKE.LicensingAgent.Desktop.ViewModels;

public sealed class MainWindowViewModel : INotifyPropertyChanged, IAsyncDisposable
{
    private readonly IAgentDesktopViewSource _source;
    private string _runtimeState = string.Empty;
    private string _runtimeDetail = string.Empty;
    private string _securityState = string.Empty;
    private string _securityDetail = string.Empty;
    private string _updateState = string.Empty;
    private string _updateDetail = string.Empty;
    private string _environmentLabel = string.Empty;

    public MainWindowViewModel(IAgentDesktopViewSource source)
    {
        _source = source;
        RefreshCommand = new AsyncRelayCommand(
            () => _source.DispatchAsync(new AgentDesktopAction.Refresh()).AsTask());
        _source.SnapshotChanged += OnSnapshotChanged;
        Apply(_source.Snapshot);
    }

    public ObservableCollection<ProductCardViewModel> Products { get; } = [];

    public ObservableCollection<ActivityRowViewModel> Activity { get; } = [];

    public ICommand RefreshCommand { get; }

    public string RuntimeState
    {
        get => _runtimeState;
        private set => SetField(ref _runtimeState, value);
    }

    public string RuntimeDetail
    {
        get => _runtimeDetail;
        private set => SetField(ref _runtimeDetail, value);
    }

    public string SecurityState
    {
        get => _securityState;
        private set => SetField(ref _securityState, value);
    }

    public string SecurityDetail
    {
        get => _securityDetail;
        private set => SetField(ref _securityDetail, value);
    }

    public string UpdateState
    {
        get => _updateState;
        private set => SetField(ref _updateState, value);
    }

    public string UpdateDetail
    {
        get => _updateDetail;
        private set => SetField(ref _updateDetail, value);
    }

    public string EnvironmentLabel
    {
        get => _environmentLabel;
        private set => SetField(ref _environmentLabel, value);
    }

    public int ProductCount => Products.Count;

    public string ProductCountLabel => ProductCount == 1 ? "1 PRODUCT" : $"{ProductCount} PRODUCTS";

    public bool ShowEmptyProducts => ProductCount == 0;

    public bool ShowEmptyActivity => Activity.Count == 0;

    public event PropertyChangedEventHandler? PropertyChanged;

    public async ValueTask DisposeAsync()
    {
        _source.SnapshotChanged -= OnSnapshotChanged;
        await _source.DisposeAsync();
    }

    private void OnSnapshotChanged(object? sender, AgentDesktopSnapshot snapshot)
    {
        if (Dispatcher.UIThread.CheckAccess())
        {
            Apply(snapshot);
            return;
        }

        Dispatcher.UIThread.Post(() => Apply(snapshot));
    }

    private void Apply(AgentDesktopSnapshot snapshot)
    {
        RuntimeState = snapshot.RuntimeState;
        RuntimeDetail = snapshot.RuntimeDetail;
        SecurityState = snapshot.SecurityState;
        SecurityDetail = snapshot.SecurityDetail;
        UpdateState = snapshot.UpdateState;
        UpdateDetail = snapshot.UpdateDetail;
        EnvironmentLabel = snapshot.IsPreview ? "UI PREVIEW" : "PROVIDER PENDING";

        Products.Clear();
        foreach (var product in snapshot.Products)
        {
            Products.Add(ProductCardViewModel.From(product));
        }

        Activity.Clear();
        foreach (var item in snapshot.Activity)
        {
            Activity.Add(new ActivityRowViewModel(item.Title, item.Detail, item.TimestampLabel));
        }

        Raise(nameof(ProductCount));
        Raise(nameof(ProductCountLabel));
        Raise(nameof(ShowEmptyProducts));
        Raise(nameof(ShowEmptyActivity));
    }

    private void SetField(ref string field, string value, [CallerMemberName] string? propertyName = null)
    {
        if (field == value)
        {
            return;
        }

        field = value;
        Raise(propertyName);
    }

    private void Raise(string? propertyName) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}

public sealed record ProductCardViewModel(
    string Initials,
    string DisplayName,
    string Detail,
    string AuthorizationState,
    string UpdateState)
{
    public static ProductCardViewModel From(ManagedProductSummary product)
    {
        var words = product.DisplayName
            .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var initials = string.Concat(words.Take(2).Select(static word => char.ToUpperInvariant(word[0])));
        if (string.IsNullOrEmpty(initials))
        {
            initials = "BKE";
        }

        return new ProductCardViewModel(
            initials,
            product.DisplayName,
            $"{product.Version} · {product.ProductId}",
            product.AuthorizationState,
            product.UpdateState);
    }
}

public sealed record ActivityRowViewModel(
    string Title,
    string Detail,
    string TimestampLabel);

internal sealed class AsyncRelayCommand(Func<Task> execute) : ICommand
{
    public event EventHandler? CanExecuteChanged
    {
        add { }
        remove { }
    }

    public bool CanExecute(object? parameter) => true;

    public async void Execute(object? parameter)
    {
        try
        {
            await execute();
        }
        catch
        {
            // Presentation actions report operational failures through the next snapshot.
        }
    }
}
