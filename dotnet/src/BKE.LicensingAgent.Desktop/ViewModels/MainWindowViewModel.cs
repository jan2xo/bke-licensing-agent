using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using Avalonia.Threading;
using BKE.LicensingAgent.Contracts;
using BKE.LicensingAgent.Desktop.Infrastructure;
using BKE.LicensingAgent.Presentation;

namespace BKE.LicensingAgent.Desktop.ViewModels;

public sealed class MainWindowViewModel : INotifyPropertyChanged, IAsyncDisposable
{
    private readonly IAgentDesktopViewSource _source;
    private readonly AccountSessionLoopbackClient _accountSessionClient;
    private string _runtimeState = string.Empty;
    private string _runtimeDetail = string.Empty;
    private string _securityState = string.Empty;
    private string _securityDetail = string.Empty;
    private string _updateState = string.Empty;
    private string _updateDetail = string.Empty;
    private string _environmentLabel = string.Empty;
    private string _accountSessionState = "UNKNOWN";
    private string _accountDisplay = "Check the Agent account session.";
    private string _accountSessionMessage = "Launcher and License Center use the same Agent-owned machine session.";
    private string _accountUserCode = string.Empty;
    private string _accountVerificationUri = string.Empty;

    public MainWindowViewModel(
        IAgentDesktopViewSource source,
        AccountSessionLoopbackClient accountSessionClient)
    {
        _source = source;
        _accountSessionClient = accountSessionClient;
        RefreshCommand = new AsyncRelayCommand(
            () => _source.DispatchAsync(new AgentDesktopAction.Refresh()).AsTask());
        AccountSignInCommand = new AsyncRelayCommand(StartAccountSessionAsync);
        AccountRefreshCommand = new AsyncRelayCommand(RefreshAccountSessionAsync);
        AccountSignOutCommand = new AsyncRelayCommand(SignOutAccountSessionAsync);
        _source.SnapshotChanged += OnSnapshotChanged;
        Apply(_source.Snapshot);
    }

    public ObservableCollection<ProductCardViewModel> Products { get; } = [];

    public ObservableCollection<ActivityRowViewModel> Activity { get; } = [];

    public ICommand RefreshCommand { get; }

    public ICommand AccountSignInCommand { get; }

    public ICommand AccountRefreshCommand { get; }

    public ICommand AccountSignOutCommand { get; }

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

    public string AccountSessionState
    {
        get => _accountSessionState;
        private set => SetField(ref _accountSessionState, value);
    }

    public string AccountDisplay
    {
        get => _accountDisplay;
        private set => SetField(ref _accountDisplay, value);
    }

    public string AccountSessionMessage
    {
        get => _accountSessionMessage;
        private set => SetField(ref _accountSessionMessage, value);
    }

    public string AccountUserCode
    {
        get => _accountUserCode;
        private set => SetField(ref _accountUserCode, value);
    }

    public string AccountVerificationUri
    {
        get => _accountVerificationUri;
        private set => SetField(ref _accountVerificationUri, value);
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

    private async Task StartAccountSessionAsync()
    {
        try
        {
            var response = await _accountSessionClient.StartAsync(CancellationToken.None);
            AccountSessionState = response.Status;
            AccountUserCode = response.UserCode ?? string.Empty;
            AccountVerificationUri = response.VerificationUri ?? string.Empty;
            AccountSessionMessage = response.Error?.Message ?? response.Status switch
            {
                "AUTHENTICATED" => "This machine already has an authenticated BKE account session.",
                "PENDING" => "Complete BKE sign-in in your browser, then refresh this account status.",
                _ => "BKE account sign-in could not be started.",
            };

            if (response.Status == "AUTHENTICATED")
            {
                await RefreshAccountSessionAsync();
                return;
            }

            if (response.Status == "PENDING" &&
                Uri.TryCreate(response.VerificationUri, UriKind.Absolute, out var verificationUri) &&
                verificationUri.Scheme == Uri.UriSchemeHttps)
            {
                TryOpenBrowser(verificationUri);
            }
        }
        catch (HttpRequestException)
        {
            SetAccountSessionUnavailable();
        }
        catch (TaskCanceledException)
        {
            SetAccountSessionUnavailable();
        }
        catch (InvalidDataException)
        {
            SetAccountSessionUnavailable();
        }
    }

    private async Task RefreshAccountSessionAsync()
    {
        try
        {
            var response = await _accountSessionClient.StatusAsync(CancellationToken.None);
            ApplyAccountStatus(response);
        }
        catch (HttpRequestException)
        {
            SetAccountSessionUnavailable();
        }
        catch (TaskCanceledException)
        {
            SetAccountSessionUnavailable();
        }
        catch (InvalidDataException)
        {
            SetAccountSessionUnavailable();
        }
    }

    private async Task SignOutAccountSessionAsync()
    {
        try
        {
            var response = await _accountSessionClient.LogoutAsync(CancellationToken.None);
            AccountSessionState = response.Status;
            AccountDisplay = "Not signed in";
            AccountUserCode = string.Empty;
            AccountVerificationUri = string.Empty;
            AccountSessionMessage = response.Error?.Message ?? "Signed out on this machine.";
        }
        catch (HttpRequestException)
        {
            SetAccountSessionUnavailable();
        }
        catch (TaskCanceledException)
        {
            SetAccountSessionUnavailable();
        }
        catch (InvalidDataException)
        {
            SetAccountSessionUnavailable();
        }
    }

    private void ApplyAccountStatus(AccountSessionStatusResponse response)
    {
        AccountSessionState = response.Status;

        if (response.Account is not null)
        {
            AccountDisplay = $"{response.Account.DisplayName} · {response.Account.Email}";
        }
        else if (response.Status is "SIGNED_OUT" or "DENIED" or "EXPIRED" or "FAILED")
        {
            AccountDisplay = "Not signed in";
        }

        AccountSessionMessage = response.Error?.Message ?? response.Status switch
        {
            "AUTHENTICATED" => "This is the same Agent-owned account session consumed by BKE Launcher.",
            "PENDING" => "Waiting for browser approval.",
            "SIGNED_OUT" => "No BKE account is authenticated on this machine.",
            "DENIED" => "BKE account authorization was denied.",
            "EXPIRED" => "BKE account authorization expired.",
            _ => "BKE account-session status updated.",
        };
    }

    private void SetAccountSessionUnavailable()
    {
        AccountSessionState = "AGENT_UNAVAILABLE";
        AccountDisplay = "Account session unavailable";
        AccountSessionMessage = "The local BKE Licensing Agent account-session endpoint is unavailable or invalid.";
    }

    private static void TryOpenBrowser(Uri uri)
    {
        try
        {
            Process.Start(new ProcessStartInfo(uri.ToString())
            {
                UseShellExecute = true,
            });
        }
        catch
        {
            // The HTTPS verification URI remains visible for manual opening.
        }
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
