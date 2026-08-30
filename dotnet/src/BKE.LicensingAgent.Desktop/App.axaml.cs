using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using BKE.LicensingAgent.Desktop.Infrastructure;
using BKE.LicensingAgent.Desktop.ViewModels;
using BKE.LicensingAgent.Presentation;

namespace BKE.LicensingAgent.Desktop;

public sealed partial class App : Application
{
    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var preview = string.Equals(
                Environment.GetEnvironmentVariable("BKE_AGENT_UI_PREVIEW"),
                "1",
                StringComparison.Ordinal);

            IAgentDesktopViewSource source = preview
                ? new DesignAgentDesktopViewSource()
                : new UnconnectedAgentDesktopViewSource();

            desktop.MainWindow = new MainWindow
            {
                DataContext = new MainWindowViewModel(source),
            };
        }

        base.OnFrameworkInitializationCompleted();
    }
}
