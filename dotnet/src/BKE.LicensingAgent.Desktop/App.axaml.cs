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
            var invocation = LicenseCenterInvocation.Parse(desktop.Args ?? []);

            if (invocation.Mode == LicenseCenterMode.Invalid)
            {
                desktop.Shutdown(3);
                base.OnFrameworkInitializationCompleted();
                return;
            }

            if (invocation.Mode == LicenseCenterMode.AgentUpdatePrompt)
            {
                desktop.MainWindow = LicenseCenterWindows.CreateUpdatePrompt(
                    invocation,
                    exitCode => desktop.Shutdown(exitCode));
                base.OnFrameworkInitializationCompleted();
                return;
            }

            if (invocation.Mode == LicenseCenterMode.Activation)
            {
                desktop.MainWindow = LicenseCenterWindows.CreateActivation(
                    invocation,
                    exitCode => desktop.Shutdown(exitCode));
                base.OnFrameworkInitializationCompleted();
                return;
            }

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
