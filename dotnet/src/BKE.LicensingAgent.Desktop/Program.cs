using Avalonia;

namespace BKE.LicensingAgent.Desktop;

internal static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        if (args.Length == 1 && string.Equals(args[0], "--smoke", StringComparison.Ordinal))
        {
            Console.WriteLine("BKE License Center .NET smoke: entrypoint OK");
            return 0;
        }

        return BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
    }

    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .LogToTrace();
}
