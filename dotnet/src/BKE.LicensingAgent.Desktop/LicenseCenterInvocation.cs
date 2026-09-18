using System.Net.Http.Json;
using System.Text.Json;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;

namespace BKE.LicensingAgent.Desktop;

internal enum LicenseCenterMode
{
    Standalone,
    Smoke,
    AgentUpdatePrompt,
    Activation,
    Invalid,
}

internal sealed record LicenseCenterInvocation(
    LicenseCenterMode Mode,
    string? CurrentVersion = null,
    string? LatestVersion = null,
    string? ReleaseNotes = null,
    string? ProductId = null,
    string? ProductVersion = null,
    string? InstallationId = null,
    string? CorrelationId = null,
    string? NotificationCode = null)
{
    internal static LicenseCenterInvocation Parse(IReadOnlyList<string> args)
    {
        var values = new Dictionary<string, string?>(StringComparer.Ordinal);
        var flags = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < args.Count; index++)
        {
            var item = args[index];
            if (!item.StartsWith("--", StringComparison.Ordinal))
            {
                continue;
            }

            if (item is "--smoke" or "--agent-update-prompt")
            {
                flags.Add(item);
                continue;
            }

            if (index + 1 < args.Count && !args[index + 1].StartsWith("--", StringComparison.Ordinal))
            {
                values[item] = args[++index];
            }
        }

        if (flags.Contains("--smoke"))
        {
            return new(LicenseCenterMode.Smoke);
        }

        if (flags.Contains("--agent-update-prompt"))
        {
            if (!values.TryGetValue("--current-version", out var current) ||
                string.IsNullOrWhiteSpace(current) ||
                !values.TryGetValue("--latest-version", out var latest) ||
                string.IsNullOrWhiteSpace(latest))
            {
                return new(LicenseCenterMode.Invalid);
            }
            values.TryGetValue("--release-notes", out var notes);
            return new(LicenseCenterMode.AgentUpdatePrompt, current, latest, notes);
        }

        var hasProductContext = values.ContainsKey("--product-id") ||
                                values.ContainsKey("--product-version") ||
                                values.ContainsKey("--installation-id") ||
                                values.ContainsKey("--correlation-id") ||
                                values.ContainsKey("--action");
        if (!hasProductContext)
        {
            return new(LicenseCenterMode.Standalone);
        }

        if (!values.TryGetValue("--product-id", out var productId) || string.IsNullOrWhiteSpace(productId) ||
            !values.TryGetValue("--product-version", out var productVersion) || string.IsNullOrWhiteSpace(productVersion) ||
            !values.TryGetValue("--installation-id", out var installationId) || string.IsNullOrWhiteSpace(installationId) ||
            !values.TryGetValue("--correlation-id", out var correlationId) || string.IsNullOrWhiteSpace(correlationId) ||
            !values.TryGetValue("--action", out var action) ||
            !string.Equals(action, "activation_required", StringComparison.Ordinal))
        {
            return new(LicenseCenterMode.Invalid);
        }

        values.TryGetValue("--notification-code", out var notificationCode);
        return new(
            LicenseCenterMode.Activation,
            ProductId: productId,
            ProductVersion: productVersion,
            InstallationId: installationId,
            CorrelationId: correlationId,
            NotificationCode: notificationCode);
    }
}

internal static class LicenseCenterWindows
{
    internal static Window CreateUpdatePrompt(LicenseCenterInvocation invocation, Action<int> complete)
    {
        var completed = false;
        var window = Shell("BKE Licensing Agent Update", 520, 320);
        var panel = Panel();

        panel.Children.Add(Heading("Licensing Agent update available"));
        panel.Children.Add(Body(
            $"A newer BKE Licensing Agent is available.\n\nCurrent version: {invocation.CurrentVersion}\nAvailable version: {invocation.LatestVersion}"));

        if (!string.IsNullOrWhiteSpace(invocation.ReleaseNotes))
        {
            panel.Children.Add(Body($"What's new\n{invocation.ReleaseNotes}"));
        }

        var actions = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 10 };
        var update = new Button { Content = "Update Now", Padding = new Thickness(18, 10) };
        var later = new Button { Content = "Later", Padding = new Thickness(18, 10) };

        void Finish(int code)
        {
            if (completed) return;
            completed = true;
            complete(code);
        }

        update.Click += (_, _) => Finish(0);
        later.Click += (_, _) => Finish(2);
        window.Closing += (_, _) => Finish(2);

        actions.Children.Add(update);
        actions.Children.Add(later);
        panel.Children.Add(actions);
        window.Content = panel;
        return window;
    }

    internal static Window CreateActivation(LicenseCenterInvocation invocation, Action<int> complete)
    {
        var completed = false;
        var window = Shell("BKE License Center", 540, 360);
        var panel = Panel();
        var status = new TextBlock
        {
            Text = string.Equals(invocation.NotificationCode, "LICENSE_REQUIRED", StringComparison.Ordinal)
                ? "A license is required. Enter a license key to activate."
                : "Enter the license key for this product.",
            TextWrapping = TextWrapping.Wrap,
        };
        var key = new TextBox
        {
            PlaceholderText = "License key",
            PasswordChar = '•',
            MinWidth = 420,
        };
        var activate = new Button { Content = "Activate License", Padding = new Thickness(18, 10) };
        var cancel = new Button { Content = "Cancel", Padding = new Thickness(18, 10) };

        panel.Children.Add(Heading("BKE License Center"));
        panel.Children.Add(Body($"Activate {invocation.ProductId} version {invocation.ProductVersion}"));
        panel.Children.Add(key);
        panel.Children.Add(status);

        var actions = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 10 };
        actions.Children.Add(activate);
        actions.Children.Add(cancel);
        panel.Children.Add(actions);

        void Finish(int code)
        {
            if (completed) return;
            completed = true;
            complete(code);
        }

        cancel.Click += (_, _) => Finish(2);
        window.Closing += (_, _) => Finish(2);
        activate.Click += async (_, _) =>
        {
            var licenseKey = key.Text?.Trim();
            if (string.IsNullOrWhiteSpace(licenseKey))
            {
                status.Text = "Enter a license key.";
                return;
            }

            activate.IsEnabled = false;
            status.Text = "Activating…";
            try
            {
                using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
                using var response = await client.PostAsJsonAsync(
                    "http://127.0.0.1:43873/v1/activate",
                    new
                    {
                        product_id = invocation.ProductId,
                        version = invocation.ProductVersion,
                        installation_id = invocation.InstallationId,
                        license_key = licenseKey,
                    });
                using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
                if (response.IsSuccessStatusCode &&
                    document.RootElement.TryGetProperty("authorized", out var authorized) &&
                    authorized.ValueKind == JsonValueKind.True)
                {
                    key.Text = string.Empty;
                    status.Text = "Activation successful. Returning to the product…";
                    Finish(0);
                    return;
                }

                var reason = document.RootElement.TryGetProperty("reason", out var reasonNode)
                    ? reasonNode.GetString()
                    : "denied";
                status.Text = $"Activation failed: {reason ?? "denied"}";
            }
            catch
            {
                status.Text = "Activation failed: Licensing Agent unavailable";
            }
            finally
            {
                if (!completed)
                {
                    activate.IsEnabled = true;
                }
            }
        };

        window.Content = panel;
        return window;
    }

    private static Window Shell(string title, double width, double height) => new()
    {
        Title = title,
        Width = width,
        Height = height,
        MinWidth = width,
        MinHeight = height,
        WindowStartupLocation = WindowStartupLocation.CenterScreen,
        Background = Brush.Parse("#080B11"),
    };

    private static StackPanel Panel() => new()
    {
        Margin = new Thickness(28),
        Spacing = 16,
    };

    private static TextBlock Heading(string text) => new()
    {
        Text = text,
        FontSize = 24,
        FontWeight = FontWeight.SemiBold,
        Foreground = Brushes.White,
    };

    private static TextBlock Body(string text) => new()
    {
        Text = text,
        TextWrapping = TextWrapping.Wrap,
        Foreground = Brush.Parse("#A8B8CE"),
    };
}
