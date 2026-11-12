using System.Text.Json;
using BKE.LicensingAgent.Infrastructure;

/// <summary>
/// Real DS catalog wire parsing proof. Never synthesize EITHER when SQL mode
/// is missing, malformed, duplicate, or explicitly LICENSE_KEY-only.
/// </summary>
internal static class AccountActivationModeCatalogCertification
{
    public static void Run()
    {
        int passed = 0;
        void Check(bool good, string message)
        {
            if (!good) throw new InvalidOperationException("FAIL: " + message);
            passed++;
            Console.WriteLine("PASS: activation mode " + message);
        }
        string Item(string mode, bool installable) => JsonSerializer.Serialize(new {
            product_id = "bke-render-dock",
            display_name = "Render Dock",
            summary = "Standalone",
            execution_type = "STANDALONE",
            activation_mode = mode,
            entitled = true,
            installable,
            latest_version = "1.0.0"
        });
        string Root(string item) =>
            "{\"status\":\"ok\",\"account_id\":\"ci-account\",\"products\":[" +
            item + "]}";

        IReadOnlyList<BKE.LicensingAgent.Application.RemoteSoftwareCatalogItem>
            Parse(string json)
        {
            using var data = JsonDocument.Parse(json);
            return SoftwareCatalogRemote.Parse(data.RootElement);
        }
        void Reject(string json, string message)
        {
            bool rejected = false;
            try { _ = Parse(json); }
            catch (InvalidDataException) { rejected = true; }
            Check(rejected, message);
        }

        Check(Parse(Root(Item("ACCOUNT", true))).Single().ActivationMode ==
            "ACCOUNT", "ACCOUNT policy parsed without borrowing key authority");
        Check(Parse(Root(Item("EITHER", true))).Single().ActivationMode ==
            "EITHER", "explicit EITHER policy permits independently checked account path");
        Check(Parse(Root(Item("LICENSE_KEY", false))).Single().ActivationMode ==
            "LICENSE_KEY", "key-only mode remains visible but cannot install via account");

        Reject(Root(Item("AUTO", false)), "unsupported activation mode rejected");
        Reject(Root(Item("EITHER", true).Replace(
            ",\"activation_mode\":\"EITHER\"", "", StringComparison.Ordinal)),
            "missing activation mode does not become EITHER");
        Reject(Root(Item("LICENSE_KEY", true)),
            "key-only account-installability contradiction rejected");
        Reject(Root(Item("EITHER", true).Replace(
            "\"activation_mode\":\"EITHER\"",
            "\"activation_mode\":\"LICENSE_KEY\",\"activation_mode\":\"EITHER\"",
            StringComparison.Ordinal)),
            "duplicate activation-mode property rejected");
        Reject(Root(Item("EITHER", true)).Replace(
            "\"account_id\":\"ci-account\"",
            "\"account_id\":\"other\",\"account_id\":\"ci-account\"",
            StringComparison.Ordinal)),
            "duplicate account identity field rejected");
        Reject(Root(Item("EITHER", true).Replace(
            "\"product_id\":\"bke-render-dock\"",
            "\"product_id\":\"foreign\",\"product_id\":\"bke-render-dock\"",
            StringComparison.Ordinal)),
            "duplicate product identity rejected");
        Reject(Root(Item("EITHER", true).Replace(
            "\"summary\":\"Standalone\"",
            "\"summary\":\"Standalone\",\"untrusted_extra\":true",
            StringComparison.Ordinal)),
            "extra catalog authority field rejected");

        if (passed != 10)
            throw new InvalidOperationException("Incomplete activation mode parsing proof.");
        Console.WriteLine($"DS activation-mode catalog wire certification: {passed}/10 PASS");
    }
}
