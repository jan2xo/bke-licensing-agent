using System.Security.Cryptography;
using System.Text.Json;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;
using BKE.LicensingAgent.Infrastructure;
using Org.BouncyCastle.Crypto.Parameters;

/// <summary>
/// Agent OPEN gate and installer-owned DS public issuer trust certification.
/// Source-only; no real customer keys, installed binaries or production DS.
/// </summary>
internal static class AccountProductOpenGateCertification
{
    public static async Task RunAsync()
    {
        var passed = 0;
        void Check(bool condition, string description)
        {
            if (!condition) throw new InvalidOperationException(
                "FAIL: account-product installed gate " + description);
            passed++;
            Console.WriteLine("PASS: account-product installed gate " + description);
        }

        var item = new SoftwareCatalogItem(
            "bke-render-dock", "Render Dock", "Standalone", "STANDALONE",
            true, true, "INSTALLED", "1.0.2", "1.0.2");
        var catalog = new Catalog(new SoftwareCatalogResponse(
            LocalAgentContract.SoftwareCatalogCapabilityId,
            LocalAgentContract.SoftwareCatalogContractVersion,
            "READY", [item], null));
        var request = new SoftwareOpenRequest("gate-contract", "bke-render-dock");

        var allow = new Gate(true);
        var approvedLauncher = new Launcher();
        var approved = await new SoftwareOpenService(
            catalog, approvedLauncher, allow).OpenAsync(request, CancellationToken.None);
        Check(approved.Status == "STARTED" && allow.Calls == 1 &&
            approvedLauncher.Calls == 1, "fresh verified JWS required before opening");

        var deny = new Gate(false);
        var deniedLauncher = new Launcher();
        var denied = await new SoftwareOpenService(
            catalog, deniedLauncher, deny).OpenAsync(request, CancellationToken.None);
        Check(denied.Status == "FAILED" &&
            denied.Error?.Code == "ACCOUNT_LEASE_UNAVAILABLE" &&
            deny.Calls == 1 && deniedLauncher.Calls == 0,
            "failed signed lease never starts executable");

        var throwGate = new Gate(true) { Throw = true };
        var failureLauncher = new Launcher();
        var unavailable = await new SoftwareOpenService(
            catalog, failureLauncher, throwGate).OpenAsync(request, CancellationToken.None);
        Check(unavailable.Error?.Code == "ACCOUNT_LEASE_UNAVAILABLE" &&
            failureLauncher.Calls == 0,
            "exception at signed authority never falls back to catalog-only open");

        var legacyLauncher = new Launcher();
        var legacy = await new SoftwareOpenService(
            catalog, legacyLauncher).OpenAsync(request, CancellationToken.None);
        Check(legacy.Status == "STARTED" && legacyLauncher.Calls == 1,
            "default-off preserves existing independent license-key workflow");

        var wrongEntitlement = new Catalog(new SoftwareCatalogResponse(
            LocalAgentContract.SoftwareCatalogCapabilityId,
            LocalAgentContract.SoftwareCatalogContractVersion,
            "READY", [item with { Entitled = false,
                State = "INSTALLED_NOT_ENTITLED" }], null));
        var wouldAuthorize = new Gate(true);
        var noEntitlementLaunch = new Launcher();
        var noEntitlement = await new SoftwareOpenService(
            wrongEntitlement, noEntitlementLaunch, wouldAuthorize)
            .OpenAsync(request, CancellationToken.None);
        Check(noEntitlement.Error?.Code == "NOT_ENTITLED" &&
            wouldAuthorize.Calls == 0 && noEntitlementLaunch.Calls == 0,
            "signed JWS cannot override DS catalog entitlement denial");

        var plugin = new Catalog(new SoftwareCatalogResponse(
            LocalAgentContract.SoftwareCatalogCapabilityId,
            LocalAgentContract.SoftwareCatalogContractVersion,
            "READY", [item with { ExecutionType = "LAUNCHER_PLUGIN" }], null));
        var pluginGate = new Gate(true);
        var pluginLaunch = new Launcher();
        var unsupported = await new SoftwareOpenService(
            plugin, pluginLaunch, pluginGate)
            .OpenAsync(request, CancellationToken.None);
        Check(unsupported.Error?.Code == "UNSUPPORTED_EXECUTION_TYPE" &&
            pluginGate.Calls == 0 && pluginLaunch.Calls == 0,
            "standalone lease cannot bypass plugin execution type");

        var crypto = new Ed25519PrivateKeyParameters(
            RandomNumberGenerator.GetBytes(32), 0);
        var publicDer = Convert.FromHexString("302A300506032B6570032100")
            .Concat(crypto.GeneratePublicKey().GetEncoded()).ToArray();
        string pem = "-----BEGIN PUBLIC KEY-----\n" +
            Convert.ToBase64String(publicDer) + "\n-----END PUBLIC KEY-----\n";
        string Bundle(string producer, string algorithmState, string keyPem,
            int copies = 1) => JsonSerializer.Serialize(new {
                schema = AccountProductLeaseInstalledTrust.BundleSchema,
                issuer_source_sha = producer,
                library_archive_sha256 =
                    AccountProductLeaseInstalledTrust.ExactLibraryArchiveSha256,
                keys = Enumerable.Range(0, copies).Select(i => new {
                    kid = "preproduction-" + i,
                    public_key_pem = keyPem,
                    state = algorithmState
                }).ToArray()
            });

        var good = Bundle(AccountProductLeaseInstalledTrust.ExactIssuerSourceSha,
            "ACTIVE", pem);
        var parsed = AccountProductLeaseInstalledTrust.Parse(good);
        Check(parsed.Count == 1 && parsed["preproduction-0"].State == "ACTIVE" &&
            parsed["preproduction-0"].PublicKeyPem == pem,
            "installed public-only issuer bundle parses with pinned provenance");

        void Reject(string value, string description)
        {
            bool rejected = false;
            try { _ = AccountProductLeaseInstalledTrust.Parse(value); }
            catch (InvalidDataException) { rejected = true; }
            Check(rejected, description);
        }
        Reject(Bundle(new string('0', 40), "ACTIVE", pem),
            "wrong DS source provenance rejected");
        Reject(Bundle(AccountProductLeaseInstalledTrust.ExactIssuerSourceSha,
            "VERIFY_ONLY", pem), "missing ACTIVE signer rejected");
        Reject(Bundle(AccountProductLeaseInstalledTrust.ExactIssuerSourceSha,
            "ACTIVE", pem, 2), "ambiguous ACTIVE signer rejected");
        Reject(Bundle(AccountProductLeaseInstalledTrust.ExactIssuerSourceSha,
            "REVOKED", pem), "revoked issuer cannot be active");
        Reject(Bundle(AccountProductLeaseInstalledTrust.ExactIssuerSourceSha,
            "ACTIVE", "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"),
            "fake non-Ed25519 key rejected");
        Reject(good.Replace("\"schema\":", "\"schema\":\"duplicate\",\"schema\":",
            StringComparison.Ordinal), "duplicate JSON property rejected");
        Reject(good.Replace("\"public_key_pem\":", "\"private_key_pem\":",
            StringComparison.Ordinal), "private-key field cannot substitute public trust");
        Reject(good.Replace("\"library_archive_sha256\":\"" +
            AccountProductLeaseInstalledTrust.ExactLibraryArchiveSha256,
            "\"library_archive_sha256\":\"" + new string('0', 64),
            StringComparison.Ordinal), "changed licensing package provenance rejected");

        bool productionRejected = false;
        try { _ = AccountProductLeaseInstalledTrust.LoadInstalled("production"); }
        catch (InvalidOperationException) { productionRejected = true; }
        Check(productionRejected, "production cannot load account-product issuer trust");

        var host = File.ReadAllText(Path.Combine(
            "dotnet", "src", "BKE.LicensingAgent.Host", "Program.cs"));
        var installer = File.ReadAllText(Path.Combine(
            "packaging", "windows", "bke-licensing-agent.iss"));
        Check(host.Contains("BKE_ACCOUNT_PRODUCT_LEASE_GATE_ENABLED",
                StringComparison.Ordinal) &&
            host.Contains("AgentRuntimeEnvironmentLoader.ProductionEnvironment",
                StringComparison.Ordinal) &&
            host.Contains("AccountProductLeaseInstalledTrust.LoadInstalled",
                StringComparison.Ordinal) &&
            host.Contains("GetRequiredService<IAccountProductOpenLeaseGate>",
                StringComparison.Ordinal),
            "Host bootstrap rejects production gate and composes installed trust");
        Check(installer.Contains(
                "account-product-lease-keys\\issuers.json",
                StringComparison.Ordinal) &&
            installer.Contains("skipifsourcedoesntexist", StringComparison.Ordinal),
            "privileged installer owns optional public-only issuer payload");

        Console.WriteLine($"Account-product installed OPEN gate certification: {passed}/17 PASS");
    }

    private sealed class Catalog(SoftwareCatalogResponse response)
        : ISoftwareCatalogService
    {
        public Task<SoftwareCatalogResponse> GetAsync(
            SoftwareCatalogRequest request,
            CancellationToken cancellationToken) => Task.FromResult(response);
    }
    private sealed class Launcher : ILocalProductLauncher
    {
        public int Calls { get; private set; }
        public Task<LocalProductLaunchResult> OpenAsync(
            string productId, CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(new LocalProductLaunchResult(
                "STARTED", "started", false));
        }
    }
    private sealed class Gate(bool allowed) : IAccountProductOpenLeaseGate
    {
        public int Calls { get; private set; }
        public bool Throw { get; init; }
        public Task<bool> VerifyFreshOpenAsync(
            string productId, CancellationToken cancellationToken)
        {
            Calls++;
            if (Throw) throw new InvalidDataException("DS unavailable");
            return Task.FromResult(allowed);
        }
    }
}
