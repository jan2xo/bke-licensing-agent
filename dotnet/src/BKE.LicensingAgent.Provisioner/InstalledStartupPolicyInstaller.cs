using System.Net;
using System.Text;
using BKE.LicensingAgent.Infrastructure;

namespace BKE.LicensingAgent.Provisioner;

/// <summary>
/// One-shot PREPRODUCTION-only elevated installed-provisioner operation.
/// No background key signing, browser auth, Host HTTP surface or production
/// network access. Returns no raw attestation or signed policy to stdout.
/// </summary>
internal static class InstalledStartupPolicyInstaller
{
    internal static async Task AcquireAsync(
        string productId, string version, string installationId,
        string allowedUserSid, CancellationToken cancellationToken = default)
    {
        if (Environment.GetEnvironmentVariable(
                "BKE_STANDALONE_STARTUP_POLICY_ACQUISITION_ENABLED") != "1")
            throw new InvalidOperationException("Preproduction policy acquisition disabled.");

        // This performs all existing checks: elevated installed Windows
        // provisioner, explicit nonproduction environment + DS origin, signed
        // privileged target policy and the actual installed executable hash.
        var attestor = StartupMachineAttestor.LoadInstalled();
        var expected = attestor.RequireSignedTarget(
            productId, version, installationId, allowedUserSid);
        var nonproductionUrl = Environment.GetEnvironmentVariable("BKE_PLATFORM_BASE_URL");
        if (!Uri.TryCreate(nonproductionUrl, UriKind.Absolute, out var origin))
            throw new InvalidDataException("Approved preproduction DS origin missing.");
        PreproductionStartupPolicyAcquisition.RequirePreproductionOrigin(origin);

        var issuerKeys = AccountProductLeaseInstalledTrust.LoadForInstalledProvisioner(
            Environment.GetEnvironmentVariable("BKE_ENVIRONMENT") ?? "production");
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var observed = new InstalledStartupPolicyScope(
            expected.ProductId, expected.Version, expected.InstallationId,
            expected.ImagePath, expected.ImageSha256, expected.UserSid);

        // Sign only AFTER all local installation/trust prerequisites pass, so
        // no fresh machine attestation leaves an untrusted environment.
        var freshSigned = attestor.IssueVerified(expected, DateTimeOffset.UtcNow);
        using var handler = new HttpClientHandler {
            AllowAutoRedirect = false,
            UseCookies = false,
            UseProxy = false,
            UseDefaultCredentials = false,
            AutomaticDecompression = DecompressionMethods.None,
        };
        using var client = new HttpClient(handler) {
            Timeout = TimeSpan.FromSeconds(15),
        };
        var verifiedPolicy = await PreproductionStartupPolicyAcquisition.AcquireVerifiedAsync(
            client, origin, freshSigned, observed, issuerKeys,
            programFiles, DateTimeOffset.UtcNow, cancellationToken);

        // The install path is determined by protected Agent code, never by
        // a network response. Host still independently reads and verifies the
        // signed installed bundle on its next explicitly controlled restart.
        InstallVerified(verifiedPolicy, observed, programFiles);
    }

    private static void RequireOrdinaryDirectory(string path)
    {
        var dir = new DirectoryInfo(path);
        if (!dir.Exists || (dir.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("Protected startup directory unavailable or redirected.");
    }

    internal static void InstallVerified(
        string policyEnvelope, InstalledStartupPolicyScope observed, string programFiles)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Windows installed policy only.");
        var agentRoot = Path.Combine(programFiles,
            "BKE Digital Solutions", "Licensing Agent");
        var provisioning = Path.Combine(agentRoot, "provisioning");
        var trustRoot = Path.Combine(agentRoot, "trust");
        var policyDir = Path.Combine(trustRoot, "standalone-startup-policies");
        foreach (var path in new[] { agentRoot, provisioning, trustRoot })
            RequireOrdinaryDirectory(path);
        if (!string.Equals(Path.TrimEndingDirectorySeparator(
                Path.GetFullPath(AppContext.BaseDirectory)),
                Path.TrimEndingDirectorySeparator(Path.GetFullPath(provisioning)),
                StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Uninstalled provisioner cannot install policy.");
        // No accidental duplicate/ambiguous authority for this product.
        var existing = Directory.Exists(policyDir);
        if (!existing) {
            Directory.CreateDirectory(policyDir);
            StartupMachineAttestor.Protect(policyDir, directory: true);
        }
        RequireOrdinaryDirectory(policyDir);

        var productId = observed.ProductId;
        if (productId.Length > 128 ||
            !System.Text.RegularExpressions.Regex.IsMatch(productId,
                "^[a-z0-9]+(?:-[a-z0-9]+)*$"))
            throw new InvalidDataException("Installed startup product ID invalid.");
        if (Directory.EnumerateFiles(policyDir, productId + "-*.json",
                SearchOption.TopDirectoryOnly).Any())
            throw new InvalidDataException("Installed startup policy already exists for product.");

        // Refuse reparse-point targets, never overwrite a prior policy.
        var target = Path.Combine(policyDir,
            productId + "-" + observed.InstallationId + ".json");
        if (File.Exists(target))
            throw new InvalidDataException("Installed startup policy already exists.");
        var temporary = Path.Combine(policyDir,
            ".startup-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            var data = new UTF8Encoding(false, true).GetBytes(policyEnvelope);
            try {
                if (data.Length is < 100 or > 16384)
                    throw new InvalidDataException("Installed startup policy size invalid.");
                using (var stream = new FileStream(temporary, FileMode.CreateNew,
                    FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
                {
                    stream.Write(data);
                    stream.Flush(flushToDisk: true);
                }
            }
            finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(data); }
            StartupMachineAttestor.Protect(temporary, directory: false);
            File.Move(temporary, target, overwrite: false);
            StartupMachineAttestor.Protect(target, directory: false);
        }
        catch
        {
            if (File.Exists(temporary)) File.Delete(temporary);
            // The operation must fail closed, not leave an unprotected active
            // signed policy if final ACL enforcement fails.
            if (File.Exists(target)) File.Delete(target);
            throw;
        }
    }
}
