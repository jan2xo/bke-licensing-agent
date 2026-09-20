using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using BKE.LicensingAgent.Storage;

namespace BKE.LicensingAgent.Updater;

internal static class Program
{
    private static readonly HashSet<string> RequestFields = new(StringComparer.Ordinal)
    {
        "schema","request_id","product_id","current_version","target_version","platform","architecture",
        "install_root","entry_point","artifact_sha256","artifact_size","update_policy_sha256",
        "target_policy_sha256","issued_at","expires_at","signing_key_id","algorithm","signature",
    };

    private static readonly HashSet<string> ProvisionRequestFields = new(StringComparer.Ordinal)
    {
        "schema","request_id","product_id","target_version","platform","architecture",
        "install_root","entry_point","artifact_sha256","artifact_size","target_policy_sha256",
        "issued_at","expires_at","signing_key_id","algorithm","signature",
    };

    private static readonly HashSet<string> UpdateFields = new(StringComparer.Ordinal)
    {
        "schema","product_id","current_version","latest_version","minimum_supported_version","channel",
        "platform","architecture","release_id","artifact_id","artifact_sha256","artifact_size","content_type",
        "published_at","issued_at","revision","signing_key_id","algorithm","signature",
    };

    private static readonly HashSet<string> TargetFields = new(StringComparer.Ordinal)
    {
        "schema","policy_id","revision","product_id","platform","architecture","install_root","entry_point",
        "signing_key_id","algorithm","signature",
    };

    private static readonly HashSet<string> TrustFields = new(StringComparer.Ordinal)
    {
        "schema","agent_keys","digital_keys","target_keys","approved_install_roots","expected_channel",
        "last_update_policy_revision","last_target_policy_revision",
    };

    private static readonly HashSet<string> ManifestRequiredFields = new(StringComparer.Ordinal)
    {
        "schemaVersion","productId","displayName","version","entryPoint",
        "updateChannel","minimumAgentVersion","platform","architecture",
    };

    private static readonly HashSet<string> ManifestAllowedFields = new(
        ManifestRequiredFields.Concat(["publisher", "icon"]),
        StringComparer.Ordinal);

    private static readonly Regex HashPattern = new("^[a-f0-9]{64}$", RegexOptions.CultureInvariant);
    private static readonly Regex RequestIdPattern = new("^[A-Za-z0-9_.-]{16,128}$", RegexOptions.CultureInvariant);
    private static readonly Regex PolicyIdPattern = new("^[A-Za-z0-9_.-]{8,128}$", RegexOptions.CultureInvariant);
    private static readonly Regex ProductIdPattern = new("^[a-z0-9-]+$", RegexOptions.CultureInvariant);

    public static int Main(string[] args)
    {
        try
        {
            var options = Parse(args);
            Execute(options);
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"BKE privileged update failed: {exception.Message}");
            return 1;
        }
    }

    private static void Execute(Options options)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Windows privileged updater must run on Windows");

        var runtimeRoot = ResolveDirectory(options.RuntimeRoot, "runtime_root");
        var requestPath = ResolveUnder(runtimeRoot, options.Request, "request");
        var targetPath = ResolveUnder(runtimeRoot, options.TargetPolicy, "target_policy");
        var artifactPath = ResolveUnder(runtimeRoot, options.Artifact, "artifact");
        var stagedRoot = ResolveUnder(runtimeRoot, options.StagedRoot, "staged_root");
        var transactionRoot = options.TransactionRoot is null
            ? null
            : ResolveUnder(runtimeRoot, options.TransactionRoot, "transaction_root", mustExist: false);

        var trust = LoadTrust(runtimeRoot, requireDigitalKeys: options.Mode == OperationMode.Update);
        using var requestDocument = JsonDocument.Parse(File.ReadAllText(requestPath));
        using var targetDocument = JsonDocument.Parse(File.ReadAllText(targetPath));
        var target = VerifyTarget(targetDocument.RootElement, trust);

        if (options.Mode == OperationMode.Update)
        {
            if (options.UpdatePolicy is null || options.BackupRoot is null)
                throw new InvalidDataException("update authority inputs are incomplete");

            var updatePath = ResolveUnder(runtimeRoot, options.UpdatePolicy, "update_policy");
            var backupRoot = ResolveUnder(runtimeRoot, options.BackupRoot, "backup_root", mustExist: false);
            using var updateDocument = JsonDocument.Parse(File.ReadAllText(updatePath));

            var request = VerifyRequest(requestDocument.RootElement, trust, runtimeRoot);
            var update = VerifyUpdate(updateDocument.RootElement, trust, request);
            ComposeAuthority(
                request,
                update,
                target,
                artifactPath,
                updateDocument.RootElement,
                targetDocument.RootElement);
            var plan = ComposePlan(
                target,
                stagedRoot,
                backupRoot,
                transactionRoot,
                options.TransactionId,
                options.LaunchArgs,
                options.ReadyMarker,
                options.StartupTimeout);
            ReplaceAndLaunch(plan, options.WaitPid);
            return;
        }

        var provisionRequest = VerifyProvisionRequest(
            requestDocument.RootElement,
            trust,
            runtimeRoot);
        ComposeProvisionAuthority(
            provisionRequest,
            target,
            artifactPath,
            targetDocument.RootElement);
        var provisionPlan = ComposeProvisionPlan(
            provisionRequest,
            target,
            runtimeRoot,
            stagedRoot,
            transactionRoot,
            options.TransactionId);
        Provision(provisionPlan);
    }

    private static Options Parse(string[] args)
    {
        var values = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        OperationMode? mode = null;

        for (var index = 0; index < args.Length; index++)
        {
            var current = args[index];
            if (current is "--privileged-update" or "--privileged-provision")
            {
                var requested = current == "--privileged-update"
                    ? OperationMode.Update
                    : OperationMode.Provision;
                if (mode is not null)
                    throw new InvalidDataException("exactly one privileged operation mode is required");
                mode = requested;
                continue;
            }

            if (!current.StartsWith("--", StringComparison.Ordinal) || index + 1 >= args.Length)
                throw new InvalidDataException($"invalid privileged updater argument: {current}");
            var value = args[++index];
            if (!values.TryGetValue(current, out var list))
            {
                list = [];
                values[current] = list;
            }
            list.Add(value);
        }

        if (mode is null)
            throw new InvalidDataException("--privileged-update or --privileged-provision is required");

        string Required(string name) =>
            values.TryGetValue(name, out var list) && list.Count == 1 && !string.IsNullOrWhiteSpace(list[0])
                ? list[0]
                : throw new InvalidDataException($"{name} is required");

        string? Optional(string name) =>
            values.TryGetValue(name, out var list) && list.Count == 1 ? list[0] : null;

        int? waitPid = null;
        if (Optional("--wait-pid") is { } wait)
        {
            if (!int.TryParse(wait, out var parsed) || parsed <= 0)
                throw new InvalidDataException("wait_pid must be positive");
            waitPid = parsed;
        }

        var timeout = 10d;
        if (Optional("--startup-timeout") is { } timeoutRaw &&
            (!double.TryParse(
                timeoutRaw,
                System.Globalization.NumberStyles.Float,
                System.Globalization.CultureInfo.InvariantCulture,
                out timeout) || timeout <= 0))
        {
            throw new InvalidDataException("startup_timeout must be positive");
        }

        var launchArgs = values.TryGetValue("--launch-arg", out var launch)
            ? launch.ToArray()
            : [];
        var readyMarker = Optional("--ready-marker");
        var updatePolicy = Optional("--update-policy");
        var backupRoot = Optional("--backup-root");

        if (mode == OperationMode.Update)
        {
            updatePolicy ??= Required("--update-policy");
            backupRoot ??= Required("--backup-root");
        }
        else if (updatePolicy is not null ||
                 backupRoot is not null ||
                 waitPid is not null ||
                 launchArgs.Length != 0 ||
                 readyMarker is not null ||
                 Optional("--startup-timeout") is not null)
        {
            throw new InvalidDataException(
                "first-install provisioning does not accept update, backup, wait, or launch arguments");
        }

        return new Options(
            mode.Value,
            Required("--runtime-root"),
            Required("--request"),
            updatePolicy,
            Required("--target-policy"),
            Required("--artifact"),
            Required("--staged-root"),
            backupRoot,
            Optional("--transaction-root"),
            Optional("--transaction-id"),
            waitPid,
            launchArgs,
            readyMarker,
            timeout);
    }

    private static TrustedRuntime LoadTrust(string runtimeRoot, bool requireDigitalKeys)
    {
        var trustPath = Path.Combine(runtimeRoot, "trust.json");
        using var document = JsonDocument.Parse(File.ReadAllText(trustPath));
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object ||
            !root.EnumerateObject().Select(p => p.Name).ToHashSet(StringComparer.Ordinal).SetEquals(TrustFields) ||
            RequiredString(root, "schema") != "bke.updater-trust.v1")
        {
            throw new InvalidDataException("unsupported trusted runtime configuration");
        }

        var approvedNode = root.GetProperty("approved_install_roots");
        if (approvedNode.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("invalid approved_install_roots");
        var approved = approvedNode.EnumerateArray().Select(item => item.GetString())
            .Where(item => !string.IsNullOrWhiteSpace(item)).Cast<string>().Select(Path.GetFullPath).ToArray();
        if (approved.Length == 0 || approved.Length != approvedNode.GetArrayLength())
            throw new InvalidDataException("invalid approved_install_roots");

        return new TrustedRuntime(
            DecodeKeys(root.GetProperty("agent_keys"), "agent_keys"),
            DecodeKeys(root.GetProperty("digital_keys"), "digital_keys", allowEmpty: !requireDigitalKeys),
            DecodeKeys(root.GetProperty("target_keys"), "target_keys"),
            approved,
            RequiredString(root, "expected_channel"),
            OptionalRevision(root, "last_update_policy_revision"),
            OptionalRevision(root, "last_target_policy_revision"));
    }

    private static VerifiedRequest VerifyRequest(JsonElement root, TrustedRuntime trust, string runtimeRoot)
    {
        RequireExact(root, RequestFields, "privileged request");
        if (RequiredString(root, "schema") != "bke.privileged-update-request.v1" ||
            RequiredString(root, "algorithm") != "Ed25519")
            throw new InvalidDataException("unsupported privileged request contract");

        var requestId = RequiredString(root, "request_id");
        if (!RequestIdPattern.IsMatch(requestId)) throw new InvalidDataException("invalid request_id");

        var artifactHash = RequiredHash(root, "artifact_sha256");
        var updateHash = RequiredHash(root, "update_policy_sha256");
        var targetHash = RequiredHash(root, "target_policy_sha256");
        var artifactSize = RequiredLong(root, "artifact_size");
        if (artifactSize < 0) throw new InvalidDataException("invalid artifact_size");

        var issued = RequiredTime(root, "issued_at");
        var expires = RequiredTime(root, "expires_at");
        var lifetime = expires - issued;
        if (lifetime <= TimeSpan.Zero || lifetime > TimeSpan.FromMinutes(5))
            throw new InvalidDataException("invalid request lifetime");
        var now = DateTimeOffset.UtcNow;
        if (issued - now > TimeSpan.FromSeconds(30)) throw new InvalidDataException("request issued in the future");
        if (now >= expires) throw new InvalidDataException("privileged request expired");

        var keyId = RequiredString(root, "signing_key_id");
        if (!trust.AgentKeys.TryGetValue(keyId, out var key))
            throw new InvalidDataException("unknown Agent signing key");
        VerifySignature(root, key, "invalid privileged request signature");

        ConsumeReplay(runtimeRoot, requestId);

        return new VerifiedRequest(
            requestId,
            RequiredString(root, "product_id"),
            RequiredString(root, "current_version"),
            RequiredString(root, "target_version"),
            RequiredString(root, "platform"),
            RequiredString(root, "architecture"),
            Path.GetFullPath(RequiredString(root, "install_root")),
            RequiredRelativePath(root, "entry_point"),
            artifactHash,
            artifactSize,
            updateHash,
            targetHash);
    }

    private static VerifiedProvisionRequest VerifyProvisionRequest(
        JsonElement root,
        TrustedRuntime trust,
        string runtimeRoot)
    {
        RequireExact(root, ProvisionRequestFields, "privileged provision request");
        if (RequiredString(root, "schema") != "bke.privileged-provision-request.v1" ||
            RequiredString(root, "algorithm") != "Ed25519")
        {
            throw new InvalidDataException("unsupported privileged provision request contract");
        }

        var requestId = RequiredString(root, "request_id");
        if (!RequestIdPattern.IsMatch(requestId))
            throw new InvalidDataException("invalid request_id");

        var targetVersion = RequiredString(root, "target_version");
        _ = SemanticVersion.Parse(targetVersion);

        var artifactHash = RequiredHash(root, "artifact_sha256");
        var targetHash = RequiredHash(root, "target_policy_sha256");
        var artifactSize = RequiredLong(root, "artifact_size");
        if (artifactSize < 0)
            throw new InvalidDataException("invalid artifact_size");

        var issued = RequiredTime(root, "issued_at");
        var expires = RequiredTime(root, "expires_at");
        var lifetime = expires - issued;
        if (lifetime <= TimeSpan.Zero || lifetime > TimeSpan.FromMinutes(5))
            throw new InvalidDataException("invalid request lifetime");

        var now = DateTimeOffset.UtcNow;
        if (issued - now > TimeSpan.FromSeconds(30))
            throw new InvalidDataException("request issued in the future");
        if (now >= expires)
            throw new InvalidDataException("privileged provision request expired");

        var keyId = RequiredString(root, "signing_key_id");
        if (!trust.AgentKeys.TryGetValue(keyId, out var key))
            throw new InvalidDataException("unknown Agent signing key");
        VerifySignature(root, key, "invalid privileged provision request signature");
        ConsumeReplay(runtimeRoot, requestId);

        return new VerifiedProvisionRequest(
            requestId,
            RequiredString(root, "product_id"),
            targetVersion,
            RequiredString(root, "platform"),
            RequiredString(root, "architecture"),
            Path.GetFullPath(RequiredString(root, "install_root")),
            RequiredRelativePath(root, "entry_point"),
            artifactHash,
            artifactSize,
            targetHash);
    }

    private static VerifiedUpdate VerifyUpdate(JsonElement root, TrustedRuntime trust, VerifiedRequest request)
    {
        RequireExact(root, UpdateFields, "update policy");
        if (RequiredString(root, "schema") != "bke.update-policy.v1" ||
            RequiredString(root, "algorithm") != "Ed25519")
            throw new InvalidDataException("unsupported update policy contract");

        if (RequiredString(root, "product_id") != request.ProductId) throw new InvalidDataException("product_id mismatch");
        if (RequiredString(root, "platform") != request.Platform) throw new InvalidDataException("platform mismatch");
        if (RequiredString(root, "architecture") != request.Architecture) throw new InvalidDataException("architecture mismatch");
        if (RequiredString(root, "channel") != trust.ExpectedChannel) throw new InvalidDataException("channel mismatch");

        var current = SemanticVersion.Parse(RequiredString(root, "current_version"));
        var latest = SemanticVersion.Parse(RequiredString(root, "latest_version"));
        var minimum = SemanticVersion.Parse(RequiredString(root, "minimum_supported_version"));
        if (minimum.CompareTo(latest) > 0) throw new InvalidDataException("minimum version exceeds latest version");
        _ = current;

        var revision = RequiredInt(root, "revision");
        if (revision < 0) throw new InvalidDataException("invalid policy revision");
        if (trust.LastUpdateRevision is not null && revision <= trust.LastUpdateRevision)
            throw new InvalidDataException("stale policy");

        var keyId = RequiredString(root, "signing_key_id");
        if (!trust.DigitalKeys.TryGetValue(keyId, out var key))
            throw new InvalidDataException("unknown signing key");
        VerifySignature(root, key, "invalid policy signature");

        return new VerifiedUpdate(
            RequiredString(root, "product_id"),
            RequiredString(root, "current_version"),
            RequiredString(root, "latest_version"),
            RequiredString(root, "platform"),
            RequiredString(root, "architecture"),
            RequiredHash(root, "artifact_sha256"),
            RequiredLong(root, "artifact_size"));
    }

    private static VerifiedTarget VerifyTarget(JsonElement root, TrustedRuntime trust)
    {
        RequireExact(root, TargetFields, "target policy");
        if (RequiredString(root, "schema") != "bke.install-target-policy.v1" ||
            RequiredString(root, "algorithm") != "Ed25519")
            throw new InvalidDataException("unsupported target policy contract");

        var policyId = RequiredString(root, "policy_id");
        if (!PolicyIdPattern.IsMatch(policyId)) throw new InvalidDataException("invalid policy_id");
        var revision = RequiredInt(root, "revision");
        if (revision < 1) throw new InvalidDataException("invalid revision");
        if (trust.LastTargetRevision is not null && revision <= trust.LastTargetRevision)
            throw new InvalidDataException("stale target policy");
        if (RequiredString(root, "platform") != "windows")
            throw new InvalidDataException("target policy is not for Windows");

        var installRoot = Path.GetFullPath(RequiredString(root, "install_root"));
        if (!trust.ApprovedRoots.Any(rootPath => IsUnder(rootPath, installRoot)))
            throw new InvalidDataException("install root is outside approved BKE roots");

        var entryPoint = RequiredRelativePath(root, "entry_point");
        var executable = Path.GetFullPath(Path.Combine(installRoot, entryPoint));
        if (!IsUnder(installRoot, executable))
            throw new InvalidDataException("entry point escapes install root");

        var keyId = RequiredString(root, "signing_key_id");
        if (!trust.TargetKeys.TryGetValue(keyId, out var key))
            throw new InvalidDataException("unknown BKE signing key");
        VerifySignature(root, key, "invalid target policy signature");

        return new VerifiedTarget(
            RequiredString(root, "product_id"),
            RequiredString(root, "platform"),
            RequiredString(root, "architecture"),
            installRoot,
            entryPoint,
            Sha256(Canonical(root)));
    }

    private static void ComposeAuthority(
        VerifiedRequest request,
        VerifiedUpdate update,
        VerifiedTarget target,
        string artifactPath,
        JsonElement updateDocument,
        JsonElement targetDocument)
    {
        if (request.ProductId != update.ProductId || request.ProductId != target.ProductId)
            throw new InvalidDataException("product identity mismatch");
        if (request.CurrentVersion != update.CurrentVersion)
            throw new InvalidDataException("current version mismatch");
        if (request.TargetVersion != update.LatestVersion)
            throw new InvalidDataException("target version mismatch");
        if (request.Platform != update.Platform || request.Platform != target.Platform)
            throw new InvalidDataException("platform mismatch");
        if (request.Architecture != update.Architecture || request.Architecture != target.Architecture)
            throw new InvalidDataException("architecture mismatch");
        if (!PathEquals(request.InstallRoot, target.InstallRoot))
            throw new InvalidDataException("install root mismatch");
        if (!string.Equals(request.EntryPoint, target.EntryPoint, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("entry point mismatch");
        if (!string.Equals(request.ArtifactSha256, update.ArtifactSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("artifact hash mismatch");
        if (request.ArtifactSize != update.ArtifactSize)
            throw new InvalidDataException("artifact size mismatch");
        if (request.UpdatePolicySha256 != Sha256(Canonical(updateDocument)))
            throw new InvalidDataException("update policy hash mismatch");
        if (request.TargetPolicySha256 != Sha256(Canonical(targetDocument)))
            throw new InvalidDataException("target policy hash mismatch");

        var info = new FileInfo(artifactPath);
        if (!info.Exists || info.Length != request.ArtifactSize)
            throw new InvalidDataException("artifact size mismatch");
        using var stream = File.OpenRead(artifactPath);
        var digest = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
        if (!string.Equals(digest, request.ArtifactSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("artifact hash mismatch");
    }

    private static void ComposeProvisionAuthority(
        VerifiedProvisionRequest request,
        VerifiedTarget target,
        string artifactPath,
        JsonElement targetDocument)
    {
        if (request.ProductId != target.ProductId)
            throw new InvalidDataException("product identity mismatch");
        if (request.Platform != target.Platform)
            throw new InvalidDataException("platform mismatch");
        if (request.Architecture != target.Architecture)
            throw new InvalidDataException("architecture mismatch");
        if (!PathEquals(request.InstallRoot, target.InstallRoot))
            throw new InvalidDataException("install root mismatch");
        if (!string.Equals(request.EntryPoint, target.EntryPoint, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("entry point mismatch");
        if (request.TargetPolicySha256 != Sha256(Canonical(targetDocument)))
            throw new InvalidDataException("target policy hash mismatch");

        var info = new FileInfo(artifactPath);
        if (!info.Exists || info.Length != request.ArtifactSize)
            throw new InvalidDataException("artifact size mismatch");
        using var stream = File.OpenRead(artifactPath);
        var digest = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
        if (!string.Equals(digest, request.ArtifactSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("artifact hash mismatch");
    }

    private static ProvisionPlan ComposeProvisionPlan(
        VerifiedProvisionRequest request,
        VerifiedTarget target,
        string runtimeRoot,
        string stagedRoot,
        string? transactionRoot,
        string? transactionId)
    {
        var installRoot = Path.GetFullPath(target.InstallRoot);
        var stage = Path.GetFullPath(stagedRoot);

        if (Directory.Exists(installRoot) || File.Exists(installRoot))
            throw new InvalidDataException("first install refused because the target already exists");
        if (PathEquals(installRoot, stage) || IsUnder(installRoot, stage) || IsUnder(stage, installRoot))
            throw new InvalidDataException("helper roots overlap");

        var stagedExecutable = Path.GetFullPath(Path.Combine(stage, target.EntryPoint));
        if (!IsUnder(stage, stagedExecutable) || !File.Exists(stagedExecutable))
            throw new InvalidDataException("authorized staged executable is missing");

        var executable = Path.GetFullPath(Path.Combine(installRoot, target.EntryPoint));
        if (!IsUnder(installRoot, executable))
            throw new InvalidDataException("authorized entry point escapes install root");

        return new ProvisionPlan(
            ResolveAgentDataRoot(runtimeRoot),
            request.ProductId,
            request.Platform,
            request.Architecture,
            installRoot,
            stage,
            executable,
            target.EntryPoint,
            request.TargetVersion,
            transactionRoot,
            transactionId);
    }

    private static void Provision(ProvisionPlan plan)
    {
        if (Directory.Exists(plan.InstallRoot) || File.Exists(plan.InstallRoot))
            throw new InvalidDataException("first install refused because the target already exists");

        var parent = Path.GetDirectoryName(plan.InstallRoot)
            ?? throw new InvalidDataException("install root has no parent");
        Directory.CreateDirectory(parent);

        var candidate = plan.InstallRoot + ".bke-install-" + Guid.NewGuid().ToString("N");
        var moved = false;
        try
        {
            CopyDirectory(plan.StagedRoot, candidate);
            var relativeEntry = Path.GetRelativePath(plan.InstallRoot, plan.Executable);
            var candidateExecutable = Path.GetFullPath(Path.Combine(candidate, relativeEntry));
            if (!IsUnder(candidate, candidateExecutable) || !File.Exists(candidateExecutable))
                throw new InvalidDataException("provisioned candidate is missing its authorized entry point");

            Directory.Move(candidate, plan.InstallRoot);
            moved = true;

            if (!File.Exists(plan.Executable))
                throw new InvalidDataException("installed entry point is missing after commit");

            RegisterInstalledProduct(plan);
            WriteProvisionTransaction(plan, "COMMITTED", null);
        }
        catch (Exception exception)
        {
            if (Directory.Exists(candidate))
                Directory.Delete(candidate, true);
            if (moved && Directory.Exists(plan.InstallRoot))
                Directory.Delete(plan.InstallRoot, true);
            WriteProvisionTransaction(plan, "FAILED_CLEANED", exception.Message);
            throw;
        }
    }

    private static Plan ComposePlan(
        VerifiedTarget target,
        string stagedRoot,
        string backupRoot,
        string? transactionRoot,
        string? transactionId,
        IReadOnlyList<string> launchArgs,
        string? readyMarker,
        double startupTimeout)
    {
        var installRoot = Path.GetFullPath(target.InstallRoot);
        var stage = Path.GetFullPath(stagedRoot);
        var backup = Path.GetFullPath(backupRoot);
        RequireDistinctNonOverlapping(installRoot, stage, backup);

        var stagedExecutable = Path.GetFullPath(Path.Combine(stage, target.EntryPoint));
        if (!IsUnder(stage, stagedExecutable) || !File.Exists(stagedExecutable))
            throw new InvalidDataException("authorized staged executable is missing");

        var executable = Path.GetFullPath(Path.Combine(installRoot, target.EntryPoint));
        if (!IsUnder(installRoot, executable))
            throw new InvalidDataException("authorized entry point escapes install root");

        return new Plan(installRoot, stage, backup, executable, transactionRoot, transactionId, launchArgs, readyMarker, startupTimeout);
    }

    private static void ReplaceAndLaunch(Plan plan, int? waitPid)
    {
        WaitForExit(waitPid, TimeSpan.FromSeconds(30));
        if (Directory.Exists(plan.BackupRoot)) Directory.Delete(plan.BackupRoot, true);
        CopyDirectory(plan.InstallRoot, plan.BackupRoot);

        Process? launched = null;
        try
        {
            Directory.Delete(plan.InstallRoot, true);
            CopyDirectory(plan.StagedRoot, plan.InstallRoot);
            launched = LaunchAndVerify(plan.Executable, plan.LaunchArgs, plan.ReadyMarker, plan.StartupTimeout);
            WriteTransaction(plan, "COMMITTED", null);
        }
        catch (Exception exception)
        {
            Stop(launched);
            if (Directory.Exists(plan.InstallRoot)) Directory.Delete(plan.InstallRoot, true);
            CopyDirectory(plan.BackupRoot, plan.InstallRoot);
            try
            {
                _ = LaunchAndVerify(plan.Executable, plan.LaunchArgs, plan.ReadyMarker, plan.StartupTimeout);
            }
            catch (Exception restore)
            {
                WriteTransaction(plan, "FAILED", $"{exception.Message}; restoration failed: {restore.Message}");
                throw;
            }
            WriteTransaction(plan, "ROLLED_BACK", exception.Message);
            throw;
        }
    }

    private static Process? LaunchAndVerify(string executable, IReadOnlyList<string> args, string? readyMarker, double startupTimeout)
    {
        var start = new ProcessStartInfo
        {
            FileName = executable,
            UseShellExecute = false,
            RedirectStandardOutput = readyMarker is not null,
            RedirectStandardError = readyMarker is not null,
        };
        foreach (var argument in args) start.ArgumentList.Add(argument);
        var process = Process.Start(start) ?? throw new InvalidOperationException("updated process could not start");

        var deadline = DateTime.UtcNow.AddSeconds(startupTimeout);
        if (readyMarker is null)
        {
            while (DateTime.UtcNow < deadline)
            {
                if (process.HasExited)
                {
                    if (process.ExitCode != 0) throw new InvalidOperationException($"updated process failed startup: {process.ExitCode}");
                    return process;
                }
                Thread.Sleep(50);
            }
            return process;
        }

        while (DateTime.UtcNow < deadline)
        {
            if (process.HasExited) throw new InvalidOperationException($"updated process exited before readiness: {process.ExitCode}");
            var line = process.StandardOutput.ReadLine();
            if (line is not null && line.Contains(readyMarker, StringComparison.Ordinal))
            {
                Thread.Sleep(200);
                if (process.HasExited) throw new InvalidOperationException($"updated process exited after readiness: {process.ExitCode}");
                return process;
            }
            Thread.Sleep(50);
        }
        throw new TimeoutException("updated process did not report readiness");
    }

    private static void Stop(Process? process)
    {
        if (process is null || process.HasExited) return;
        process.Kill(entireProcessTree: true);
        process.WaitForExit(3000);
    }

    private static void WaitForExit(int? pid, TimeSpan timeout)
    {
        if (pid is null) return;
        try
        {
            using var process = Process.GetProcessById(pid.Value);
            if (!process.WaitForExit((int)timeout.TotalMilliseconds))
                throw new TimeoutException("target process did not exit");
        }
        catch (ArgumentException)
        {
            // Already exited.
        }
    }

    private static void WriteTransaction(Plan plan, string state, string? reason)
    {
        if (string.IsNullOrWhiteSpace(plan.TransactionRoot) || string.IsNullOrWhiteSpace(plan.TransactionId)) return;
        var folder = Path.Combine(plan.TransactionRoot, plan.TransactionId);
        Directory.CreateDirectory(folder);
        var document = new SortedDictionary<string, object?>(StringComparer.Ordinal)
        {
            ["transaction_id"] = plan.TransactionId,
            ["state"] = state,
            ["target_version"] = plan.TransactionId,
        };
        if (reason is not null) document["reason"] = reason;
        var temporary = Path.Combine(folder, "state.json.tmp");
        File.WriteAllText(temporary, JsonSerializer.Serialize(document), new UTF8Encoding(false));
        File.Move(temporary, Path.Combine(folder, "state.json"), true);
    }

    private static void ConsumeReplay(string runtimeRoot, string requestId)
    {
        var replay = Path.Combine(runtimeRoot, "replay");
        Directory.CreateDirectory(replay);
        var replayPath = Path.Combine(replay, requestId);
        try
        {
            using var stream = new FileStream(
                replayPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None);
            stream.Write(Encoding.ASCII.GetBytes("consumed\n"));
        }
        catch (IOException)
        {
            throw new InvalidDataException("privileged request already consumed");
        }
    }

    private static void WriteProvisionTransaction(
        ProvisionPlan plan,
        string state,
        string? reason)
    {
        if (string.IsNullOrWhiteSpace(plan.TransactionRoot) ||
            string.IsNullOrWhiteSpace(plan.TransactionId))
        {
            return;
        }

        var folder = Path.Combine(plan.TransactionRoot, plan.TransactionId);
        Directory.CreateDirectory(folder);
        var document = new SortedDictionary<string, object?>(StringComparer.Ordinal)
        {
            ["transaction_id"] = plan.TransactionId,
            ["state"] = state,
            ["target_version"] = plan.TargetVersion,
            ["operation"] = "PROVISION",
        };
        if (reason is not null)
            document["reason"] = reason;

        var temporary = Path.Combine(folder, "state.json.tmp");
        File.WriteAllText(
            temporary,
            JsonSerializer.Serialize(document),
            new UTF8Encoding(false));
        File.Move(temporary, Path.Combine(folder, "state.json"), true);
    }

    private static Dictionary<string, byte[]> DecodeKeys(
        JsonElement root,
        string field,
        bool allowEmpty = false)
    {
        if (root.ValueKind != JsonValueKind.Object) throw new InvalidDataException($"invalid {field}");
        var result = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (var property in root.EnumerateObject())
        {
            if (property.Value.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(property.Name))
                throw new InvalidDataException($"invalid {field}");
            byte[] raw;
            try { raw = Convert.FromBase64String(property.Value.GetString()!); }
            catch (FormatException exception) { throw new InvalidDataException($"invalid {field}", exception); }
            if (raw.Length != 32) throw new InvalidDataException($"invalid {field}");
            result[property.Name] = raw;
        }
        if (!allowEmpty && result.Count == 0) throw new InvalidDataException($"invalid {field}");
        return result;
    }

    private static void VerifySignature(JsonElement root, byte[] rawKey, string error)
    {
        byte[] signature;
        try { signature = Convert.FromBase64String(RequiredString(root, "signature")); }
        catch (FormatException exception) { throw new InvalidDataException(error, exception); }
        var canonical = Canonical(root, "signature");
        var verifier = new Ed25519Signer();
        verifier.Init(false, new Ed25519PublicKeyParameters(rawKey));
        verifier.BlockUpdate(canonical, 0, canonical.Length);
        if (!verifier.VerifySignature(signature)) throw new InvalidDataException(error);
    }

    private static byte[] Canonical(JsonElement root, string? exclude = null)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions
               {
                   Indented = false,
                   Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
               }))
        {
            WriteCanonical(writer, root, exclude);
        }
        return stream.ToArray();
    }

    private static void WriteCanonical(Utf8JsonWriter writer, JsonElement element, string? exclude)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                foreach (var property in element.EnumerateObject()
                             .Where(property => property.Name != exclude)
                             .OrderBy(property => property.Name, StringComparer.Ordinal))
                {
                    writer.WritePropertyName(property.Name);
                    WriteCanonical(writer, property.Value, null);
                }
                writer.WriteEndObject();
                break;
            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (var item in element.EnumerateArray()) WriteCanonical(writer, item, null);
                writer.WriteEndArray();
                break;
            case JsonValueKind.String:
                writer.WriteStringValue(element.GetString());
                break;
            case JsonValueKind.Number:
                writer.WriteRawValue(element.GetRawText(), skipInputValidation: true);
                break;
            case JsonValueKind.True:
                writer.WriteBooleanValue(true);
                break;
            case JsonValueKind.False:
                writer.WriteBooleanValue(false);
                break;
            case JsonValueKind.Null:
                writer.WriteNullValue();
                break;
            default:
                throw new InvalidDataException("unsupported canonical JSON value");
        }
    }

    private static string ResolveDirectory(string value, string field)
    {
        var path = Path.GetFullPath(value);
        if (!Directory.Exists(path) || Path.GetPathRoot(path) == path) throw new InvalidDataException($"invalid {field} root");
        return path;
    }

    private static string ResolveUnder(string root, string value, string field, bool mustExist = true)
    {
        var path = Path.GetFullPath(value);
        if (!IsUnder(root, path)) throw new InvalidDataException($"{field} must be inside the helper-owned runtime root");
        if (mustExist && !File.Exists(path) && !Directory.Exists(path))
            throw new InvalidDataException($"{field} is unavailable");
        return path;
    }

    private static bool IsUnder(string root, string child)
    {
        var normalizedRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        var normalizedChild = Path.GetFullPath(child);
        return normalizedChild.StartsWith(normalizedRoot, StringComparison.OrdinalIgnoreCase) ||
               string.Equals(normalizedChild.TrimEnd(Path.DirectorySeparatorChar), normalizedRoot.TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase);
    }

    private static bool PathEquals(string left, string right) =>
        string.Equals(Path.GetFullPath(left).TrimEnd(Path.DirectorySeparatorChar),
            Path.GetFullPath(right).TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase);

    private static void RequireDistinctNonOverlapping(params string[] paths)
    {
        for (var left = 0; left < paths.Length; left++)
        for (var right = left + 1; right < paths.Length; right++)
        {
            if (PathEquals(paths[left], paths[right]) || IsUnder(paths[left], paths[right]) || IsUnder(paths[right], paths[left]))
                throw new InvalidDataException("helper roots overlap");
        }
    }

    private static string ResolveAgentDataRoot(string runtimeRoot)
    {
        var runtime = new DirectoryInfo(Path.GetFullPath(runtimeRoot));
        if (!string.Equals(runtime.Name, "runtime", StringComparison.OrdinalIgnoreCase) ||
            runtime.Parent is null ||
            !string.Equals(runtime.Parent.Name, "privileged", StringComparison.OrdinalIgnoreCase) ||
            runtime.Parent.Parent is null)
        {
            throw new InvalidDataException(
                "privileged runtime root is not under the canonical Agent data root");
        }

        var dataRoot = runtime.Parent.Parent.FullName;
        if (Path.GetPathRoot(dataRoot) == dataRoot)
        {
            throw new InvalidDataException("Agent data root is invalid");
        }

        return dataRoot;
    }

    private static void RegisterInstalledProduct(ProvisionPlan plan)
    {
        var manifestPath = Path.GetFullPath(
            Path.Combine(plan.InstallRoot, "bke.manifest.json"));
        if (!IsUnder(plan.InstallRoot, manifestPath) || !File.Exists(manifestPath))
        {
            throw new InvalidDataException(
                "installed product manifest is missing");
        }

        using var document = JsonDocument.Parse(File.ReadAllText(manifestPath));
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException(
                "installed product manifest is not an object");
        }

        var fields = root.EnumerateObject()
            .Select(property => property.Name)
            .ToHashSet(StringComparer.Ordinal);
        if (!ManifestRequiredFields.IsSubsetOf(fields) ||
            !fields.IsSubsetOf(ManifestAllowedFields))
        {
            throw new InvalidDataException(
                "installed product manifest fields are invalid");
        }

        if (!root.TryGetProperty("schemaVersion", out var schemaVersion) ||
            schemaVersion.ValueKind != JsonValueKind.Number ||
            !schemaVersion.TryGetInt32(out var schema) ||
            schema != 1)
        {
            throw new InvalidDataException(
                "installed product manifest schema is unsupported");
        }

        var productId = RequiredString(root, "productId");
        var displayName = RequiredString(root, "displayName");
        var version = RequiredString(root, "version");
        var entryPoint = RequiredString(root, "entryPoint");
        var channel = RequiredString(root, "updateChannel");
        var minimumAgentVersion = RequiredString(root, "minimumAgentVersion");
        var platform = RequiredString(root, "platform");
        var architecture = RequiredString(root, "architecture");

        if (!ProductIdPattern.IsMatch(productId) ||
            productId != plan.ProductId ||
            version != plan.TargetVersion ||
            platform != plan.Platform ||
            !ArchitecturesEquivalent(architecture, plan.Architecture) ||
            displayName.Length > 256 ||
            channel is not ("stable" or "beta" or "alpha"))
        {
            throw new InvalidDataException(
                "installed product manifest identity does not match the authorized install");
        }

        _ = SemanticVersion.Parse(version);
        _ = SemanticVersion.Parse(minimumAgentVersion);

        var normalizedEntry = entryPoint
            .Replace('/', Path.DirectorySeparatorChar)
            .Replace('\\', Path.DirectorySeparatorChar);
        if (Path.IsPathRooted(normalizedEntry) ||
            normalizedEntry.Split(Path.DirectorySeparatorChar)
                .Any(part => part is "" or "." or "..") ||
            !string.Equals(
                normalizedEntry,
                plan.EntryPoint
                    .Replace('/', Path.DirectorySeparatorChar)
                    .Replace('\\', Path.DirectorySeparatorChar),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "installed product manifest entry point is invalid");
        }

        var entryPointPath = Path.GetFullPath(
            Path.Combine(plan.InstallRoot, normalizedEntry));
        if (!IsUnder(plan.InstallRoot, entryPointPath) ||
            !PathEquals(entryPointPath, plan.Executable) ||
            !File.Exists(entryPointPath))
        {
            throw new InvalidDataException(
                "installed product manifest entry point is unavailable");
        }

        AgentDatabase.RegisterDiscoveredProduct(
            plan.AgentDataRoot,
            new DiscoveredProductRegistration(
                productId,
                displayName,
                version,
                manifestPath,
                plan.InstallRoot,
                entryPointPath,
                DateTimeOffset.UtcNow));
    }

    private static bool ArchitecturesEquivalent(string left, string right)
    {
        static string Normalize(string value) =>
            value.Trim().ToLowerInvariant() switch
            {
                "amd64" or "x86_64" or "x64" => "x64",
                "arm64" or "aarch64" => "arm64",
                "x86" or "i386" or "i686" => "x86",
                _ => value.Trim().ToLowerInvariant(),
            };

        return string.Equals(
            Normalize(left),
            Normalize(right),
            StringComparison.Ordinal);
    }

    private static void CopyDirectory(string source, string destination)
    {
        if (!Directory.Exists(source)) throw new DirectoryNotFoundException(source);
        Directory.CreateDirectory(destination);
        foreach (var file in Directory.EnumerateFiles(source))
            File.Copy(file, Path.Combine(destination, Path.GetFileName(file)), overwrite: true);
        foreach (var directory in Directory.EnumerateDirectories(source))
            CopyDirectory(directory, Path.Combine(destination, Path.GetFileName(directory)));
    }

    private static void RequireExact(JsonElement root, HashSet<string> expected, string contract)
    {
        if (root.ValueKind != JsonValueKind.Object ||
            !root.EnumerateObject().Select(p => p.Name).ToHashSet(StringComparer.Ordinal).SetEquals(expected))
            throw new InvalidDataException($"unsupported {contract} contract");
    }

    private static string RequiredString(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(value.GetString()))
            throw new InvalidDataException($"invalid {name}");
        var result = value.GetString()!;
        if (result.Length > 1024) throw new InvalidDataException($"invalid {name}");
        return result;
    }

    private static string RequiredRelativePath(JsonElement root, string name)
    {
        var value = RequiredString(root, name).Replace('/', Path.DirectorySeparatorChar).Replace('\\', Path.DirectorySeparatorChar);
        if (Path.IsPathRooted(value) || value.Split(Path.DirectorySeparatorChar).Any(part => part is "" or "." or ".."))
            throw new InvalidDataException($"invalid {name}");
        return value;
    }

    private static string RequiredHash(JsonElement root, string name)
    {
        var value = RequiredString(root, name);
        if (!HashPattern.IsMatch(value)) throw new InvalidDataException($"invalid {name}");
        return value;
    }

    private static long RequiredLong(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.Number || !value.TryGetInt64(out var result))
            throw new InvalidDataException($"invalid {name}");
        return result;
    }

    private static int RequiredInt(JsonElement root, string name)
    {
        var value = RequiredLong(root, name);
        if (value is < int.MinValue or > int.MaxValue) throw new InvalidDataException($"invalid {name}");
        return (int)value;
    }

    private static DateTimeOffset RequiredTime(JsonElement root, string name)
    {
        var raw = RequiredString(root, name);
        if (!DateTimeOffset.TryParse(raw, out var value)) throw new InvalidDataException($"invalid {name}");
        return value.ToUniversalTime();
    }

    private static int? OptionalRevision(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null) return null;
        if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt32(out var revision))
            throw new InvalidDataException($"invalid {name}");
        return revision;
    }

    private static string Sha256(byte[] data) => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    private enum OperationMode
    {
        Update,
        Provision,
    }

    private sealed record Options(
        OperationMode Mode,
        string RuntimeRoot,
        string Request,
        string? UpdatePolicy,
        string TargetPolicy,
        string Artifact,
        string StagedRoot,
        string? BackupRoot,
        string? TransactionRoot,
        string? TransactionId,
        int? WaitPid,
        IReadOnlyList<string> LaunchArgs,
        string? ReadyMarker,
        double StartupTimeout);

    private sealed record TrustedRuntime(
        IReadOnlyDictionary<string, byte[]> AgentKeys,
        IReadOnlyDictionary<string, byte[]> DigitalKeys,
        IReadOnlyDictionary<string, byte[]> TargetKeys,
        IReadOnlyList<string> ApprovedRoots,
        string ExpectedChannel,
        int? LastUpdateRevision,
        int? LastTargetRevision);

    private sealed record VerifiedRequest(
        string RequestId, string ProductId, string CurrentVersion, string TargetVersion,
        string Platform, string Architecture, string InstallRoot, string EntryPoint,
        string ArtifactSha256, long ArtifactSize, string UpdatePolicySha256, string TargetPolicySha256);

    private sealed record VerifiedProvisionRequest(
        string RequestId,
        string ProductId,
        string TargetVersion,
        string Platform,
        string Architecture,
        string InstallRoot,
        string EntryPoint,
        string ArtifactSha256,
        long ArtifactSize,
        string TargetPolicySha256);

    private sealed record VerifiedUpdate(
        string ProductId, string CurrentVersion, string LatestVersion, string Platform,
        string Architecture, string ArtifactSha256, long ArtifactSize);

    private sealed record VerifiedTarget(
        string ProductId, string Platform, string Architecture, string InstallRoot,
        string EntryPoint, string PolicySha256);

    private sealed record Plan(
        string InstallRoot, string StagedRoot, string BackupRoot, string Executable,
        string? TransactionRoot, string? TransactionId, IReadOnlyList<string> LaunchArgs,
        string? ReadyMarker, double StartupTimeout);

    private sealed record ProvisionPlan(
        string AgentDataRoot,
        string ProductId,
        string Platform,
        string Architecture,
        string InstallRoot,
        string StagedRoot,
        string Executable,
        string EntryPoint,
        string TargetVersion,
        string? TransactionRoot,
        string? TransactionId);

    private sealed record SemanticVersion(int Major, int Minor, int Patch, string? PreRelease) : IComparable<SemanticVersion>
    {
        private static readonly Regex Pattern = new(
            "^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z.-]+))?(?:\\+[0-9A-Za-z.-]+)?$",
            RegexOptions.CultureInvariant);

        internal static SemanticVersion Parse(string value)
        {
            var match = Pattern.Match(value);
            if (!match.Success) throw new InvalidDataException("invalid semantic version");
            return new(
                int.Parse(match.Groups[1].Value),
                int.Parse(match.Groups[2].Value),
                int.Parse(match.Groups[3].Value),
                match.Groups[4].Success ? match.Groups[4].Value : null);
        }

        public int CompareTo(SemanticVersion? other)
        {
            if (other is null) return 1;
            var compared = Major.CompareTo(other.Major);
            if (compared == 0) compared = Minor.CompareTo(other.Minor);
            if (compared == 0) compared = Patch.CompareTo(other.Patch);
            if (compared != 0) return compared;
            if (PreRelease is null) return other.PreRelease is null ? 0 : 1;
            if (other.PreRelease is null) return -1;
            return string.CompareOrdinal(PreRelease, other.PreRelease);
        }
    }
}
