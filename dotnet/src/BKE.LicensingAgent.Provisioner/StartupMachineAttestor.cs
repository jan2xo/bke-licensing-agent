using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace BKE.LicensingAgent.Provisioner;

/// <summary>
/// One-shot PREPRODUCTION privileged installer attestor. Not an Agent Host
/// endpoint, account-session key, or updater signing authority.
/// </summary>
internal sealed class StartupMachineAttestor
{
    private const string Domain = "BKE-AGENT-STARTUP-INSTALL-ATTESTATION-V1\n";
    private static readonly byte[] Entropy = Encoding.ASCII.GetBytes("BKE startup install machine attestation key 1");
    private static readonly byte[] Spki = Convert.FromHexString("302A300506032B6570032100");
    private static readonly Regex Product = new("^[a-z0-9]+(?:-[a-z0-9]+)*$", RegexOptions.CultureInvariant);
    private static readonly Regex Version = new(@"^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$", RegexOptions.CultureInvariant);
    private static readonly Regex UserSid = new(@"^S-1-(?:5-21-\d+-\d+-\d+-\d+|12-1-\d+-\d+-\d+-\d+)$", RegexOptions.CultureInvariant);
    private readonly string _dataRoot;
    private readonly string _programFiles;
    private readonly string _privatePath;
    private sealed record Record(string Kid, string DeviceId, string Seed);
    internal sealed record InstalledEvidence(string ProductId, string Version,
        string InstallationId, string ImagePath, string ImageSha256, string UserSid);

    private StartupMachineAttestor(string dataRoot, string programFiles)
    {
        _dataRoot = Path.GetFullPath(dataRoot);
        _programFiles = Path.GetFullPath(programFiles);
        _privatePath = Path.Combine(_dataRoot, "privileged", "startup-attestation", "identity.dpapi");
    }

    internal static StartupMachineAttestor ForCertification(string dataRoot, string programFiles)
        => new(dataRoot, programFiles);

    internal static StartupMachineAttestor LoadInstalled()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Windows-only installed attestation.");
        var environment = Environment.GetEnvironmentVariable("BKE_ENVIRONMENT") ?? "production";
        if (environment is not ("development" or "certification" or "utm") ||
            Environment.GetEnvironmentVariable("BKE_STANDALONE_STARTUP_ATTESTATION_ENABLED") != "1")
            throw new InvalidOperationException("Startup attestation disabled outside PREPRODUCTION.");
        using var identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
            throw new UnauthorizedAccessException("Elevated installer administrator identity required.");
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        if (string.IsNullOrWhiteSpace(programFiles) || string.IsNullOrWhiteSpace(programData))
            throw new InvalidDataException("Windows installed roots unavailable.");
        var expected = Path.GetFullPath(Path.Combine(programFiles,
            "BKE Digital Solutions", "Licensing Agent", "provisioning"));
        if (!string.Equals(Path.TrimEndingDirectorySeparator(Path.GetFullPath(AppContext.BaseDirectory)),
                Path.TrimEndingDirectorySeparator(expected), StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Must run from installed Agent provisioner.");
        RequireDirectory(expected);
        RequireDirectory(Path.GetDirectoryName(expected)!);
        return new StartupMachineAttestor(Path.Combine(programData,
            "BKE Digital Solutions", "Licensing Agent"), programFiles);
    }

    internal string EnrollmentCandidate()
    {
        var record = ReadOrCreate();
        var seed = Convert.FromBase64String(record.Seed);
        try
        {
            var publicBytes = new Ed25519PrivateKeyParameters(seed, 0).GeneratePublicKey().GetEncoded();
            return JsonSerializer.Serialize(new {
                schema = "bke.agent-startup-attestation-enrollment-candidate.v1",
                kid = record.Kid, device_id = record.DeviceId,
                public_key_pem = "-----BEGIN PUBLIC KEY-----\n" +
                    Convert.ToBase64String(Spki.Concat(publicBytes).ToArray()) +
                    "\n-----END PUBLIC KEY-----\n",
                status = "STAGED" // Not ACTIVE; DS never trusts it automatically.
            });
        }
        finally { CryptographicOperations.ZeroMemory(seed); }
    }

    internal string IssueInstalled(string productId, string version,
        string installationId, string sid)
        => IssueVerified(RequireSignedTarget(productId, version, installationId, sid),
            DateTimeOffset.UtcNow);

    internal InstalledEvidence RequireSignedTarget(string productId, string version,
        string installationId, string sid)
    {
        RequireScope(productId, version, installationId, sid);
        var privileged = Path.Combine(_dataRoot, "privileged");
        RequireDirectory(privileged);
        var keyDir = Path.Combine(privileged, "target-keys");
        var policyDir = Path.Combine(privileged, "target-policies");
        RequireDirectory(keyDir);
        RequireDirectory(policyDir);
        // Reject redirected public verification keys before parsing them.
        // A signed policy is never certified against a user-writable key path.
        foreach (var keyFile in Directory.GetFiles(
                     keyDir, "*.pem", SearchOption.TopDirectoryOnly))
            RequireFile(keyFile, 16_384);
        // Existing privileged provisioner owns both signature and exact-field
        // verification; no mutable product manifest is trusted.
        Program.ValidatePolicies(policyDir, Program.ValidatePublicKeys(keyDir));
        var files = Directory.GetFiles(policyDir, "*.json", SearchOption.TopDirectoryOnly);
        if (files.Length is < 1 or > 128)
            throw new InvalidDataException("Signed privileged target count invalid.");
        var found = new List<JsonElement>();
        foreach (var file in files)
        {
            RequireFile(file, 16_384);
            using var doc = JsonDocument.Parse(File.ReadAllText(file, new UTF8Encoding(false, true)));
            if (doc.RootElement.GetProperty("product_id").GetString() == productId)
                found.Add(doc.RootElement.Clone());
        }
        if (found.Count != 1 ||
            found[0].GetProperty("platform").GetString() != "windows" ||
            found[0].GetProperty("architecture").GetString() is not ("x64" or "amd64"))
            throw new InvalidDataException("Exactly one Windows target policy must match.");
        var root = Path.GetFullPath(found[0].GetProperty("install_root").GetString()!);
        var relative = found[0].GetProperty("entry_point").GetString()!;
        if (string.IsNullOrEmpty(relative) || Path.IsPathRooted(relative) ||
            relative.Contains('/') || relative.Split('\\').Any(x => x is "" or "." or ".."))
            throw new InvalidDataException("Signed entry point must be relative and safe.");
        var approved = Path.Combine(_programFiles, "BKE Digital Solutions");
        if (!root.StartsWith(approved + Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase) ||
            Path.GetRelativePath(approved, root).Contains(Path.DirectorySeparatorChar))
            throw new InvalidDataException("Signed root is not directly under BKE Program Files.");
        var exe = Path.GetFullPath(Path.Combine(root, relative));
        if (!string.Equals(Path.GetDirectoryName(exe), root, StringComparison.OrdinalIgnoreCase) ||
            !exe.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Signed executable path escapes product root.");
        RequireDirectory(root);
        RequireFile(exe, 2_000_000_000);
        var before = new FileInfo(exe);
        long expectedBytes = before.Length;
        var expectedModified = before.LastWriteTimeUtc;
        using var stream = new FileStream(exe, FileMode.Open, FileAccess.Read, FileShare.Read);
        var digest = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
        var observed = new FileInfo(exe);
        observed.Refresh();
        if (observed.Length != expectedBytes ||
            observed.LastWriteTimeUtc != expectedModified)
            throw new IOException("Installed executable changed while hashing.");
        return new InstalledEvidence(productId, version, installationId, exe, digest, sid);
    }

    internal string IssueVerified(InstalledEvidence evidence, DateTimeOffset now)
    {
        RequireScope(evidence.ProductId, evidence.Version, evidence.InstallationId,
            evidence.UserSid);
        if (now.Offset != TimeSpan.Zero ||
            !Regex.IsMatch(evidence.ImageSha256, "^[0-9a-f]{64}$") ||
            !Path.IsPathFullyQualified(evidence.ImagePath))
            throw new InvalidDataException("Installed evidence or clock invalid.");
        var record = ReadOrCreate();
        var seed = Convert.FromBase64String(record.Seed);
        try
        {
            var payload = JsonSerializer.Serialize(new {
                schema = "bke.agent-startup-install-attestation.v1",
                product_id = evidence.ProductId, version = evidence.Version,
                installation_id = evidence.InstallationId,
                image_path = evidence.ImagePath, image_sha256 = evidence.ImageSha256,
                allowed_user_sid = evidence.UserSid, device_id = record.DeviceId,
                attestation_id = Guid.NewGuid().ToString("D"),
                issued_at = now.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fff'Z'", CultureInfo.InvariantCulture),
                expires_at = now.AddSeconds(60).UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fff'Z'", CultureInfo.InvariantCulture)
            }, new JsonSerializerOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
            var message = Encoding.UTF8.GetBytes(Domain + payload);
            try
            {
                var signer = new Ed25519Signer();
                signer.Init(true, new Ed25519PrivateKeyParameters(seed, 0));
                signer.BlockUpdate(message, 0, message.Length);
                return JsonSerializer.Serialize(new {
                    schema = "bke.agent-startup-install-attestation-envelope.v1",
                    kid = record.Kid, payload,
                    signature = Convert.ToBase64String(signer.GenerateSignature())
                }, new JsonSerializerOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
            }
            finally { CryptographicOperations.ZeroMemory(message); }
        }
        finally { CryptographicOperations.ZeroMemory(seed); }
    }

    private static void RequireScope(string product, string version, string installationId, string sid)
    {
        if (product.Length > 128 || !Product.IsMatch(product) ||
            version.Length > 128 || !Version.IsMatch(version) ||
            !Guid.TryParseExact(installationId, "D", out var uuid) ||
            uuid.ToString("D") != installationId || !UserSid.IsMatch(sid))
            throw new InvalidDataException("Installer product/version/installation/SID scope invalid.");
    }

    private Record ReadOrCreate()
    {
        var parent = Path.GetDirectoryName(Path.GetDirectoryName(_privatePath)!)!;
        RequireDirectory(parent);
        var directory = Path.GetDirectoryName(_privatePath)!;
        if (!Directory.Exists(directory)) Directory.CreateDirectory(directory);
        RequireDirectory(directory);
        Protect(directory, true);
        if (File.Exists(_privatePath)) return ReadExisting();
        var seed = RandomNumberGenerator.GetBytes(32);
        var temporary = Path.Combine(directory, ".startup-" + Guid.NewGuid().ToString("N") + ".tmp");
        byte[]? plain = null;
        byte[]? cipher = null;
        try
        {
            plain = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new Record(
                "startup-" + Guid.NewGuid().ToString("N"),
                "startup-device-" + Guid.NewGuid().ToString("N"),
                Convert.ToBase64String(seed))));
            cipher = Dpapi(plain, true);
            using (var file = new FileStream(temporary, FileMode.CreateNew,
                FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            { file.Write(cipher); file.Flush(flushToDisk: true); }
            Protect(temporary, false);
            File.Move(temporary, _privatePath, false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
            if (plain is not null) CryptographicOperations.ZeroMemory(plain);
            if (cipher is not null) CryptographicOperations.ZeroMemory(cipher);
            if (File.Exists(temporary)) File.Delete(temporary);
        }
        return ReadExisting();
    }

    private Record ReadExisting()
    {
        RequireFile(_privatePath, 8192);
        using var stream = new FileStream(_privatePath, FileMode.Open,
            FileAccess.Read, FileShare.Read);
        if (stream.Length < 32) throw new InvalidDataException("Protected identity truncated.");
        var cipher = new byte[(int)stream.Length];
        stream.ReadExactly(cipher);
        byte[]? plain = null;
        try
        {
            plain = Dpapi(cipher, false);
            var record = JsonSerializer.Deserialize<Record>(
                new UTF8Encoding(false, true).GetString(plain)) ??
                throw new InvalidDataException("Protected identity missing.");
            if (!Regex.IsMatch(record.Kid, "^startup-[0-9a-f]{32}$") ||
                !Regex.IsMatch(record.DeviceId, "^startup-device-[0-9a-f]{32}$") ||
                Convert.FromBase64String(record.Seed).Length != 32)
                throw new InvalidDataException("Protected identity fields invalid.");
            return record;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(cipher);
            if (plain is not null) CryptographicOperations.ZeroMemory(plain);
        }
    }

    private static void RequireDirectory(string path)
    {
        var f = new DirectoryInfo(path);
        if (!f.Exists || (f.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("Privileged directory is missing or redirected.");
    }
    private static void RequireFile(string path, long limit)
    {
        var f = new FileInfo(path);
        if (!f.Exists || (f.Attributes & FileAttributes.ReparsePoint) != 0 ||
            f.Length < 1 || f.Length > limit)
            throw new InvalidDataException("Privileged file is missing, redirected or oversized.");
    }

    private static void Protect(string path, bool directory)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        var psi = new ProcessStartInfo {
            FileName = Path.Combine(Environment.SystemDirectory, "icacls.exe"),
            RedirectStandardOutput = true, RedirectStandardError = true,
            UseShellExecute = false, CreateNoWindow = true
        };
        foreach (var arg in new[] { path, "/inheritance:r", "/grant:r",
            directory ? "*S-1-5-18:(OI)(CI)F" : "*S-1-5-18:F",
            directory ? "*S-1-5-32-544:(OI)(CI)F" : "*S-1-5-32-544:F" })
            psi.ArgumentList.Add(arg);
        using var process = Process.Start(psi) ??
            throw new InvalidOperationException("Windows ACL tool unavailable.");
        process.WaitForExit();
        if (process.ExitCode != 0)
            throw new InvalidDataException("Could not establish protected machine key ACL.");
    }

    private static byte[] Dpapi(byte[] data, bool encrypt)
    {
        using var input = NativeBuffer.FromBytes(data);
        using var entropy = NativeBuffer.FromBytes(Entropy);
        Blob output;
        bool ok;
        if (encrypt)
            ok = CryptProtectData(ref input.Value, "BKE Agent startup installer key",
                ref entropy.Value, IntPtr.Zero, IntPtr.Zero, 4, out output);
        else
            ok = CryptUnprotectData(ref input.Value, IntPtr.Zero,
                ref entropy.Value, IntPtr.Zero, IntPtr.Zero, 0, out output);
        if (!ok) throw new Win32Exception(Marshal.GetLastWin32Error(),
            "Windows startup machine DPAPI failed.");
        try { return output.GetBytes(); }
        finally { FreeBlob(output); }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Blob
    {
        public int Size;
        public IntPtr Data;
        public readonly byte[] GetBytes()
        {
            if (Size is < 1 or > 8192 || Data == IntPtr.Zero)
                throw new InvalidDataException("Protected machine DPAPI returned invalid data.");
            var bytes = new byte[Size];
            Marshal.Copy(Data, bytes, 0, Size);
            return bytes;
        }
    }
    private sealed class NativeBuffer : IDisposable
    {
        public Blob Value;
        private NativeBuffer(byte[] data)
        {
            Value = new Blob { Size = data.Length,
                Data = Marshal.AllocHGlobal(data.Length) };
            Marshal.Copy(data, 0, Value.Data, data.Length);
        }
        public static NativeBuffer FromBytes(byte[] data) => new(data);
        public void Dispose()
        {
            if (Value.Data == IntPtr.Zero) return;
            var zeros = new byte[Value.Size];
            try { Marshal.Copy(zeros, 0, Value.Data, Value.Size); }
            finally { CryptographicOperations.ZeroMemory(zeros);
                Marshal.FreeHGlobal(Value.Data); Value.Data = IntPtr.Zero; }
        }
    }
    private static void FreeBlob(Blob blob)
    {
        if (blob.Data == IntPtr.Zero) return;
        var zeros = new byte[blob.Size];
        try { Marshal.Copy(zeros, 0, blob.Data, blob.Size); }
        finally { CryptographicOperations.ZeroMemory(zeros); LocalFree(blob.Data); }
    }
    [DllImport("Crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptProtectData(ref Blob input, string? description,
        ref Blob entropy, IntPtr reserved, IntPtr prompt, int flags, out Blob output);
    [DllImport("Crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptUnprotectData(ref Blob input, IntPtr description,
        ref Blob entropy, IntPtr reserved, IntPtr prompt, int flags, out Blob output);
    [DllImport("Kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr pointer);
}
