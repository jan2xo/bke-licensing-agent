using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace BKE.LicensingAgent.Infrastructure;

/// <summary>
/// Trusted internal Agent session identity. Callers MUST derive all four values
/// from the Agent's authenticated DS session, never from an IPC request body.
/// </summary>
public sealed record AgentEd25519SessionBinding(
    string SessionId, string AccountId, string UserId, string DeviceId);

public sealed record AgentEd25519PublicIdentity(
    string PublicKeyPem, string KeyThumbprint, string KeyProtection,
    string Algorithm = "EdDSA");

/// <summary>
/// Trusted OS-protected machine key signer, one exact authenticated Agent binding.
/// TPM P-256 and software EdDSA share exact protocol sign operation.
/// </summary>
public interface IAgentMachineKeySigner
{
    AgentEd25519PublicIdentity GetOrCreateIdentity(
        AgentEd25519SessionBinding binding, bool createIfMissing = true);
    string SignChallenge(
        AgentEd25519SessionBinding binding, string registrationId, string challengeId,
        string messageBase64url, DateTimeOffset expiresAt,
        string? productId = null, string? action = null);
}

/// <summary>
/// Windows user-DPAPI protected SOFTWARE Ed25519 key. The seed is exportable to
/// the running account in process memory; this is NOT TPM, attestation, or a
/// nonexportable hardware-backed identity. No public HTTP/IPC route exposes it.
/// Unsupported platforms and damaged/foreign stores fail closed.
/// </summary>
public sealed class WindowsDpapiEd25519MachineKeyStore : IAgentMachineKeySigner
{
    private const string Protocol = "bke.agent-key-proof.v1";
    private const int SeedLength = 32;
    private static readonly byte[] Header =
        Encoding.ASCII.GetBytes("BKE-AGENT-ED25519-DPAPI-1\0");
    private static readonly byte[] Entropy =
        Encoding.ASCII.GetBytes("BKE agent software key custody v1");
    private static readonly byte[] SpkiPrefix =
        Convert.FromHexString("302A300506032B6570032100");
    private readonly string _path;

    public WindowsDpapiEd25519MachineKeyStore(string? dataDirectory = null)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException(
                "OS-protected Agent Ed25519 custody is certified only on Windows.");
        string root = dataDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "BKE Digital Solutions", "Licensing Agent");
        if (string.IsNullOrWhiteSpace(root))
            throw new InvalidOperationException("Protected Agent user profile is unavailable.");
        _path = Path.Combine(Path.GetFullPath(root), "machine-trust",
            "agent-ed25519.dpapi");
    }

    public bool HasStoredIdentity => File.Exists(_path);

    public AgentEd25519PublicIdentity GetOrCreateIdentity(
        AgentEd25519SessionBinding binding, bool createIfMissing = true)
    {
        byte[] seed = createIfMissing ? LoadOrCreateSeed(binding) : ReadExistingSeed(binding);
        try
        {
            var key = new Ed25519PrivateKeyParameters(seed, 0);
            var encoded = key.GeneratePublicKey().GetEncoded();
            byte[] spki = new byte[SpkiPrefix.Length + encoded.Length];
            Buffer.BlockCopy(SpkiPrefix, 0, spki, 0, SpkiPrefix.Length);
            Buffer.BlockCopy(encoded, 0, spki, SpkiPrefix.Length, encoded.Length);
            return new AgentEd25519PublicIdentity(
                "-----BEGIN PUBLIC KEY-----\n" +
                Convert.ToBase64String(spki) +
                "\n-----END PUBLIC KEY-----\n",
                Base64Url(SHA256.HashData(spki)),
                "software");
        }
        finally { CryptographicOperations.ZeroMemory(seed); }
    }

    /// <summary>
    /// Signs EXACT DS challenge bytes, not caller-provided arbitrary payloads.
    /// The expected binding and registration/challenge IDs must come from a
    /// trusted Agent transaction/session; the DS server independently checks
    /// SHA-256(message), scope, registration and single-use nonce.
    /// </summary>
    public string SignChallenge(
        AgentEd25519SessionBinding binding,
        string registrationId,
        string challengeId,
        string messageBase64url,
        DateTimeOffset expiresAt,
        string? productId = null,
        string? action = null)
    {
        ValidateBinding(binding);
        if (!IsCanonicalUuid(registrationId) || !IsCanonicalUuid(challengeId))
            throw new InvalidDataException("Agent challenge reference is invalid.");
        var now = DateTimeOffset.UtcNow;
        if (expiresAt <= now || expiresAt > now.AddSeconds(35))
            throw new InvalidDataException("Agent challenge expiry is invalid.");
        byte[] message = DecodeCanonicalBase64Url(messageBase64url, 4096);
        try
        {
            var strictUtf8 = new UTF8Encoding(false, true);
            string body = strictUtf8.GetString(message);
            var fields = body.Split('\n');
            if (fields.Length != 11 || fields[0] != Protocol ||
                fields[2] != challengeId || fields[3] != registrationId ||
                fields[4] != binding.SessionId ||
                fields[5] != binding.AccountId ||
                fields[6] != binding.UserId ||
                fields[7] != binding.DeviceId ||
                !IsCanonicalUuid(fields[2]) || !IsCanonicalUuid(fields[3]) ||
                !IsValidNonce(fields[10]))
                throw new InvalidDataException("Agent challenge envelope does not match trusted session.");

            if (fields[1] == "ENROLL")
            {
                if (productId is not null || action is not null ||
                    fields[8] != "-" || fields[9] != "-")
                    throw new InvalidDataException("ENROLL challenge must be unscoped.");
            }
            else if (fields[1] == "LEASE")
            {
                if (!IsValidProduct(productId) ||
                    (action != "OPEN" && action != "USE") ||
                    fields[8] != productId || fields[9] != action)
                    throw new InvalidDataException("LEASE challenge scope is invalid.");
            }
            else throw new InvalidDataException("Agent challenge purpose is invalid.");

            byte[] seed = ReadExistingSeed(binding);
            try
            {
                var signer = new Ed25519Signer();
                signer.Init(true, new Ed25519PrivateKeyParameters(seed, 0));
                signer.BlockUpdate(message, 0, message.Length);
                byte[] signature = signer.GenerateSignature();
                try { return Base64Url(signature); }
                finally { CryptographicOperations.ZeroMemory(signature); }
            }
            finally { CryptographicOperations.ZeroMemory(seed); }
        }
        catch (DecoderFallbackException error)
        {
            throw new InvalidDataException("Agent challenge is not valid UTF-8.", error);
        }
        finally { CryptographicOperations.ZeroMemory(message); }
    }

    /// <summary>
    /// LOCAL removal only: this does not revoke DS registration. The future
    /// authenticated revocation protocol must run before production rotation.
    /// Does not silently replace a corrupt or mismatched key.
    /// </summary>
    public void RemoveLocalKey()
    {
        if (File.Exists(_path))
            File.Delete(_path);
    }

    private byte[] LoadOrCreateSeed(AgentEd25519SessionBinding binding)
    {
        ValidateBinding(binding);
        if (File.Exists(_path)) return ReadExistingSeed(binding);
        byte[] fresh = RandomNumberGenerator.GetBytes(SeedLength);
        byte[] bindingHash = HashBinding(binding);
        byte[] plaintext = new byte[Header.Length + SeedLength + SeedLength];
        byte[]? ciphertext = null;
        string? temporary = null;
        try
        {
            Buffer.BlockCopy(Header, 0, plaintext, 0, Header.Length);
            Buffer.BlockCopy(bindingHash, 0, plaintext, Header.Length, SeedLength);
            Buffer.BlockCopy(fresh, 0, plaintext, Header.Length + SeedLength, SeedLength);
            ciphertext = Protect(plaintext);
            string directory = Path.GetDirectoryName(_path)
                ?? throw new InvalidOperationException("Key directory is unavailable.");
            Directory.CreateDirectory(directory);
            temporary = Path.Combine(directory,
                ".agent-key." + Guid.NewGuid().ToString("N") + ".tmp");
            using (var stream = new FileStream(temporary, FileMode.CreateNew,
                FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                stream.Write(ciphertext);
                stream.Flush(flushToDisk: true);
            }
            try
            {
                // No overwrite: concurrent startup may use only the first key.
                File.Move(temporary, _path, overwrite: false);
                temporary = null;
                return (byte[])fresh.Clone();
            }
            catch (IOException) when (File.Exists(_path))
            {
                // A concurrent initialization won. Validate its binding.
                return ReadExistingSeed(binding);
            }
        }
        finally
        {
            if (temporary is not null)
            {
                try { File.Delete(temporary); } catch { /* preserve primary failure */ }
            }
            CryptographicOperations.ZeroMemory(fresh);
            CryptographicOperations.ZeroMemory(bindingHash);
            CryptographicOperations.ZeroMemory(plaintext);
            if (ciphertext is not null) CryptographicOperations.ZeroMemory(ciphertext);
        }
    }

    private byte[] ReadExistingSeed(AgentEd25519SessionBinding binding)
    {
        ValidateBinding(binding);
        // File.Exists alone must never lead to implicit replacement of
        // inaccessible, truncated or tampered material.
        using var stream = new FileStream(_path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length == 0 || stream.Length > 8192)
            throw new InvalidDataException("Protected Agent key size is invalid.");
        byte[] ciphertext = new byte[(int)stream.Length];
        stream.ReadExactly(ciphertext);
        byte[]? plaintext = null;
        byte[] expectedBinding = HashBinding(binding);
        try
        {
            plaintext = Unprotect(ciphertext);
            if (plaintext.Length != Header.Length + SeedLength + SeedLength ||
                !plaintext.AsSpan(0, Header.Length).SequenceEqual(Header) ||
                !CryptographicOperations.FixedTimeEquals(
                    plaintext.AsSpan(Header.Length, SeedLength), expectedBinding))
                throw new InvalidDataException("Protected Agent key belongs to another session or is invalid.");
            return plaintext.AsSpan(Header.Length + SeedLength, SeedLength).ToArray();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(expectedBinding);
            if (plaintext is not null) CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private static byte[] HashBinding(AgentEd25519SessionBinding binding)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(
            "bke.agent-key-binding.v1\n" + binding.SessionId + "\n" +
            binding.AccountId + "\n" + binding.UserId + "\n" + binding.DeviceId);
        try { return SHA256.HashData(bytes); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private static void ValidateBinding(AgentEd25519SessionBinding binding)
    {
        ArgumentNullException.ThrowIfNull(binding);
        foreach (string? value in new[] {
            binding.SessionId, binding.AccountId, binding.UserId, binding.DeviceId })
        {
            if (string.IsNullOrWhiteSpace(value) || value.Length > 256 ||
                value.Any(c => c < '!' || c > '~' || c == '\\'))
                throw new InvalidDataException("Agent key identity must use canonical printable fields.");
        }
    }

    private static bool IsCanonicalUuid(string input) =>
        Guid.TryParseExact(input, "D", out var id) &&
        string.Equals(id.ToString("D"), input, StringComparison.Ordinal);

    private static bool IsValidProduct(string? id) =>
        !string.IsNullOrEmpty(id) && id.Length <= 128 &&
        id.All(c => (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                    (c >= '0' && c <= '9') || c is '.' or '_' or '-');

    private static bool IsValidNonce(string input)
    {
        try
        {
            byte[] nonce = DecodeCanonicalBase64Url(input, 64);
            try { return nonce.Length == 32; }
            finally { CryptographicOperations.ZeroMemory(nonce); }
        }
        catch (FormatException) { return false; }
    }

    private static byte[] DecodeCanonicalBase64Url(string input, int maximum)
    {
        if (string.IsNullOrEmpty(input) || input.Length > maximum ||
            input.Any(c => !((c >= 'A' && c <= 'Z') ||
                             (c >= 'a' && c <= 'z') ||
                             (c >= '0' && c <= '9') || c is '-' or '_')))
            throw new FormatException("Non-canonical base64url Agent challenge.");
        string normalized = input.Replace('-', '+').Replace('_', '/');
        normalized = normalized.PadRight((normalized.Length + 3) / 4 * 4, '=');
        byte[] result = Convert.FromBase64String(normalized);
        if (Base64Url(result) != input)
        {
            CryptographicOperations.ZeroMemory(result);
            throw new FormatException("Non-canonical base64url Agent challenge.");
        }
        return result;
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] Protect(byte[] plaintext)
    {
        using var input = NativeBuffer.FromBytes(plaintext);
        using var entropy = NativeBuffer.FromBytes(Entropy);
        if (!CryptProtectData(ref input.Value, "BKE Agent Ed25519 software key",
            ref entropy.Value, IntPtr.Zero, IntPtr.Zero, 0, out var output))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "DPAPI Agent key protection failed.");
        try { return output.ToBytes(); }
        finally { FreeNativeOutput(output); }
    }

    private static byte[] Unprotect(byte[] ciphertext)
    {
        using var input = NativeBuffer.FromBytes(ciphertext);
        using var entropy = NativeBuffer.FromBytes(Entropy);
        if (!CryptUnprotectData(ref input.Value, IntPtr.Zero,
            ref entropy.Value, IntPtr.Zero, IntPtr.Zero, 0, out var output))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "DPAPI Agent key recovery failed.");
        try { return output.ToBytes(); }
        finally { FreeNativeOutput(output); }
    }

    private static void FreeNativeOutput(NativeDataBlob output)
    {
        if (output.Data == IntPtr.Zero) return;
        if (output.Size > 0)
        {
            byte[] zeros = new byte[output.Size];
            try { Marshal.Copy(zeros, 0, output.Data, output.Size); }
            finally { CryptographicOperations.ZeroMemory(zeros); }
        }
        LocalFree(output.Data);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeDataBlob
    {
        public int Size;
        public IntPtr Data;
        public readonly byte[] ToBytes()
        {
            if (Size <= 0 || Data == IntPtr.Zero)
                throw new InvalidDataException("DPAPI returned empty Agent key data.");
            byte[] bytes = new byte[Size];
            Marshal.Copy(Data, bytes, 0, Size);
            return bytes;
        }
    }

    private sealed class NativeBuffer : IDisposable
    {
        public NativeDataBlob Value;
        private NativeBuffer(byte[] value)
        {
            Value = new NativeDataBlob { Size = value.Length,
                Data = Marshal.AllocHGlobal(value.Length) };
            Marshal.Copy(value, 0, Value.Data, value.Length);
        }
        public static NativeBuffer FromBytes(byte[] bytes) => new(bytes);
        public void Dispose()
        {
            if (Value.Data == IntPtr.Zero) return;
            byte[] zeros = new byte[Value.Size];
            try { Marshal.Copy(zeros, 0, Value.Data, Value.Size); }
            finally
            {
                CryptographicOperations.ZeroMemory(zeros);
                Marshal.FreeHGlobal(Value.Data);
                Value.Data = IntPtr.Zero;
            }
        }
    }

    [DllImport("Crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptProtectData(
        ref NativeDataBlob input, string? description, ref NativeDataBlob entropy,
        IntPtr reserved, IntPtr prompt, int flags, out NativeDataBlob output);

    [DllImport("Crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptUnprotectData(
        ref NativeDataBlob input, IntPtr description, ref NativeDataBlob entropy,
        IntPtr reserved, IntPtr prompt, int flags, out NativeDataBlob output);

    [DllImport("Kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr pointer);
}
