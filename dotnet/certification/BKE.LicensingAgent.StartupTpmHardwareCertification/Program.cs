using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

// Dedicated PREPRODUCTION hardware proof. This executable is not shipped,
// does not enroll with DS and does not use a software/DPAPI signing fallback.
// A CNG Platform provider check is LOCAL evidence, not remote TPM attestation.
if (!OperatingSystem.IsWindows())
    throw new PlatformNotSupportedException("TPM machine-store proof requires Windows.");
if (Environment.GetEnvironmentVariable("BKE_ENVIRONMENT") != "certification" ||
    Environment.GetEnvironmentVariable("BKE_TPM_HARDWARE_CERTIFICATION_ENABLED") != "1")
    throw new InvalidOperationException("Explicit preproduction TPM certification authorization required.");
if (args.Length != 4 || args[0] is not ("create" or "verify" or "cleanup") ||
    !Regex.IsMatch(args[1], @"^BKE-PREPRODUCTION-STARTUP-TPM-[A-F0-9]{32}$",
        RegexOptions.CultureInvariant) ||
    args[2].Length < 2 || !Path.IsPathFullyQualified(args[2]) ||
    !Regex.IsMatch(args[3], "^[0-9a-f]{40}$", RegexOptions.CultureInvariant))
    throw new InvalidDataException("Use: create|verify|cleanup <disposable CNG key> <absolute evidence file> <exact main SHA>.");

var phase = args[0];
var name = args[1];
var evidenceFile = args[2];
var sourceSha = args[3];
if (phase == "create")
    HardwareProof.Create(name, evidenceFile, sourceSha);
else if (phase == "verify")
    HardwareProof.Verify(name, evidenceFile, sourceSha);
else
    HardwareProof.Cleanup(name, evidenceFile, sourceSha);

[SupportedOSPlatform("windows")]
internal static class HardwareProof
{
    private const string Schema = "bke.preproduction-startup-tpm-machine-proof.v1";
    private const string Domain = "BKE-PREPRODUCTION-STARTUP-TPM-MACHINE-ES256-V1\n";
    private static readonly CngProvider Platform = CngProvider.MicrosoftPlatformCryptoProvider;
    private const CngKeyOpenOptions Machine = CngKeyOpenOptions.MachineKey;
    internal sealed record Evidence(string Schema, string SourceSha, string KeyName,
        string Algorithm, string Provider, string Scope, string PublicSpkiBase64,
        string PublicKeySha256, string ChallengeBase64, string SignatureBase64);

    private static void RequireMachine(CngKey key)
    {
        if (!key.IsMachineKey || key.IsEphemeral ||
            key.Provider.Provider != Platform.Provider ||
            key.Algorithm.Algorithm != CngAlgorithm.ECDsaP256.Algorithm ||
            key.ExportPolicy != CngExportPolicies.None ||
            (key.KeyUsage & CngKeyUsages.Signing) != CngKeyUsages.Signing)
            throw new InvalidDataException(
                "Missing TPM Platform provider, machine scope, P-256 signing, or nonexportable custody.");
    }

    private static byte[] Spki(CngKey key)
    {
        RequireMachine(key);
        using var signer = new ECDsaCng(key);
        var spki = signer.ExportSubjectPublicKeyInfo();
        using var verifier = ECDsa.Create();
        verifier.ImportSubjectPublicKeyInfo(spki, out var read);
        if (read != spki.Length || verifier.KeySize != 256)
            throw new InvalidDataException("TPM key did not return canonical ECDSA P-256 SPKI.");
        return spki;
    }

    private static void RequireNoPrivateExport(CngKey key)
    {
        if (key.ExportPolicy != CngExportPolicies.None)
            throw new InvalidDataException("CNG private-key export policy is not NONE.");
        try
        {
            _ = key.Export(CngKeyBlobFormat.EccPrivateBlob);
            throw new InvalidDataException("TPM private-key material was exportable.");
        }
        catch (CryptographicException) { /* Required: CNG provider must deny private export. */ }
    }

    private static byte[] Message(byte[] nonce) =>
        Encoding.UTF8.GetBytes(Domain + Convert.ToBase64String(nonce));

    private static byte[] Sign(CngKey key, byte[] message)
    {
        RequireMachine(key);
        using var signer = new ECDsaCng(key);
        var signature = signer.SignData(message, HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        if (signature.Length != 64)
            throw new InvalidDataException("ES256 signature is not exact 64-byte IEEE P1363.");
        return signature;
    }

    private static bool PublicVerify(byte[] spki, byte[] message, byte[] signature)
    {
        using var publicOnly = ECDsa.Create();
        publicOnly.ImportSubjectPublicKeyInfo(spki, out var read);
        return read == spki.Length &&
            publicOnly.VerifyData(message, signature, HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    private static Evidence Read(string filename, string expectedKey, string expectedSourceSha)
    {
        var info = new FileInfo(filename);
        if (!info.Exists || info.Length is < 120 or > 8192 ||
            (info.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("Missing, redirected or oversized TPM proof record.");
        var text = File.ReadAllText(filename, new UTF8Encoding(false, true));
        Evidence? proof;
        try { proof = JsonSerializer.Deserialize<Evidence>(text); }
        catch (JsonException error) { throw new InvalidDataException("TPM evidence is malformed.", error); }
        if (proof is null || JsonSerializer.Serialize(proof) != text ||
            proof.Schema != Schema || proof.SourceSha != expectedSourceSha ||
            proof.KeyName != expectedKey ||
            proof.Provider != Platform.Provider ||
            proof.Algorithm != "ES256" || proof.Scope != "MACHINE" ||
            !Regex.IsMatch(proof.PublicKeySha256, "^[0-9a-f]{64}$"))
            throw new InvalidDataException("TPM evidence does not match exact main/protocol/key.");
        return proof;
    }

    private static void ValidateEvidence(CngKey key, Evidence p)
    {
        var spki = Spki(key);
        if (Convert.ToBase64String(spki) != p.PublicSpkiBase64 ||
            Convert.ToHexString(SHA256.HashData(spki)).ToLowerInvariant() != p.PublicKeySha256)
            throw new InvalidDataException("Reopened TPM identity no longer matches public proof.");
        var nonce = Convert.FromBase64String(p.ChallengeBase64);
        var signature = Convert.FromBase64String(p.SignatureBase64);
        if (nonce.Length != 32 || signature.Length != 64 ||
            !PublicVerify(spki, Message(nonce), signature))
            throw new InvalidDataException("Persisted TPM P-256 signature is not valid.");
        var altered = (byte[])nonce.Clone();
        altered[0] ^= 0x40;
        if (PublicVerify(spki, Message(altered), signature))
            throw new InvalidDataException("Tampered TPM challenge was accepted.");
        var forged = (byte[])signature.Clone();
        forged[0] ^= 0x40;
        if (PublicVerify(spki, Message(nonce), forged))
            throw new InvalidDataException("Forged TPM signature was accepted.");
        RequireNoPrivateExport(key);
        CryptographicOperations.ZeroMemory(nonce);
        CryptographicOperations.ZeroMemory(signature);
    }

    internal static void Create(string name, string path, string source)
    {
        if (File.Exists(path) || CngKey.Exists(name, Platform, Machine))
            throw new InvalidDataException("Never replace an existing TPM key or proof.");
        CngKey key;
        try
        {
            key = CngKey.Create(CngAlgorithm.ECDsaP256, name,
                new CngKeyCreationParameters {
                    Provider = Platform,
                    KeyCreationOptions = CngKeyCreationOptions.MachineKey,
                    ExportPolicy = CngExportPolicies.None,
                    KeyUsage = CngKeyUsages.Signing,
                });
        }
        catch (CryptographicException error)
        {
            throw new InvalidOperationException(
                "TPM_MACHINE_HARDWARE_UNAVAILABLE: platform provider refused strict machine key.", error);
        }
        using (key)
        {
            var committed = false;
            try
            {
                RequireMachine(key);
                var spki = Spki(key);
                RequireNoPrivateExport(key);
                var nonce = RandomNumberGenerator.GetBytes(32);
                try
                {
                    var signature = Sign(key, Message(nonce));
                    try
                    {
                        if (!PublicVerify(spki, Message(nonce), signature))
                            throw new InvalidDataException("Provider ES256 proof did not verify.");
                        var proof = new Evidence(Schema, source, name, "ES256", Platform.Provider,
                            "MACHINE", Convert.ToBase64String(spki),
                            Convert.ToHexString(SHA256.HashData(spki)).ToLowerInvariant(),
                            Convert.ToBase64String(nonce), Convert.ToBase64String(signature));
                        using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write,
                            FileShare.None, bufferSize: 4096, FileOptions.WriteThrough);
                        var data = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(proof));
                        file.Write(data); file.Flush(flushToDisk: true);
                        committed = true;
                    }
                    finally { CryptographicOperations.ZeroMemory(signature); }
                }
                finally { CryptographicOperations.ZeroMemory(nonce); }
            }
            finally
            {
                if (!committed) {
                    try { key.Delete(); } catch { /* preserve original exception; inspect orphan */ }
                }
            }
        }
        Console.WriteLine("TPM MACHINE CREATE PASS: Microsoft Platform Crypto Provider, ES256, private export denied.");
    }

    internal static void Verify(string name, string path, string source)
    {
        var proof = Read(path, name, source);
        // Reopen from a NEW PROCESS and verify the exact original public identity.
        if (!CngKey.Exists(name, Platform, Machine))
            throw new InvalidDataException("TPM machine key missing after process restart; no fallback.");
        using var key = CngKey.Open(name, Platform, Machine);
        ValidateEvidence(key, proof);
        var nonce = RandomNumberGenerator.GetBytes(32);
        try
        {
            var signature = Sign(key, Message(nonce));
            try
            {
                var spki = Spki(key);
                if (!PublicVerify(spki, Message(nonce), signature))
                    throw new InvalidDataException("Reopened TPM machine key cannot sign.");
                var changed = (byte[])nonce.Clone();
                changed[0] ^= 1;
                if (PublicVerify(spki, Message(changed), signature))
                    throw new InvalidDataException("New challenge tamper was accepted.");
            }
            finally { CryptographicOperations.ZeroMemory(signature); }
        }
        finally { CryptographicOperations.ZeroMemory(nonce); }
        Console.WriteLine("TPM MACHINE REOPEN PASS: same nonexportable platform key, second-process ES256, tamper DENY.");
    }

    internal static void Cleanup(string name, string path, string source)
    {
        // Do not delete anything unless the proof's stored public key matches
        // this exact newly created disposable CNG object.
        var proof = Read(path, name, source);
        if (!CngKey.Exists(name, Platform, Machine))
            throw new InvalidDataException("TPM test key vanished before verified cleanup.");
        using (var key = CngKey.Open(name, Platform, Machine)) {
            ValidateEvidence(key, proof);
            key.Delete();
        }
        if (CngKey.Exists(name, Platform, Machine))
            throw new InvalidDataException("Disposable TPM test key persisted after deletion.");
        File.Delete(path);
        Console.WriteLine("TPM MACHINE CLEANUP PASS: exact disposable key removed; no installed Agent keys touched.");
    }
}
