using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;
using BKE.LicensingAgent.Host;
using BKE.LicensingAgent.Infrastructure;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

/// <summary>
/// Windows-only POSITIVE native Host fixture: real OS-observed separate client,
/// real Ed25519 signed policy, real durable SQLite audit and replay rejection.
/// NOT an installed SYSTEM Agent, DS-approved enrollment, customer license,
/// SDK/Render Dock acceptance or production authorization. Commercial proof
/// is a narrowly scoped certification-only substitute.
/// </summary>
internal static class StandaloneStartupHostPositiveCertification
{
    private const string Product = "bke-render-dock";
    private const string Version = "1.0.3";
    private const string Installation = "00000000-0000-0000-0000-000000000123";
    private const string ChildExe = "RENDER DOCK.exe";

    public static async Task RunAsync()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Native startup positive fixture requires Windows.");

        var root = Path.Combine(Path.GetTempPath(),
            "bke-startup-host-positive-" + Guid.NewGuid().ToString("N"));
        var imageDir = Path.Combine(root, "BKE Digital Solutions", "Render Dock");
        var image = Path.Combine(imageDir, ChildExe);
        var ledger = Path.Combine(root, "grants.db");
        Directory.CreateDirectory(imageDir);
        StandaloneStartupPipeHostedService? host = null;
        try
        {
            // Copy the actual self-contained apphost *identity* plus its .NET
            // dependencies to an isolated Program-Files-shaped test root.
            // Never write to the real Program Files or install a service.
            var apphost = Path.Combine(AppContext.BaseDirectory,
                "BKE.LicensingAgent.ContractCertification.exe");
            Check(File.Exists(apphost), "native certification apphost missing");
            foreach (var file in Directory.GetFiles(AppContext.BaseDirectory))
            {
                var filename = Path.GetFileName(file);
                File.Copy(file, Path.Combine(imageDir,
                    string.Equals(filename, Path.GetFileName(apphost),
                        StringComparison.OrdinalIgnoreCase) ? ChildExe : filename));
            }

            var sha = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(image)))
                .ToLowerInvariant();
            var sid = WindowsIdentity.GetCurrent().User?.Value ??
                throw new InvalidOperationException("Windows SID unavailable");
            var now = DateTimeOffset.UtcNow;
            var privateKey = new Ed25519PrivateKeyParameters(
                RandomNumberGenerator.GetBytes(32), 0);
            var publicDer = Convert.FromHexString("302A300506032B6570032100")
                .Concat(privateKey.GeneratePublicKey().GetEncoded()).ToArray();
            var pem = "-----BEGIN PUBLIC KEY-----\n" +
                Convert.ToBase64String(publicDer) + "\n-----END PUBLIC KEY-----\n";
            var keys = new Dictionary<string, AccountProductLeaseTrustedKey>(
                StringComparer.Ordinal) {
                    ["disposable-host-issuer"] = new(pem, "ACTIVE")
                };
            var payload = JsonSerializer.Serialize(new {
                schema = InstalledStandaloneStartupPolicyRegistry.PayloadSchema,
                issuer_source_sha =
                    AccountProductLeaseInstalledTrust.ExactIssuerSourceSha,
                product_id = Product,
                version = Version,
                installation_id = Installation,
                image_path = Path.GetFullPath(image),
                image_sha256 = sha,
                allowed_user_sid = sid,
                activation_mode = "LICENSE_KEY",
                not_before = now.AddMinutes(-1).ToString("O"),
                expires_at = now.AddMinutes(20).ToString("O")
            });
            var message = Encoding.UTF8.GetBytes(
                InstalledStandaloneStartupPolicyRegistry.Domain + payload);
            var signer = new Ed25519Signer();
            signer.Init(true, privateKey);
            signer.BlockUpdate(message, 0, message.Length);
            var envelope = JsonSerializer.Serialize(new {
                schema = InstalledStandaloneStartupPolicyRegistry.EnvelopeSchema,
                kid = "disposable-host-issuer",
                payload,
                signature = Convert.ToBase64String(signer.GenerateSignature())
            });
            var policy = InstalledStandaloneStartupPolicyRegistry.ForCertification(
                [envelope], keys, root, now);
            var audit = InstalledStandaloneStartupGrantAudit.ForCertification(ledger);
            var commercial = new BoundCommercialCredential();
            host = new StandaloneStartupPipeHostedService(
                policy, audit, new NoCatalog(), commercial, "certification",
                NullLogger<StandaloneStartupPipeHostedService>.Instance);
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(40));
            await host.StartAsync(timeout.Token);

            using var child = new Process {
                StartInfo = new ProcessStartInfo(image) {
                    Arguments = "--certify-startup-client",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                    WorkingDirectory = imageDir
                }
            };
            Check(child.Start(), "could not start real child EXE");
            var pid = child.Id;
            var started = child.StartTime.ToUniversalTime().Ticks;
            try
            {
                var stdout = child.StandardOutput.ReadToEndAsync(timeout.Token);
                var stderr = child.StandardError.ReadToEndAsync(timeout.Token);
                await child.WaitForExitAsync(timeout.Token);
                var output = await stdout;
                var error = await stderr;
                Check(child.ExitCode == 0 &&
                    output.Contains("NATIVE_CHILD_AUTHORIZED_AND_REPLAY_DENIED",
                        StringComparison.Ordinal),
                    "native child did not receive grant and reject replay: " +
                        error[..Math.Min(error.Length, 250)]);
            }
            finally
            {
                if (!child.HasExited) child.Kill(entireProcessTree: true);
            }

            using (var connection = new SqliteConnection(
                new SqliteConnectionStringBuilder {
                    DataSource = ledger,
                    Mode = SqliteOpenMode.ReadOnly,
                    Pooling = false
                }.ToString()))
            {
                connection.Open();
                using var query = connection.CreateCommand();
                query.CommandText = """
                    SELECT pid, started_utc_ticks, user_sid, product_id, version,
                           installation_id, image_sha256, credential
                    FROM startup_grants
                    """;
                using var rows = query.ExecuteReader();
                Check(rows.Read() &&
                    rows.GetInt32(0) == pid &&
                    rows.GetInt64(1) == started &&
                    rows.GetString(2) == sid &&
                    rows.GetString(3) == Product &&
                    rows.GetString(4) == Version &&
                    rows.GetString(5) == Installation &&
                    rows.GetString(6) == sha &&
                    rows.GetString(7) == "LICENSE_KEY",
                    "signed policy and grant must bind actual kernel process");
                Check(!rows.Read(), "replayed client created a second durable grant");
            }
            Check(commercial.Calls == 2,
                "independent commercial authorization was not checked on both attempts");
            Console.WriteLine("Windows signed native Host positive fixture: PASS " +
                "(signed test policy + real child PID/SID/image + durable grant + replay denial)");
        }
        finally
        {
            if (host is not null)
            {
                await host.StopAsync(CancellationToken.None);
                host.Dispose();
            }
            Directory.Delete(root, recursive: true);
        }
    }

    // Executed by the copied apphost; tests only the identity-free real wire
    // protocol and deliberately supplies no PID, SID, product, license or mode.
    public static async Task RunChildAsync()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(18));
        var first = await RequestAsync("native-signed-1", timeout.Token);
        Check(first.Authorized && first.Reason == "authorized",
            "first real child request must be granted by signed Host");
        var replay = await RequestAsync("native-signed-replay", timeout.Token);
        Check(!replay.Authorized && replay.Reason != "authorized",
            "same actual child process replay must be denied");
        Console.WriteLine("NATIVE_CHILD_AUTHORIZED_AND_REPLAY_DENIED");
    }

    private static async Task<(bool Authorized, string Reason)> RequestAsync(
        string requestId, CancellationToken cancellationToken)
    {
        await using var pipe = new NamedPipeClientStream(".",
            StandaloneStartupPipeHostedService.PipeName,
            PipeDirection.InOut, PipeOptions.Asynchronous,
            TokenImpersonationLevel.Impersonation);
        await pipe.ConnectAsync(cancellationToken);
        var message = JsonSerializer.SerializeToUtf8Bytes(new {
            schema = StandaloneStartupPipeHostedService.Protocol,
            operation = "authorize",
            request_id = requestId
        });
        var header = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(header, message.Length);
        await pipe.WriteAsync(header, cancellationToken);
        await pipe.WriteAsync(message, cancellationToken);
        await pipe.FlushAsync(cancellationToken);
        await pipe.ReadExactlyAsync(header, cancellationToken);
        var length = BinaryPrimitives.ReadInt32BigEndian(header);
        Check(length is > 2 and <= 1024, "unbounded Host response");
        var response = new byte[length];
        await pipe.ReadExactlyAsync(response, cancellationToken);
        using var doc = JsonDocument.Parse(response);
        var value = doc.RootElement;
        Check(value.EnumerateObject().Count() == 4 &&
            value.GetProperty("schema").GetString() ==
                StandaloneStartupPipeHostedService.Protocol &&
            value.GetProperty("request_id").GetString() == requestId,
            "response schema/correlation mismatch");
        return (value.GetProperty("authorized").GetBoolean(),
            value.GetProperty("reason").GetString() ?? "");
    }

    private static void Check(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException("FAIL Windows startup positive: " + message);
    }

    private sealed class BoundCommercialCredential : IAuthorizationService
    {
        public int Calls { get; private set; }
        public Task<AuthorizationResponse> AuthorizeAsync(
            AuthorizeRequest request, CancellationToken cancellationToken)
        {
            Calls++;
            var allowed = request.ProductId == Product &&
                request.Version == Version && request.InstallationId == Installation;
            return Task.FromResult(new AuthorizationResponse(allowed,
                allowed ? "authorized" : "unverifiable_signed_lease"));
        }
    }

    private sealed class NoCatalog : ISoftwareCatalogService
    {
        public Task<SoftwareCatalogResponse> GetAsync(
            SoftwareCatalogRequest request, CancellationToken cancellationToken) =>
            Task.FromResult(new SoftwareCatalogResponse(
                LocalAgentContract.SoftwareCatalogCapabilityId,
                LocalAgentContract.SoftwareCatalogContractVersion,
                "AUTH_REQUIRED", [], null));
    }
}
