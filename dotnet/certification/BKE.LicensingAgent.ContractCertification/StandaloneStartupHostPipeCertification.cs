using System.Buffers.Binary;
using System.IO.Pipes;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;
using BKE.LicensingAgent.Host;
using BKE.LicensingAgent.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Real Windows Host named pipe wire/ACL bootstrap test. Deliberately uses an
/// empty trusted signing registry, so no executable can be granted startup;
/// the signed policy and credential-positive paths have independent fixtures.
/// </summary>
internal static class StandaloneStartupHostPipeCertification
{
    public static async Task RunAsync()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Real startup Host pipe test requires Windows.");

        var root = Path.Combine(Path.GetTempPath(),
            "bke-host-startup-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var passed = 0;
        void Check(bool condition, string description)
        {
            if (!condition) throw new InvalidOperationException(
                "FAIL Windows startup Host pipe " + description);
            passed++;
            Console.WriteLine("PASS Windows startup Host pipe: " + description);
        }

        var host = new StandaloneStartupPipeHostedService(
            InstalledStandaloneStartupPolicyRegistry.DenyAllForCertification(),
            InstalledStandaloneStartupGrantAudit.ForCertification(
                Path.Combine(root, "grants.db")),
            new Catalog(), new Commercial(), "certification",
            NullLogger<StandaloneStartupPipeHostedService>.Instance);
        using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(35));

        try
        {
            await host.StartAsync(limit.Token);
            await using (var client = await ConnectAsync(limit.Token))
            {
                var request = JsonSerializer.SerializeToUtf8Bytes(new {
                    schema = StandaloneStartupPipeHostedService.Protocol,
                    operation = "authorize",
                    request_id = "native-denied-1"
                });
                await WriteAsync(client, request, limit.Token);
                var response = await ReadAsync(client, limit.Token);
                using var result = JsonDocument.Parse(response!);
                var rootValue = result.RootElement;
                Check(rootValue.GetProperty("schema").GetString() ==
                    StandaloneStartupPipeHostedService.Protocol &&
                    rootValue.GetProperty("request_id").GetString() ==
                    "native-denied-1" &&
                    !rootValue.GetProperty("authorized").GetBoolean(),
                    "actual attested process cannot bypass absent signed registry");
                Check(rootValue.EnumerateObject().Count() == 4 &&
                    rootValue.GetProperty("reason").GetString() != "authorized",
                    "Host exposes no issuer secret, key or entitlement data");
            }

            async Task RequireClosed(byte[] request, string description)
            {
                await using var client = await ConnectAsync(limit.Token);
                await WriteAsync(client, request, limit.Token);
                var header = new byte[4];
                var bytesRead = await client.ReadAsync(header, limit.Token);
                Check(bytesRead == 0, description);
            }

            await RequireClosed(JsonSerializer.SerializeToUtf8Bytes(new {
                schema = StandaloneStartupPipeHostedService.Protocol,
                operation = "authorize",
                request_id = "spoof-id",
                product_id = "bke-render-dock",
                activation_mode = "ACCOUNT"
            }), "product-supplied identity and mode not admitted");

            await RequireClosed(JsonSerializer.SerializeToUtf8Bytes(new {
                schema = StandaloneStartupPipeHostedService.Protocol,
                operation = "authorize",
                request_id = "spoof-pid",
                pid = Environment.ProcessId
            }), "client-supplied PID cannot become process authority");

            await RequireClosed(JsonSerializer.SerializeToUtf8Bytes(new {
                schema = "unknown-protocol",
                operation = "authorize",
                request_id = "wrong-version"
            }), "unknown startup wire protocol rejected");

            await RequireClosed(Encoding.UTF8.GetBytes(
                "{\"schema\":\"bke.standalone-startup.v1\"," +
                "\"operation\":\"authorize\",\"request_id\":\"a\"," +
                "\"request_id\":\"b\"}"),
                "duplicate JSON authority field rejected");

            await RequireClosed(Encoding.UTF8.GetBytes("not-json"),
                "malformed JSON rejected without granting process");

            Check(!File.Exists(Path.Combine(root, "grants.db")),
                "denied Host requests never wrote a grant to durable ledger");
            if (passed != 8)
                throw new InvalidOperationException(
                    $"Incomplete native Host startup certification: {passed}/8");
        }
        finally
        {
            await host.StopAsync(CancellationToken.None);
            host.Dispose();
            Directory.Delete(root, recursive: true);
        }
    }

    private static async Task<NamedPipeClientStream> ConnectAsync(
        CancellationToken cancellationToken)
    {
        var stream = new NamedPipeClientStream(
            ".", StandaloneStartupPipeHostedService.PipeName,
            PipeDirection.InOut, PipeOptions.Asynchronous,
            TokenImpersonationLevel.Impersonation);
        await stream.ConnectAsync(cancellationToken);
        return stream;
    }

    private static async Task WriteAsync(
        NamedPipeClientStream stream, byte[] data,
        CancellationToken cancellationToken)
    {
        var header = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(header, data.Length);
        await stream.WriteAsync(header, cancellationToken);
        await stream.WriteAsync(data, cancellationToken);
        await stream.FlushAsync(cancellationToken);
    }

    private static async Task<byte[]?> ReadAsync(
        NamedPipeClientStream stream, CancellationToken cancellationToken)
    {
        var header = new byte[4];
        var n = await stream.ReadAsync(header, cancellationToken);
        if (n == 0) return null;
        while (n < 4)
            n += await stream.ReadAsync(header.AsMemory(n), cancellationToken);
        var length = BinaryPrimitives.ReadInt32BigEndian(header);
        if (length is < 2 or > 1024)
            throw new InvalidDataException("Invalid Host startup response length.");
        var response = new byte[length];
        await stream.ReadExactlyAsync(response, cancellationToken);
        return response;
    }

    private sealed class Catalog : ISoftwareCatalogService
    {
        public Task<SoftwareCatalogResponse> GetAsync(
            SoftwareCatalogRequest request, CancellationToken ct) =>
            Task.FromResult(new SoftwareCatalogResponse(
                LocalAgentContract.SoftwareCatalogCapabilityId,
                LocalAgentContract.SoftwareCatalogContractVersion,
                "AUTH_REQUIRED", [], null));
    }

    private sealed class Commercial : IAuthorizationService
    {
        public Task<AuthorizationResponse> AuthorizeAsync(
            AuthorizeRequest request, CancellationToken ct) =>
            throw new InvalidOperationException(
                "Absent signed installed policy must never reach commercial verifier.");
    }
}
