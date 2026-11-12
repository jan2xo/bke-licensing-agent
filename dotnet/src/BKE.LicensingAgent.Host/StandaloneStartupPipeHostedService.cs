using System.Buffers.Binary;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Infrastructure;

namespace BKE.LicensingAgent.Host;

/// <summary>
/// PREPRODUCTION machine-local, OS-attested product startup rendezvous.
/// This is not HTTP and never accepts product-supplied identity, entitlement,
/// mode, key or path as authorization. The service is registered only under
/// the explicitly enabled, nonproduction Host bootstrap.
/// </summary>
public sealed class StandaloneStartupPipeHostedService : BackgroundService
{
    internal const string PipeName = "bke-licensing-agent-standalone-startup-v1";
    internal const string Protocol = "bke.standalone-startup.v1";
    private const int MaxMessageBytes = 1024;
    private const int ActiveConnections = 4;
    private static readonly Regex RequestIdPattern = new(
        "^[A-Za-z0-9._-]{1,64}$", RegexOptions.CultureInvariant);
    private readonly InstalledStandaloneStartupPolicyRegistry _policy;
    private readonly InstalledStandaloneStartupGrantAudit _audit;
    private readonly ISoftwareCatalogService _catalog;
    private readonly IAuthorizationService _commercial;
    private readonly IAccountProductOpenLeaseGate? _account;
    private readonly string _environment;
    private readonly ILogger<StandaloneStartupPipeHostedService> _logger;

    public StandaloneStartupPipeHostedService(
        InstalledStandaloneStartupPolicyRegistry policy,
        InstalledStandaloneStartupGrantAudit audit,
        ISoftwareCatalogService catalog,
        IAuthorizationService commercial,
        string environment,
        ILogger<StandaloneStartupPipeHostedService> logger,
        IAccountProductOpenLeaseGate? account = null)
    {
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _catalog = catalog ?? throw new ArgumentNullException(nameof(catalog));
        _commercial = commercial ?? throw new ArgumentNullException(nameof(commercial));
        _account = account;
        _environment = environment;
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!OperatingSystem.IsWindows() ||
            _environment is not ("development" or "certification" or "utm"))
            throw new InvalidOperationException(
                "Standalone startup pipe cannot run outside PREPRODUCTION Windows.");

        using var slots = new SemaphoreSlim(ActiveConnections, ActiveConnections);
        while (!stoppingToken.IsCancellationRequested)
        {
            // Bound resource consumption; each client has at most one request.
            await slots.WaitAsync(stoppingToken);
            NamedPipeServerStream? server = null;
            try
            {
                server = CreateSecurePipe();
                await server.WaitForConnectionAsync(stoppingToken);
                var accepted = server;
                server = null;
                _ = HandleAndReleaseAsync(accepted, slots, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                server?.Dispose();
                slots.Release();
                break;
            }
            catch (Exception exception)
            {
                server?.Dispose();
                slots.Release();
                _logger.LogError(exception,
                    "Standalone startup transport failed; stopping the gate.");
                // Deny rather than spinning an unprotected or relaxed pipe.
                throw;
            }
        }
    }

    private async Task HandleAndReleaseAsync(
        NamedPipeServerStream pipe, SemaphoreSlim slots,
        CancellationToken stopped)
    {
        try
        {
            using (pipe)
            using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(stopped))
            {
                timeout.CancelAfter(TimeSpan.FromSeconds(12));
                await HandleConnectedAsync(pipe, timeout.Token);
            }
        }
        catch (OperationCanceledException)
        {
            // Expired request receives no grant.
        }
        catch (Exception error)
        {
            _logger.LogWarning(error,
                "Standalone startup request denied by transport or authority.");
        }
        finally
        {
            slots.Release();
        }
    }

    internal async Task HandleConnectedAsync(
        NamedPipeServerStream pipe, CancellationToken cancellationToken)
    {
        if (!pipe.IsConnected)
            return;
        var header = new byte[4];
        await pipe.ReadExactlyAsync(header, cancellationToken);
        var length = BinaryPrimitives.ReadInt32BigEndian(header);
        if (length is < 2 or > MaxMessageBytes)
            return;
        var payload = new byte[length];
        await pipe.ReadExactlyAsync(payload, cancellationToken);

        string requestId;
        try
        {
            using var doc = JsonDocument.Parse(payload, new JsonDocumentOptions {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 4
            });
            var root = doc.RootElement;
            var names = root.ValueKind == JsonValueKind.Object
                ? root.EnumerateObject().Select(x => x.Name).ToArray()
                : Array.Empty<string>();
            if (names.Length != 3 ||
                !names.ToHashSet(StringComparer.Ordinal).SetEquals(
                    ["schema", "operation", "request_id"]) ||
                root.GetProperty("schema").ValueKind != JsonValueKind.String ||
                root.GetProperty("schema").GetString() != Protocol ||
                root.GetProperty("operation").ValueKind != JsonValueKind.String ||
                root.GetProperty("operation").GetString() != "authorize" ||
                root.GetProperty("request_id").ValueKind != JsonValueKind.String)
                return;
            requestId = root.GetProperty("request_id").GetString() ?? "";
            if (!RequestIdPattern.IsMatch(requestId))
                return;
        }
        catch (JsonException)
        {
            return;
        }
        catch (InvalidOperationException)
        {
            return;
        }

        var peer = new WindowsNamedPipeStandaloneStartupPeerAttestor(pipe);
        var authority = new StandaloneStartupAuthorizationService(
            peer, _policy, _policy, _catalog, _commercial,
            _account, _audit, _environment);
        var decision = await authority.AuthorizeConnectedPeerAsync(cancellationToken);

        // Reason is a stable code; the caller never supplies a credential or
        // license. No persistent token is returned to the product.
        var response = JsonSerializer.SerializeToUtf8Bytes(new {
            schema = Protocol,
            request_id = requestId,
            authorized = decision.Authorized,
            reason = decision.Reason
        });
        if (response.Length > MaxMessageBytes)
            throw new InvalidDataException("Startup response was oversized.");
        BinaryPrimitives.WriteInt32BigEndian(header, response.Length);
        await pipe.WriteAsync(header, cancellationToken);
        await pipe.WriteAsync(response, cancellationToken);
        await pipe.FlushAsync(cancellationToken);
    }

    private static NamedPipeServerStream CreateSecurePipe()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException();

        var security = new PipeSecurity();
        // The default pipe DACL may grant Everyone/anonymous read. Never use it.
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.NetworkSid, null),
            PipeAccessRights.ReadWrite, AccessControlType.Deny));
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
            PipeAccessRights.ReadWrite, AccessControlType.Allow));

        return NamedPipeServerStreamAcl.Create(
            PipeName, PipeDirection.InOut, ActiveConnections,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous,
            MaxMessageBytes, MaxMessageBytes, security);
    }
}
