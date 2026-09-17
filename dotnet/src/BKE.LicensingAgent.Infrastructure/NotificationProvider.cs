using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;
using Microsoft.Data.Sqlite;

namespace BKE.LicensingAgent.Infrastructure;

public sealed class NotificationProvider : INotificationService
{
    private const string LicenseRequired = "LICENSE_REQUIRED";
    private static readonly HashSet<string> RemoteCodes = new(StringComparer.Ordinal)
    {
        "BETA_ENDED",
        "TRIAL_ENDED",
        "FREE_SUPPORT_ENDED",
        "LICENSE_RENEWAL_REQUIRED",
    };

    private static readonly IReadOnlyDictionary<string, Presentation> Presentations =
        new Dictionary<string, Presentation>(StringComparer.Ordinal)
        {
            ["LICENSE_REQUIRED"] = new(
                "License required",
                "This installation is not currently authorized. A commercial license is required to continue.",
                "Licensing"),
            ["AGENT_UPDATE_AVAILABLE"] = new(
                "BKE Licensing Agent update",
                "A newer BKE Licensing Agent release is available.",
                "Update"),
            ["BETA_ENDED"] = new(
                "Beta period ended",
                "The free beta period for this product has ended. Commercial licensing now applies to continued use.",
                "Product"),
            ["TRIAL_ENDED"] = new(
                "Trial period ended",
                "The trial period for this product has ended. Purchase or activate a commercial license to continue using the software.",
                "Product"),
            ["FREE_SUPPORT_ENDED"] = new(
                "Free support period ended",
                "The complimentary support period for this product has ended. Continued support is available under the applicable commercial support terms.",
                "Product"),
            ["LICENSE_RENEWAL_REQUIRED"] = new(
                "License renewal required",
                "The current commercial license requires renewal. Renew the license to continue receiving licensed access and services.",
                "Licensing"),
        };

    private readonly AuthorizationProvider _authorization;
    private readonly string _databasePath;
    private readonly Uri _platformBaseUri;
    private readonly HttpClient _http;
    private readonly object _deliveryLock = new();
    private readonly Dictionary<string, HashSet<string>> _everyLaunchIds = new(StringComparer.Ordinal);

    public NotificationProvider(AuthorizationProvider authorization)
    {
        _authorization = authorization;
        var dataDir = Environment.GetEnvironmentVariable("BKE_AGENT_DATA_DIR")
            ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "share", "bke_licensing_agent");
        _databasePath = Path.Combine(dataDir, "agent.db");

        var platformBaseUrl = (Environment.GetEnvironmentVariable("BKE_PLATFORM_BASE_URL") ?? "https://jl-bke.com").TrimEnd('/');
        if (!Uri.TryCreate(platformBaseUrl, UriKind.Absolute, out var baseUri))
        {
            throw new InvalidOperationException("BKE_PLATFORM_BASE_URL is invalid");
        }
        var insecureCertificationLoopback =
            Environment.GetEnvironmentVariable("BKE_AGENT_VNEXT_ALLOW_INSECURE_LOCAL") == "1" &&
            baseUri.IsLoopback;
        if (!string.Equals(baseUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) &&
            !(insecureCertificationLoopback && string.Equals(baseUri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException("Product broadcast authority must use HTTPS");
        }
        _platformBaseUri = baseUri;
        _http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false })
        {
            Timeout = TimeSpan.FromSeconds(5),
        };
    }

    public async Task<TypedNotificationResponse> RequestAsync(
        TypedNotificationRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!string.Equals(request.Code, LicenseRequired, StringComparison.Ordinal))
        {
            return TypedRejected("unsupported_notification_code");
        }

        var decision = await _authorization.AuthorizeAsync(
            new AuthorizeRequest(request.ProductId, request.Version, request.InstallationId),
            cancellationToken);
        if (!ProductContextIsValid(decision))
        {
            return TypedRejected("invalid_product_context");
        }
        if (decision.Authorized)
        {
            return TypedRejected("product_already_authorized");
        }
        if (!string.Equals(decision.Reason, "activation_required", StringComparison.Ordinal))
        {
            return TypedRejected("notification_not_authoritative");
        }

        var row = EnsureNotification(request.ProductId, LicenseRequired, "warning", null, NotificationId(request.ProductId, LicenseRequired), false);
        return new TypedNotificationResponse(
            LocalAgentContract.TypedNotificationCapabilityId,
            LocalAgentContract.TypedNotificationContractVersion,
            "accepted",
            row.Id,
            LicenseRequired,
            "");
    }

    public async Task<NotificationFeedResponse> FeedAsync(
        NotificationFeedRequest request,
        CancellationToken cancellationToken)
    {
        var validation = await ValidateProductContextAsync(request.ProductId, request.Version, request.InstallationId, cancellationToken);
        if (validation is null)
        {
            return FeedFailed("InvalidRequest", "The notification product context is invalid.");
        }

        await TrySyncAsync(request.ProductId, request.Version, cancellationToken);
        var rows = ListNotifications(request.ProductId, request.IncludeDismissed, request.Limit);
        var items = new List<NotificationItem>();
        AuthorizationResponse? licenseDecision = null;
        foreach (var row in rows)
        {
            if (!NotExpired(row.ExpiresAt))
            {
                continue;
            }
            if (string.Equals(row.Code, LicenseRequired, StringComparison.Ordinal))
            {
                licenseDecision ??= validation;
                if (licenseDecision.Authorized || !string.Equals(licenseDecision.Reason, "activation_required", StringComparison.Ordinal))
                {
                    continue;
                }
            }

            if (!Presentations.TryGetValue(row.Code, out var presentation))
            {
                throw new InvalidDataException($"Unsupported persisted notification code: {row.Code}");
            }
            var everyLaunch = IsEveryLaunch(row.ProductId, row.Id);
            items.Add(new NotificationItem(
                row.Id,
                "bke-licensing-agent",
                presentation.Title,
                presentation.Body,
                presentation.Category,
                string.Equals(row.Severity, "warning", StringComparison.Ordinal) ? "Warning" : "Information",
                row.CreatedAt,
                row.ExpiresAt,
                everyLaunch ? "Unread" : StateName(row.State),
                everyLaunch ? "EVERY_LAUNCH" : "ONCE",
                Array.Empty<object>()));
        }

        return new NotificationFeedResponse(
            LocalAgentContract.NotificationInboxCapabilityId,
            LocalAgentContract.NotificationInboxContractVersion,
            "Succeeded",
            items,
            null);
    }

    public async Task<NotificationMutationResponse> MarkReadAsync(
        NotificationMutationRequest request,
        CancellationToken cancellationToken)
    {
        if (await ValidateProductContextAsync(request.ProductId, request.Version, request.InstallationId, cancellationToken) is null)
        {
            return MutationFailed("InvalidRequest", "The notification product context is invalid.");
        }

        using var connection = OpenDatabase();
        var state = NotificationState(connection, request.ProductId, request.NotificationId);
        if (state is null)
        {
            return Mutation("NotFound");
        }
        if (string.Equals(state, "unread", StringComparison.Ordinal))
        {
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE notifications SET state='read' WHERE id=$id AND product_id=$product_id AND state='unread'";
            command.Parameters.AddWithValue("$id", request.NotificationId);
            command.Parameters.AddWithValue("$product_id", request.ProductId);
            command.ExecuteNonQuery();
        }
        return Mutation("Succeeded");
    }

    public async Task<NotificationMutationResponse> DismissAsync(
        NotificationMutationRequest request,
        CancellationToken cancellationToken)
    {
        if (await ValidateProductContextAsync(request.ProductId, request.Version, request.InstallationId, cancellationToken) is null)
        {
            return MutationFailed("InvalidRequest", "The notification product context is invalid.");
        }

        using var connection = OpenDatabase();
        var state = NotificationState(connection, request.ProductId, request.NotificationId);
        if (state is null)
        {
            return Mutation("NotFound");
        }
        if (!string.Equals(state, "dismissed", StringComparison.Ordinal))
        {
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE notifications SET state='dismissed', dismissed_at=$dismissed_at WHERE id=$id AND product_id=$product_id";
            command.Parameters.AddWithValue("$dismissed_at", DateTimeOffset.UtcNow.ToString("O"));
            command.Parameters.AddWithValue("$id", request.NotificationId);
            command.Parameters.AddWithValue("$product_id", request.ProductId);
            command.ExecuteNonQuery();
        }
        return Mutation("Succeeded");
    }

    public async Task<NotificationUnreadCountResponse> UnreadCountAsync(
        NotificationContextRequest request,
        CancellationToken cancellationToken)
    {
        var validation = await ValidateProductContextAsync(request.ProductId, request.Version, request.InstallationId, cancellationToken);
        if (validation is null)
        {
            return CountFailed("InvalidRequest", "The notification product context is invalid.");
        }

        await TrySyncAsync(request.ProductId, request.Version, cancellationToken);
        var rows = ListNotifications(request.ProductId, false, 200);
        var count = 0;
        foreach (var row in rows)
        {
            if (!NotExpired(row.ExpiresAt))
            {
                continue;
            }
            if (string.Equals(row.Code, LicenseRequired, StringComparison.Ordinal) &&
                (validation.Authorized || !string.Equals(validation.Reason, "activation_required", StringComparison.Ordinal)))
            {
                continue;
            }
            if (string.Equals(row.State, "unread", StringComparison.Ordinal) || IsEveryLaunch(row.ProductId, row.Id))
            {
                count++;
            }
        }

        return new NotificationUnreadCountResponse(
            LocalAgentContract.NotificationInboxCapabilityId,
            LocalAgentContract.NotificationInboxContractVersion,
            "Succeeded",
            count,
            null);
    }

    private async Task<AuthorizationResponse?> ValidateProductContextAsync(
        string productId,
        string version,
        string installationId,
        CancellationToken cancellationToken)
    {
        var decision = await _authorization.AuthorizeAsync(
            new AuthorizeRequest(productId, version, installationId), cancellationToken);
        return ProductContextIsValid(decision) ? decision : null;
    }

    private static bool ProductContextIsValid(AuthorizationResponse decision) =>
        !string.Equals(decision.Reason, "unknown_product_or_version", StringComparison.Ordinal) &&
        !string.Equals(decision.Reason, "authorization_provider_unavailable", StringComparison.Ordinal);

    private async Task TrySyncAsync(string productId, string version, CancellationToken cancellationToken)
    {
        try
        {
            await SyncAsync(productId, version, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            // Broadcast delivery is best-effort and never becomes local authorization authority.
        }
    }

    private async Task SyncAsync(string productId, string version, CancellationToken cancellationToken)
    {
        var uri = new Uri(
            _platformBaseUri,
            $"/api/licensing-agent/notifications?product_id={Uri.EscapeDataString(productId)}&version={Uri.EscapeDataString(version)}");
        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.Accept.ParseAdd("application/json");
        request.Headers.UserAgent.ParseAdd("BKE-Licensing-Agent/1");
        using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        if (response.StatusCode != HttpStatusCode.OK)
        {
            throw new InvalidDataException($"Product broadcast authority returned HTTP {(int)response.StatusCode}");
        }
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object ||
            RequiredString(root, "capabilityId") != "bke.product-broadcasts" ||
            !root.TryGetProperty("contractVersion", out var contractVersion) || contractVersion.ValueKind != JsonValueKind.Number || contractVersion.GetInt32() != 1 ||
            RequiredString(root, "source") != "bke-digital-solutions" ||
            RequiredString(root, "productId") != productId ||
            RequiredString(root, "version") != version ||
            !root.TryGetProperty("broadcasts", out var broadcasts) || broadcasts.ValueKind != JsonValueKind.Array || broadcasts.GetArrayLength() > 32)
        {
            throw new InvalidDataException("Invalid product broadcast response");
        }

        var seenCodes = new HashSet<string>(StringComparer.Ordinal);
        var everyLaunch = new HashSet<string>(StringComparer.Ordinal);
        foreach (var raw in broadcasts.EnumerateArray())
        {
            if (raw.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidDataException("Invalid product broadcast item");
            }
            var broadcastId = RequiredString(raw, "broadcastId");
            if (!Guid.TryParse(broadcastId, out _))
            {
                throw new InvalidDataException("Invalid product broadcast id");
            }
            var code = RequiredString(raw, "code");
            if (!RemoteCodes.Contains(code))
            {
                throw new InvalidDataException("Unsupported product broadcast code");
            }
            if (RequiredString(raw, "audience") != "ALL_ACTIVE_CLIENTS")
            {
                throw new InvalidDataException("Unsupported product broadcast audience");
            }
            var priority = RequiredString(raw, "priority");
            if (priority is not ("LOW" or "NORMAL" or "HIGH" or "URGENT"))
            {
                throw new InvalidDataException("Invalid product broadcast priority");
            }
            var deliveryMode = "ONCE";
            if (raw.TryGetProperty("deliveryMode", out var deliveryElement))
            {
                if (deliveryElement.ValueKind != JsonValueKind.String)
                {
                    throw new InvalidDataException("Invalid product broadcast delivery mode");
                }
                deliveryMode = deliveryElement.GetString()!;
            }
            if (deliveryMode is not ("ONCE" or "EVERY_LAUNCH"))
            {
                throw new InvalidDataException("Invalid product broadcast delivery mode");
            }
            _ = RequiredString(raw, "publishedAt");
            _ = RequiredString(raw, "startsAt");
            string? endsAt = null;
            if (raw.TryGetProperty("endsAt", out var endsElement) && endsElement.ValueKind != JsonValueKind.Null)
            {
                if (endsElement.ValueKind != JsonValueKind.String)
                {
                    throw new InvalidDataException("Invalid product broadcast expiry");
                }
                endsAt = endsElement.GetString();
            }

            var severity = priority is "HIGH" or "URGENT" ? "warning" : "information";
            var notificationId = NotificationIdForBroadcast(broadcastId);
            var row = EnsureNotification(productId, code, severity, endsAt, notificationId, true);
            if (deliveryMode == "EVERY_LAUNCH")
            {
                everyLaunch.Add(row.Id);
            }
            seenCodes.Add(code);
        }

        var missingCodes = RemoteCodes.Where(code => !seenCodes.Contains(code)).ToArray();
        DeactivateCodes(productId, missingCodes);
        lock (_deliveryLock)
        {
            _everyLaunchIds[productId] = everyLaunch;
        }
    }

    private NotificationRow EnsureNotification(
        string productId,
        string code,
        string severity,
        string? expiresAt,
        string notificationId,
        bool replaceCampaign)
    {
        using var connection = OpenDatabase();
        using var transaction = connection.BeginTransaction();
        NotificationRow? existing;
        using (var select = connection.CreateCommand())
        {
            select.Transaction = transaction;
            select.CommandText = "SELECT id, product_id, code, severity, state, created_at, expires_at, dismissed_at FROM notifications WHERE product_id=$product_id AND code=$code";
            select.Parameters.AddWithValue("$product_id", productId);
            select.Parameters.AddWithValue("$code", code);
            using var reader = select.ExecuteReader();
            existing = reader.Read() ? ReadRow(reader) : null;
        }

        var createdAt = DateTimeOffset.UtcNow.ToString("O");
        if (existing is null)
        {
            using var insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = "INSERT INTO notifications (id, product_id, code, severity, state, created_at, expires_at, dismissed_at) VALUES ($id,$product_id,$code,$severity,'unread',$created_at,$expires_at,NULL)";
            insert.Parameters.AddWithValue("$id", notificationId);
            insert.Parameters.AddWithValue("$product_id", productId);
            insert.Parameters.AddWithValue("$code", code);
            insert.Parameters.AddWithValue("$severity", severity);
            insert.Parameters.AddWithValue("$created_at", createdAt);
            insert.Parameters.AddWithValue("$expires_at", (object?)expiresAt ?? DBNull.Value);
            insert.ExecuteNonQuery();
        }
        else if (replaceCampaign && !string.Equals(existing.Id, notificationId, StringComparison.Ordinal))
        {
            using var update = connection.CreateCommand();
            update.Transaction = transaction;
            update.CommandText = "UPDATE notifications SET id=$id,severity=$severity,state='unread',created_at=$created_at,expires_at=$expires_at,dismissed_at=NULL WHERE product_id=$product_id AND code=$code";
            update.Parameters.AddWithValue("$id", notificationId);
            update.Parameters.AddWithValue("$severity", severity);
            update.Parameters.AddWithValue("$created_at", createdAt);
            update.Parameters.AddWithValue("$expires_at", (object?)expiresAt ?? DBNull.Value);
            update.Parameters.AddWithValue("$product_id", productId);
            update.Parameters.AddWithValue("$code", code);
            update.ExecuteNonQuery();
        }
        else
        {
            using var update = connection.CreateCommand();
            update.Transaction = transaction;
            update.CommandText = "UPDATE notifications SET severity=$severity,expires_at=$expires_at WHERE product_id=$product_id AND code=$code";
            update.Parameters.AddWithValue("$severity", severity);
            update.Parameters.AddWithValue("$expires_at", (object?)expiresAt ?? DBNull.Value);
            update.Parameters.AddWithValue("$product_id", productId);
            update.Parameters.AddWithValue("$code", code);
            update.ExecuteNonQuery();
        }

        NotificationRow row;
        using (var select = connection.CreateCommand())
        {
            select.Transaction = transaction;
            select.CommandText = "SELECT id, product_id, code, severity, state, created_at, expires_at, dismissed_at FROM notifications WHERE product_id=$product_id AND code=$code";
            select.Parameters.AddWithValue("$product_id", productId);
            select.Parameters.AddWithValue("$code", code);
            using var reader = select.ExecuteReader();
            if (!reader.Read())
            {
                throw new InvalidDataException("Notification persistence failed");
            }
            row = ReadRow(reader);
        }
        transaction.Commit();
        return row;
    }

    private List<NotificationRow> ListNotifications(string productId, bool includeDismissed, int limit)
    {
        using var connection = OpenDatabase();
        using var command = connection.CreateCommand();
        command.CommandText = includeDismissed
            ? "SELECT id, product_id, code, severity, state, created_at, expires_at, dismissed_at FROM notifications WHERE product_id=$product_id ORDER BY created_at DESC LIMIT $limit"
            : "SELECT id, product_id, code, severity, state, created_at, expires_at, dismissed_at FROM notifications WHERE product_id=$product_id AND state != 'dismissed' ORDER BY created_at DESC LIMIT $limit";
        command.Parameters.AddWithValue("$product_id", productId);
        command.Parameters.AddWithValue("$limit", limit);
        using var reader = command.ExecuteReader();
        var rows = new List<NotificationRow>();
        while (reader.Read())
        {
            rows.Add(ReadRow(reader));
        }
        return rows;
    }

    private void DeactivateCodes(string productId, IReadOnlyCollection<string> codes)
    {
        if (codes.Count == 0)
        {
            return;
        }
        using var connection = OpenDatabase();
        using var transaction = connection.BeginTransaction();
        foreach (var code in codes)
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = "UPDATE notifications SET state='dismissed', dismissed_at=$dismissed_at WHERE product_id=$product_id AND code=$code AND state != 'dismissed'";
            command.Parameters.AddWithValue("$dismissed_at", DateTimeOffset.UtcNow.ToString("O"));
            command.Parameters.AddWithValue("$product_id", productId);
            command.Parameters.AddWithValue("$code", code);
            command.ExecuteNonQuery();
        }
        transaction.Commit();
    }

    private SqliteConnection OpenDatabase()
    {
        if (!File.Exists(_databasePath))
        {
            throw new InvalidDataException("Agent database does not exist");
        }
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = _databasePath,
            Mode = SqliteOpenMode.ReadWrite,
            Cache = SqliteCacheMode.Private,
        }.ToString());
        connection.Open();
        return connection;
    }

    private static string? NotificationState(SqliteConnection connection, string productId, string notificationId)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT state FROM notifications WHERE id=$id AND product_id=$product_id";
        command.Parameters.AddWithValue("$id", notificationId);
        command.Parameters.AddWithValue("$product_id", productId);
        return command.ExecuteScalar() as string;
    }

    private bool IsEveryLaunch(string productId, string notificationId)
    {
        lock (_deliveryLock)
        {
            return _everyLaunchIds.TryGetValue(productId, out var ids) && ids.Contains(notificationId);
        }
    }

    private static bool NotExpired(string? expiresAt)
    {
        if (expiresAt is null)
        {
            return true;
        }
        return DateTimeOffset.TryParse(expiresAt, out var expiry) && expiry > DateTimeOffset.UtcNow;
    }

    private static string StateName(string state) => state switch
    {
        "read" => "Read",
        "dismissed" => "Dismissed",
        _ => "Unread",
    };

    private static NotificationRow ReadRow(SqliteDataReader reader) => new(
        reader.GetString(0),
        reader.GetString(1),
        reader.GetString(2),
        reader.GetString(3),
        reader.GetString(4),
        reader.GetString(5),
        reader.IsDBNull(6) ? null : reader.GetString(6),
        reader.IsDBNull(7) ? null : reader.GetString(7));

    private static string RequiredString(JsonElement value, string property)
    {
        if (!value.TryGetProperty(property, out var element) || element.ValueKind != JsonValueKind.String)
        {
            throw new InvalidDataException($"Product broadcast {property} is invalid");
        }
        return element.GetString()!;
    }

    private static string NotificationId(string productId, string code) =>
        Uuid5("6ba7b8119dad11d180b400c04fd430c8", $"bke-notification:{productId}:{code}");

    private static string NotificationIdForBroadcast(string broadcastId) =>
        Uuid5("6ba7b8119dad11d180b400c04fd430c8", $"bke-product-broadcast:{broadcastId}");

    private static string Uuid5(string namespaceHex, string name)
    {
        var namespaceBytes = Convert.FromHexString(namespaceHex);
        var nameBytes = Encoding.UTF8.GetBytes(name);
        var data = new byte[namespaceBytes.Length + nameBytes.Length];
        Buffer.BlockCopy(namespaceBytes, 0, data, 0, namespaceBytes.Length);
        Buffer.BlockCopy(nameBytes, 0, data, namespaceBytes.Length, nameBytes.Length);
        var hash = SHA1.HashData(data);
        hash[6] = (byte)((hash[6] & 0x0f) | 0x50);
        hash[8] = (byte)((hash[8] & 0x3f) | 0x80);
        var hex = Convert.ToHexString(hash.AsSpan(0, 16)).ToLowerInvariant();
        return $"{hex[..8]}-{hex[8..12]}-{hex[12..16]}-{hex[16..20]}-{hex[20..32]}";
    }

    private static TypedNotificationResponse TypedRejected(string reason) => new(
        LocalAgentContract.TypedNotificationCapabilityId,
        LocalAgentContract.TypedNotificationContractVersion,
        "rejected",
        null,
        null,
        reason);

    private static NotificationFeedResponse FeedFailed(string code, string message) => new(
        LocalAgentContract.NotificationInboxCapabilityId,
        LocalAgentContract.NotificationInboxContractVersion,
        "Failed",
        Array.Empty<NotificationItem>(),
        new NotificationCapabilityError(code, message, false));

    private static NotificationMutationResponse Mutation(string status) => new(
        LocalAgentContract.NotificationInboxCapabilityId,
        LocalAgentContract.NotificationInboxContractVersion,
        status,
        null);

    private static NotificationMutationResponse MutationFailed(string code, string message) => new(
        LocalAgentContract.NotificationInboxCapabilityId,
        LocalAgentContract.NotificationInboxContractVersion,
        "Failed",
        new NotificationCapabilityError(code, message, false));

    private static NotificationUnreadCountResponse CountFailed(string code, string message) => new(
        LocalAgentContract.NotificationInboxCapabilityId,
        LocalAgentContract.NotificationInboxContractVersion,
        "Failed",
        0,
        new NotificationCapabilityError(code, message, false));

    private sealed record Presentation(string Title, string Body, string Category);
    private sealed record NotificationRow(
        string Id,
        string ProductId,
        string Code,
        string Severity,
        string State,
        string CreatedAt,
        string? ExpiresAt,
        string? DismissedAt);
}
