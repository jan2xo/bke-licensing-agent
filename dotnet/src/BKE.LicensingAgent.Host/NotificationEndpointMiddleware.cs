using System.Text.Json;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Host;

public sealed class NotificationEndpointMiddleware
{
    private static readonly HashSet<string> NotificationPaths = new(StringComparer.Ordinal)
    {
        LocalAgentContract.RequestNotificationPath,
        LocalAgentContract.NotificationFeedPath,
        LocalAgentContract.AccountNotificationFeedPath,
        LocalAgentContract.AccountNotificationReceiptPath,
        LocalAgentContract.NotificationMarkReadPath,
        LocalAgentContract.NotificationDismissPath,
        LocalAgentContract.NotificationUnreadCountPath,
    };

    private readonly RequestDelegate _next;

    public NotificationEndpointMiddleware(RequestDelegate next) => _next = next;

    public async Task InvokeAsync(HttpContext context, INotificationService service)
    {
        var path = context.Request.Path.Value ?? string.Empty;
        if (!HttpMethods.IsPost(context.Request.Method) || !NotificationPaths.Contains(path))
        {
            await _next(context);
            return;
        }

        context.Response.Headers.CacheControl = "no-store";
        var typed = string.Equals(path, LocalAgentContract.RequestNotificationPath, StringComparison.Ordinal);
        var accountFeed = string.Equals(path, LocalAgentContract.AccountNotificationFeedPath, StringComparison.Ordinal);
        var accountReceipt = string.Equals(path, LocalAgentContract.AccountNotificationReceiptPath, StringComparison.Ordinal);

        if (context.Request.Headers.ContainsKey("Origin"))
        {
            if (typed)
            {
                await GenericFailure(context, 403, "browser_origin_rejected");
            }
            else
            {
                await NotificationFailure(context, accountFeed, accountReceipt, 403, "Rejected", "Browser-origin requests are not allowed.", false);
            }
            return;
        }

        var mediaType = context.Request.ContentType?.Split(';', 2)[0].Trim();
        if (!string.Equals(mediaType, "application/json", StringComparison.OrdinalIgnoreCase))
        {
            if (typed)
            {
                await GenericFailure(context, 415, "invalid_content_type");
            }
            else
            {
                await NotificationFailure(context, accountFeed, accountReceipt, 415, "InvalidRequest", "Notification requests must use application/json.", false);
            }
            return;
        }

        var hasLength = context.Request.Headers.ContainsKey("Content-Length");
        var hasTransfer = context.Request.Headers.ContainsKey("Transfer-Encoding");
        if (hasLength && hasTransfer)
        {
            await GenericFailure(context, 400, "ambiguous_request_framing");
            return;
        }
        if (hasTransfer)
        {
            var codings = context.Request.Headers.TransferEncoding
                .SelectMany(value => value?.Split(',') ?? Array.Empty<string>())
                .Select(value => value.Trim())
                .Where(value => value.Length > 0)
                .ToArray();
            if (codings.Length != 1 || !string.Equals(codings[0], "chunked", StringComparison.OrdinalIgnoreCase))
            {
                await GenericFailure(context, 400, "unsupported_transfer_encoding");
                return;
            }
        }
        else if (!hasLength)
        {
            await GenericFailure(context, 411, "content_length_required");
            return;
        }

        if (context.Request.ContentLength is < 0)
        {
            await GenericFailure(context, 400, "invalid_content_length");
            return;
        }
        if (context.Request.ContentLength > LocalAgentContract.MaxJsonBodyBytes)
        {
            await GenericFailure(context, 413, "payload_too_large");
            return;
        }

        byte[] raw;
        try
        {
            raw = await ReadBoundedBodyAsync(context.Request, context.RequestAborted);
        }
        catch (InvalidDataException exception) when (exception.Message == "payload_too_large")
        {
            await GenericFailure(context, 413, "payload_too_large");
            return;
        }
        catch
        {
            await GenericFailure(context, 400, "invalid_request_body");
            return;
        }

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(raw);
        }
        catch (JsonException)
        {
            if (typed)
            {
                await TypedFailure(context, 400, "invalid_notification_request");
            }
            else
            {
                await NotificationFailure(context, accountFeed, accountReceipt, 400, "InvalidRequest", "Invalid notification request.", false);
            }
            return;
        }

        using (document)
        {
            try
            {
                if (document.RootElement.ValueKind != JsonValueKind.Object)
                {
                    if (typed)
                    {
                        await TypedFailure(context, 400, "invalid_notification_request");
                    }
                    else
                    {
                        await NotificationFailure(context, accountFeed, accountReceipt, 400, "InvalidRequest", "Invalid notification request.", false);
                    }
                    return;
                }

                if (typed)
                {
                    await HandleTyped(context, service, document.RootElement);
                }
                else if (accountFeed)
                {
                    await HandleAccountFeed(context, service, document.RootElement);
                }
                else if (accountReceipt)
                {
                    await HandleAccountReceipt(context, service, document.RootElement);
                }
                else
                {
                    await HandleInbox(context, service, document.RootElement, path);
                }
            }
            catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
            {
                throw;
            }
            catch
            {
                if (typed)
                {
                    await TypedFailure(context, 400, "invalid_notification_request");
                }
                else
                {
                    await NotificationFailure(context, accountFeed, accountReceipt, 500, "Unknown", "The notification provider failed.", true);
                }
            }
        }
    }

    private static async Task HandleTyped(HttpContext context, INotificationService service, JsonElement body)
    {
        if (!HasExactKeys(body, "product_id", "version", "installation_id", "code") ||
            !TryBoundedString(body, "product_id", 128, out var productId) ||
            !TryBoundedString(body, "version", 64, out var version) ||
            !TryBoundedString(body, "installation_id", 256, out var installationId) ||
            !TryBoundedString(body, "code", 64, out var code))
        {
            await TypedFailure(context, 400, "invalid_notification_request");
            return;
        }

        var result = await service.RequestAsync(
            new TypedNotificationRequest(productId!, version!, installationId!, code!),
            context.RequestAborted);
        await WriteJson(context, 200, result);
    }

    private static async Task HandleAccountFeed(
        HttpContext context,
        INotificationService service,
        JsonElement body)
    {
        if (!HasExactKeys(body, "limit") ||
            !body.TryGetProperty("limit", out var limitElement) ||
            limitElement.ValueKind != JsonValueKind.Number ||
            !limitElement.TryGetInt32(out var limit) ||
            limit is < 1 or > 200)
        {
            await AccountInboxFailure(
                context,
                400,
                "InvalidRequest",
                "Invalid account notification feed request.",
                false);
            return;
        }

        await WriteJson(
            context,
            200,
            await service.AccountFeedAsync(
                new AccountNotificationFeedRequest(limit),
                context.RequestAborted));
    }

    private static async Task HandleAccountReceipt(
        HttpContext context,
        INotificationService service,
        JsonElement body)
    {
        if (!HasExactKeys(body, "notification_id", "action") ||
            !TryBoundedString(body, "notification_id", 160, out var notificationId) ||
            !TryBoundedString(body, "action", 32, out var action) ||
            action is not ("MARK_READ" or "DISMISS"))
        {
            await AccountReceiptFailure(
                context,
                400,
                "InvalidRequest",
                "Invalid account notification receipt request.",
                false);
            return;
        }

        await WriteJson(
            context,
            200,
            await service.AccountReceiptAsync(
                new AccountNotificationReceiptRequest(notificationId!, action!),
                context.RequestAborted));
    }

    private static async Task HandleInbox(
        HttpContext context,
        INotificationService service,
        JsonElement body,
        string path)
    {
        if (!TryBoundedString(body, "product_id", 128, out var productId) ||
            !TryBoundedString(body, "version", 64, out var version) ||
            !TryBoundedString(body, "installation_id", 256, out var installationId))
        {
            await InboxFailure(context, 400, "InvalidRequest", "Invalid notification product context.", false);
            return;
        }

        if (string.Equals(path, LocalAgentContract.NotificationFeedPath, StringComparison.Ordinal))
        {
            if (!HasExactKeys(body, "product_id", "version", "installation_id", "limit", "include_dismissed"))
            {
                await InboxFailure(context, 400, "InvalidRequest", "Invalid notification feed request.", false);
                return;
            }
            if (!body.TryGetProperty("limit", out var limitElement) ||
                limitElement.ValueKind != JsonValueKind.Number || !limitElement.TryGetInt32(out var limit) || limit is < 1 or > 200 ||
                !body.TryGetProperty("include_dismissed", out var includeElement) ||
                includeElement.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
            {
                await InboxFailure(context, 400, "InvalidRequest", "Invalid notification feed query.", false);
                return;
            }
            await WriteJson(context, 200, await service.FeedAsync(
                new NotificationFeedRequest(productId!, version!, installationId!, limit, includeElement.GetBoolean()),
                context.RequestAborted));
            return;
        }

        if (string.Equals(path, LocalAgentContract.NotificationUnreadCountPath, StringComparison.Ordinal))
        {
            if (!HasExactKeys(body, "product_id", "version", "installation_id"))
            {
                await InboxFailure(context, 400, "InvalidRequest", "Invalid unread-count request.", false);
                return;
            }
            await WriteJson(context, 200, await service.UnreadCountAsync(
                new NotificationContextRequest(productId!, version!, installationId!),
                context.RequestAborted));
            return;
        }

        if (!HasExactKeys(body, "product_id", "version", "installation_id", "notification_id"))
        {
            await InboxFailure(context, 400, "InvalidRequest", "Invalid notification lifecycle request.", false);
            return;
        }
        if (!TryBoundedString(body, "notification_id", 128, out var notificationId))
        {
            await InboxFailure(context, 400, "InvalidRequest", "Invalid notification identifier.", false);
            return;
        }

        var request = new NotificationMutationRequest(productId!, version!, installationId!, notificationId!);
        var result = string.Equals(path, LocalAgentContract.NotificationMarkReadPath, StringComparison.Ordinal)
            ? await service.MarkReadAsync(request, context.RequestAborted)
            : await service.DismissAsync(request, context.RequestAborted);
        await WriteJson(context, 200, result);
    }

    private static bool HasExactKeys(JsonElement body, params string[] expected)
    {
        var keys = body.EnumerateObject().Select(property => property.Name).ToHashSet(StringComparer.Ordinal);
        return keys.SetEquals(expected);
    }

    private static bool TryBoundedString(JsonElement body, string name, int maxLength, out string? value)
    {
        value = null;
        if (!body.TryGetProperty(name, out var element) || element.ValueKind != JsonValueKind.String)
        {
            return false;
        }
        value = element.GetString();
        return !string.IsNullOrWhiteSpace(value) && value.Length <= maxLength;
    }

    private static async Task<byte[]> ReadBoundedBodyAsync(HttpRequest request, CancellationToken cancellationToken)
    {
        await using var buffer = new MemoryStream();
        var chunk = new byte[8192];
        while (true)
        {
            var read = await request.Body.ReadAsync(chunk.AsMemory(), cancellationToken);
            if (read == 0)
            {
                return buffer.ToArray();
            }
            if (buffer.Length + read > LocalAgentContract.MaxJsonBodyBytes)
            {
                throw new InvalidDataException("payload_too_large");
            }
            await buffer.WriteAsync(chunk.AsMemory(0, read), cancellationToken);
        }
    }

    private static Task GenericFailure(HttpContext context, int statusCode, string reason) =>
        WriteJson(context, statusCode, new { outcome = "failed", reason });

    private static Task TypedFailure(HttpContext context, int statusCode, string reason) =>
        WriteJson(context, statusCode, new TypedNotificationResponse(
            LocalAgentContract.TypedNotificationCapabilityId,
            LocalAgentContract.TypedNotificationContractVersion,
            "rejected", null, null, reason));

    private static Task InboxFailure(
        HttpContext context,
        int statusCode,
        string code,
        string message,
        bool retryable) =>
        WriteJson(context, statusCode, new NotificationMutationResponse(
            LocalAgentContract.NotificationInboxCapabilityId,
            LocalAgentContract.NotificationInboxContractVersion,
            "Failed",
            new NotificationCapabilityError(code, message, retryable)));

    private static Task AccountInboxFailure(
        HttpContext context,
        int statusCode,
        string code,
        string message,
        bool retryable) =>
        WriteJson(context, statusCode, new AccountNotificationFeedResponse(
            LocalAgentContract.AccountNotificationInboxCapabilityId,
            LocalAgentContract.AccountNotificationInboxContractVersion,
            "Failed",
            Array.Empty<AccountNotificationItem>(),
            new NotificationCapabilityError(code, message, retryable)));

    private static Task AccountReceiptFailure(
        HttpContext context,
        int statusCode,
        string code,
        string message,
        bool retryable) =>
        WriteJson(context, statusCode, new AccountNotificationReceiptResponse(
            LocalAgentContract.AccountNotificationInboxCapabilityId,
            LocalAgentContract.AccountNotificationInboxContractVersion,
            "Failed",
            null,
            null,
            new NotificationCapabilityError(code, message, retryable)));

    private static Task NotificationFailure(
        HttpContext context,
        bool accountFeed,
        bool accountReceipt,
        int statusCode,
        string code,
        string message,
        bool retryable)
    {
        if (accountFeed)
        {
            return AccountInboxFailure(context, statusCode, code, message, retryable);
        }
        if (accountReceipt)
        {
            return AccountReceiptFailure(context, statusCode, code, message, retryable);
        }
        return InboxFailure(context, statusCode, code, message, retryable);
    }

    private static async Task WriteJson<T>(HttpContext context, int statusCode, T body)
    {
        context.Response.StatusCode = statusCode;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsJsonAsync(body, cancellationToken: context.RequestAborted);
    }
}
