using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Application;

public interface IAccountPrivacyRemote
{
    Task<RemoteAccountPrivacyResult> ListAsync(
        string accessToken,
        int limit,
        CancellationToken cancellationToken);

    Task<RemoteAccountPrivacyResult> CreateAsync(
        string accessToken,
        string requestType,
        string summary,
        CancellationToken cancellationToken);
}

public interface IAccountPrivacyService
{
    Task<AccountPrivacyListResponse> ListAsync(
        AccountPrivacyListRequest request,
        CancellationToken cancellationToken);

    Task<AccountPrivacyCreateResponse> CreateAsync(
        AccountPrivacyCreateRequest request,
        CancellationToken cancellationToken);
}

public sealed record RemoteAccountPrivacyItem(
    string Id,
    string Scope,
    string RequestType,
    string Status,
    string Summary,
    string? ResponseSummary,
    string? ReviewedAt,
    string? ClosedAt,
    string CreatedAt);

public sealed record RemoteAccountPrivacyResult(
    string Status,
    IReadOnlyList<string>? RequestTypes = null,
    IReadOnlyList<RemoteAccountPrivacyItem>? Items = null,
    string? RequestId = null,
    string? RequestType = null,
    string? RequestStatus = null,
    string? ErrorCode = null,
    bool Retryable = false);

public sealed class AccountPrivacyService : IAccountPrivacyService
{
    private readonly IAccountSessionService _accountSession;
    private readonly IAccountSessionSecretStore _secretStore;
    private readonly IAccountPrivacyRemote _remote;

    public AccountPrivacyService(
        IAccountSessionService accountSession,
        IAccountSessionSecretStore secretStore,
        IAccountPrivacyRemote remote)
    {
        _accountSession = accountSession;
        _secretStore = secretStore;
        _remote = remote;
    }

    public async Task<AccountPrivacyListResponse> ListAsync(
        AccountPrivacyListRequest request,
        CancellationToken cancellationToken)
    {
        var active = await ActiveAsync(request.CorrelationId, cancellationToken);
        if (active is null)
        {
            return ListResponse(
                "AUTH_REQUIRED",
                Array.Empty<string>(),
                Array.Empty<AccountPrivacyItem>(),
                Error(
                    "AUTH_REQUIRED",
                    "Sign in with BKE before opening privacy requests.",
                    false));
        }

        try
        {
            var result = await _remote.ListAsync(
                active.AccessToken,
                request.Limit,
                cancellationToken);

            if (result.Status != "ok" ||
                result.RequestTypes is null ||
                result.Items is null)
            {
                return ListResponse(
                    result.Status == "invalid_input" ? "INVALID_INPUT" : "FAILED",
                    Array.Empty<string>(),
                    Array.Empty<AccountPrivacyItem>(),
                    Error(
                        result.ErrorCode ?? "PRIVACY_UNAVAILABLE",
                        result.Status == "invalid_input"
                            ? "The privacy request query is invalid."
                            : "BKE privacy requests are temporarily unavailable.",
                        result.Retryable));
            }

            return ListResponse(
                "READY",
                result.RequestTypes,
                result.Items.Select(item => new AccountPrivacyItem(
                    item.Id,
                    item.Scope,
                    item.RequestType,
                    item.Status,
                    item.Summary,
                    item.ResponseSummary,
                    item.ReviewedAt,
                    item.ClosedAt,
                    item.CreatedAt)).ToArray(),
                null);
        }
        catch (UnauthorizedAccessException)
        {
            await _secretStore.ClearAsync(CancellationToken.None);
            return ListResponse(
                "AUTH_REQUIRED",
                Array.Empty<string>(),
                Array.Empty<AccountPrivacyItem>(),
                Error(
                    "SESSION_INVALID",
                    "The BKE account session is no longer valid. Sign in again.",
                    false));
        }
        catch (Exception error) when (
            error is HttpRequestException or
            InvalidDataException or
            TaskCanceledException)
        {
            return ListResponse(
                "FAILED",
                Array.Empty<string>(),
                Array.Empty<AccountPrivacyItem>(),
                Error(
                    "PRIVACY_UNAVAILABLE",
                    "BKE privacy requests are temporarily unavailable.",
                    true));
        }
    }

    public async Task<AccountPrivacyCreateResponse> CreateAsync(
        AccountPrivacyCreateRequest request,
        CancellationToken cancellationToken)
    {
        var active = await ActiveAsync(request.CorrelationId, cancellationToken);
        if (active is null)
        {
            return CreateResponse(
                "AUTH_REQUIRED",
                null,
                null,
                null,
                Error(
                    "AUTH_REQUIRED",
                    "Sign in with BKE before creating a privacy request.",
                    false));
        }

        try
        {
            var result = await _remote.CreateAsync(
                active.AccessToken,
                request.RequestType,
                request.Summary,
                cancellationToken);

            if (result.Status == "created" &&
                !string.IsNullOrWhiteSpace(result.RequestId) &&
                !string.IsNullOrWhiteSpace(result.RequestType) &&
                !string.IsNullOrWhiteSpace(result.RequestStatus))
            {
                return CreateResponse(
                    "CREATED",
                    result.RequestId,
                    result.RequestType,
                    result.RequestStatus,
                    null);
            }

            if (result.Status == "invalid_input")
            {
                return CreateResponse(
                    "INVALID_INPUT",
                    null,
                    null,
                    null,
                    Error(
                        result.ErrorCode ?? "INVALID_INPUT",
                        "The privacy request was not accepted.",
                        false));
            }

            return CreateResponse(
                "FAILED",
                null,
                null,
                null,
                Error(
                    result.ErrorCode ?? "PRIVACY_UNAVAILABLE",
                    result.Status == "rate_limited"
                        ? "Privacy requests are temporarily rate limited."
                        : "BKE privacy requests are temporarily unavailable.",
                    result.Retryable));
        }
        catch (UnauthorizedAccessException)
        {
            await _secretStore.ClearAsync(CancellationToken.None);
            return CreateResponse(
                "AUTH_REQUIRED",
                null,
                null,
                null,
                Error(
                    "SESSION_INVALID",
                    "The BKE account session is no longer valid. Sign in again.",
                    false));
        }
        catch (Exception error) when (
            error is HttpRequestException or
            InvalidDataException or
            TaskCanceledException)
        {
            return CreateResponse(
                "OUTCOME_UNKNOWN",
                null,
                null,
                null,
                Error(
                    "PRIVACY_CREATE_OUTCOME_UNKNOWN",
                    "The privacy request result could not be confirmed. Refresh the request list before submitting again.",
                    false));
        }
    }

    private async Task<ActiveAccountSessionState?> ActiveAsync(
        string correlationId,
        CancellationToken cancellationToken)
    {
        var status = await _accountSession.StatusAsync(
            new AccountSessionStatusRequest(correlationId),
            cancellationToken);
        if (status.Status != "AUTHENTICATED")
        {
            return null;
        }

        return await _secretStore.ReadAsync(cancellationToken)
            as ActiveAccountSessionState;
    }

    private static AccountPrivacyListResponse ListResponse(
        string status,
        IReadOnlyList<string> requestTypes,
        IReadOnlyList<AccountPrivacyItem> items,
        AccountPrivacyError? error) =>
        new(
            LocalAgentContract.AccountPrivacyCapabilityId,
            LocalAgentContract.AccountPrivacyContractVersion,
            status,
            requestTypes,
            items,
            error);

    private static AccountPrivacyCreateResponse CreateResponse(
        string status,
        string? requestId,
        string? requestType,
        string? requestStatus,
        AccountPrivacyError? error) =>
        new(
            LocalAgentContract.AccountPrivacyCapabilityId,
            LocalAgentContract.AccountPrivacyContractVersion,
            status,
            requestId,
            requestType,
            requestStatus,
            error);

    private static AccountPrivacyError Error(
        string code,
        string message,
        bool retryable) =>
        new(code, message, retryable);
}
