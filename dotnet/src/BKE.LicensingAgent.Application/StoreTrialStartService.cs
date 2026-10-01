using System.Text.Json;
using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Application;

public interface IStoreTrialStartRemote
{
    Task<RemoteStoreTrialStartResult> StartAsync(
        string accessToken,
        StoreTrialStartRequest request,
        CancellationToken cancellationToken);
}

public interface IStoreTrialStartService
{
    Task<StoreTrialStartResponse> StartAsync(
        StoreTrialStartRequest request,
        CancellationToken cancellationToken);
}

public sealed record RemoteStoreTrialStartResult(
    string Status,
    string CorrelationId,
    string? TrialEndsAt = null,
    string? GraceEndsAt = null,
    string? ErrorCode = null);

public sealed class StoreTrialStartService : IStoreTrialStartService
{
    private readonly IAccountSessionService _accountSession;
    private readonly IAccountSessionSecretStore _secretStore;
    private readonly IStoreTrialStartRemote _remote;

    public StoreTrialStartService(
        IAccountSessionService accountSession,
        IAccountSessionSecretStore secretStore,
        IStoreTrialStartRemote remote)
    {
        _accountSession = accountSession;
        _secretStore = secretStore;
        _remote = remote;
    }

    public async Task<StoreTrialStartResponse> StartAsync(
        StoreTrialStartRequest request,
        CancellationToken cancellationToken)
    {
        var session = await _accountSession.StatusAsync(
            new AccountSessionStatusRequest(request.CorrelationId),
            cancellationToken);
        if (session.Status != "AUTHENTICATED")
        {
            return Response(
                "AUTH_REQUIRED",
                request.CorrelationId,
                error: Error(
                    session.Error?.Code ?? "AUTH_REQUIRED",
                    session.Error?.Message ??
                        "Sign in with a BKE account before starting a trial."));
        }

        var stored = await _secretStore.ReadAsync(cancellationToken);
        if (stored is not ActiveAccountSessionState active)
        {
            return Response(
                "AUTH_REQUIRED",
                request.CorrelationId,
                error: Error(
                    "SESSION_STATE_UNAVAILABLE",
                    "The BKE account session is not available to start a trial."));
        }

        RemoteStoreTrialStartResult result;
        try
        {
            result = await _remote.StartAsync(
                active.AccessToken,
                request,
                cancellationToken);
        }
        catch (UnauthorizedAccessException)
        {
            await _secretStore.ClearAsync(CancellationToken.None);
            return Response(
                "AUTH_REQUIRED",
                request.CorrelationId,
                error: Error(
                    "SESSION_INVALID",
                    "The BKE account session is no longer valid. Sign in again."));
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception error) when (
            error is HttpRequestException or TaskCanceledException)
        {
            return Response(
                "RESULT_UNKNOWN",
                request.CorrelationId,
                error: Error(
                    "TRIAL_START_RESULT_UNKNOWN",
                    "The trial request may have reached BKE Digital Solutions, but the result could not be confirmed. Refresh authoritative software/account state before trying again."));
        }
        catch (Exception error) when (
            error is InvalidDataException or JsonException)
        {
            return Response(
                "FAILED",
                request.CorrelationId,
                error: Error(
                    "INVALID_REMOTE_RESPONSE",
                    "Trial authority returned an invalid response."));
        }

        if (!string.Equals(
                result.CorrelationId,
                request.CorrelationId,
                StringComparison.Ordinal))
        {
            return Response(
                "FAILED",
                request.CorrelationId,
                error: Error(
                    "CORRELATION_MISMATCH",
                    "Trial authority returned a mismatched correlation identifier."));
        }

        if (result.Status == "started")
        {
            if (string.IsNullOrWhiteSpace(result.TrialEndsAt) ||
                string.IsNullOrWhiteSpace(result.GraceEndsAt))
            {
                return Response(
                    "FAILED",
                    request.CorrelationId,
                    error: Error(
                        "INVALID_REMOTE_RESPONSE",
                        "Trial authority omitted required trial timestamps."));
            }

            return Response(
                "STARTED",
                request.CorrelationId,
                result.TrialEndsAt,
                result.GraceEndsAt);
        }

        var code = result.ErrorCode ?? "TRIAL_START_FAILED";
        return code switch
        {
            "TRIAL_ALREADY_USED_THIS_YEAR" =>
                Response(
                    "ALREADY_USED",
                    request.CorrelationId,
                    error: Error(
                        code,
                        "This account already used its self-service trial for this product during the current calendar year.")),
            "LEGAL_REACCEPTANCE_REQUIRED" =>
                Response(
                    "LEGAL_REACCEPTANCE_REQUIRED",
                    request.CorrelationId,
                    error: Error(
                        code,
                        "Current BKE Legal documents must be accepted before a trial can start.")),
            "FORBIDDEN" or "ACCOUNT_ROLE_FORBIDDEN" =>
                Response(
                    "ACCOUNT_FORBIDDEN",
                    request.CorrelationId,
                    error: Error(
                        code,
                        "This BKE account role cannot start a self-service trial.")),
            "ACCOUNT_NOT_ACTIVE" or
            "ACCOUNT_NOT_FOUND" =>
                Response(
                    "ACCOUNT_UNAVAILABLE",
                    request.CorrelationId,
                    error: Error(
                        code,
                        "The authenticated BKE account is not available for self-service trials.")),
            "NOT_FOUND" =>
                Response(
                    "EDITION_NOT_AVAILABLE",
                    request.CorrelationId,
                    error: Error(
                        code,
                        "The selected Store edition is no longer available. Refresh the Store.")),
            "RATE_LIMITED" =>
                Response(
                    "FAILED",
                    request.CorrelationId,
                    error: Error(
                        code,
                        "Trial start is temporarily rate limited.")),
            _ =>
                Response(
                    "FAILED",
                    request.CorrelationId,
                    error: Error(
                        code,
                        "The self-service trial could not be started. No automatic retry will be attempted.")),
        };
    }

    private static StoreTrialStartResponse Response(
        string status,
        string correlationId,
        string? trialEndsAt = null,
        string? graceEndsAt = null,
        StoreTrialStartError? error = null) =>
        new(
            LocalAgentContract.StoreTrialStartCapabilityId,
            LocalAgentContract.StoreTrialStartContractVersion,
            status,
            correlationId,
            trialEndsAt,
            graceEndsAt,
            error);

    private static StoreTrialStartError Error(
        string code,
        string message) =>
        new(code, message, false);
}
