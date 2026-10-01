using System.Text.Json;
using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Application;

public interface IAccountRecentAuthRemote
{
    Task<RemoteAccountRecentAuthResult> StartAsync(
        string accessToken,
        string currentPassword,
        CancellationToken cancellationToken);

    Task<RemoteAccountRecentAuthResult> CompleteAsync(
        string accessToken,
        string challengeToken,
        string code,
        CancellationToken cancellationToken);
}

public interface IAccountRecentAuthService
{
    Task<AccountRecentAuthResponse> StartAsync(
        AccountRecentAuthStartRequest request,
        CancellationToken cancellationToken);

    Task<AccountRecentAuthResponse> CompleteAsync(
        AccountRecentAuthCompleteRequest request,
        CancellationToken cancellationToken);
}

public sealed record RemoteAccountRecentAuthResult(
    string Status,
    string? RecentAuthenticatedUntil = null,
    string? ChallengeToken = null,
    string? ExpiresAt = null,
    bool? EmailSent = null,
    string? MfaReference = null,
    string? ErrorCode = null,
    bool Retryable = false);

public sealed class AccountRecentAuthService : IAccountRecentAuthService
{
    private readonly IAccountSessionService _accountSession;
    private readonly IAccountSessionSecretStore _secretStore;
    private readonly IAccountRecentAuthRemote _remote;

    public AccountRecentAuthService(
        IAccountSessionService accountSession,
        IAccountSessionSecretStore secretStore,
        IAccountRecentAuthRemote remote)
    {
        _accountSession = accountSession;
        _secretStore = secretStore;
        _remote = remote;
    }

    public async Task<AccountRecentAuthResponse> StartAsync(
        AccountRecentAuthStartRequest request,
        CancellationToken cancellationToken)
    {
        var active = await ActiveAsync(
            request.CorrelationId,
            cancellationToken);
        if (active is null)
        {
            return Response(
                "AUTH_REQUIRED",
                request.CorrelationId,
                error: Error(
                    "AUTH_REQUIRED",
                    "Sign in with BKE before confirming recent authentication.",
                    false));
        }

        RemoteAccountRecentAuthResult result;
        try
        {
            result = await _remote.StartAsync(
                active.AccessToken,
                request.CurrentPassword,
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
                    "The BKE account session is no longer valid. Sign in again.",
                    false));
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
                    "RECENT_AUTH_START_RESULT_UNKNOWN",
                    "Recent authentication may have started remotely, but the result could not be confirmed. Do not automatically replay the password proof.",
                    false));
        }
        catch (Exception error) when (
            error is InvalidDataException or JsonException)
        {
            return Response(
                "FAILED",
                request.CorrelationId,
                error: Error(
                    "INVALID_REMOTE_RESPONSE",
                    "Recent-auth authority returned an invalid response.",
                    false));
        }

        return MapResult(result, request.CorrelationId);
    }

    public async Task<AccountRecentAuthResponse> CompleteAsync(
        AccountRecentAuthCompleteRequest request,
        CancellationToken cancellationToken)
    {
        var active = await ActiveAsync(
            request.CorrelationId,
            cancellationToken);
        if (active is null)
        {
            return Response(
                "AUTH_REQUIRED",
                request.CorrelationId,
                error: Error(
                    "AUTH_REQUIRED",
                    "Sign in with BKE before completing recent authentication.",
                    false));
        }

        RemoteAccountRecentAuthResult result;
        try
        {
            result = await _remote.CompleteAsync(
                active.AccessToken,
                request.ChallengeToken,
                request.Code,
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
                    "The BKE account session is no longer valid. Sign in again.",
                    false));
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
                    "RECENT_AUTH_COMPLETE_RESULT_UNKNOWN",
                    "Recent authentication may have completed remotely, but the result could not be confirmed. Do not automatically replay the MFA proof.",
                    false));
        }
        catch (Exception error) when (
            error is InvalidDataException or JsonException)
        {
            return Response(
                "FAILED",
                request.CorrelationId,
                error: Error(
                    "INVALID_REMOTE_RESPONSE",
                    "Recent-auth authority returned an invalid response.",
                    false));
        }

        return MapResult(result, request.CorrelationId);
    }

    private static AccountRecentAuthResponse MapResult(
        RemoteAccountRecentAuthResult result,
        string correlationId) =>
        result.Status switch
        {
            "verified" when
                !string.IsNullOrWhiteSpace(
                    result.RecentAuthenticatedUntil) =>
                Response(
                    "VERIFIED",
                    correlationId,
                    recentAuthenticatedUntil:
                        result.RecentAuthenticatedUntil),
            "mfa_challenge_issued" when
                !string.IsNullOrWhiteSpace(result.ChallengeToken) &&
                !string.IsNullOrWhiteSpace(result.ExpiresAt) &&
                result.EmailSent.HasValue &&
                !string.IsNullOrWhiteSpace(result.MfaReference) =>
                Response(
                    "MFA_CHALLENGE_ISSUED",
                    correlationId,
                    challengeToken: result.ChallengeToken,
                    expiresAt: result.ExpiresAt,
                    emailSent: result.EmailSent,
                    mfaReference: result.MfaReference),
            "invalid_credentials" =>
                Response(
                    "INVALID_CREDENTIALS",
                    correlationId,
                    error: Error(
                        result.ErrorCode ?? "INVALID_CREDENTIALS",
                        "The current password was not accepted.",
                        false)),
            "invalid_mfa_challenge" =>
                Response(
                    "INVALID_MFA_CHALLENGE",
                    correlationId,
                    error: Error(
                        result.ErrorCode ?? "INVALID_MFA_CHALLENGE",
                        "The MFA challenge is no longer valid.",
                        false)),
            "invalid_mfa_code" =>
                Response(
                    "INVALID_MFA_CODE",
                    correlationId,
                    error: Error(
                        result.ErrorCode ?? "INVALID_MFA_CODE",
                        "The MFA code was not accepted.",
                        false)),
            "rate_limited" =>
                Response(
                    "FAILED",
                    correlationId,
                    error: Error(
                        result.ErrorCode ?? "RATE_LIMITED",
                        "Recent authentication is temporarily rate limited.",
                        true)),
            "password_provider_unavailable" or "mfa_unavailable" =>
                Response(
                    "FAILED",
                    correlationId,
                    error: Error(
                        result.ErrorCode ?? "RECENT_AUTH_UNAVAILABLE",
                        "Recent authentication is temporarily unavailable.",
                        true)),
            "invalid_input" =>
                Response(
                    "FAILED",
                    correlationId,
                    error: Error(
                        result.ErrorCode ?? "INVALID_INPUT",
                        "Recent-auth authority rejected the proof request.",
                        false)),
            _ =>
                Response(
                    "FAILED",
                    correlationId,
                    error: Error(
                        result.ErrorCode ?? "INVALID_REMOTE_RESPONSE",
                        "Recent-auth authority returned an invalid state.",
                        false)),
        };

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

    private static AccountRecentAuthResponse Response(
        string status,
        string correlationId,
        string? recentAuthenticatedUntil = null,
        string? challengeToken = null,
        string? expiresAt = null,
        bool? emailSent = null,
        string? mfaReference = null,
        AccountRecentAuthError? error = null) =>
        new(
            LocalAgentContract.AccountRecentAuthCapabilityId,
            LocalAgentContract.AccountRecentAuthContractVersion,
            status,
            correlationId,
            recentAuthenticatedUntil,
            challengeToken,
            expiresAt,
            emailSent,
            mfaReference,
            error);

    private static AccountRecentAuthError Error(
        string code,
        string message,
        bool retryable) =>
        new(code, message, retryable);
}
