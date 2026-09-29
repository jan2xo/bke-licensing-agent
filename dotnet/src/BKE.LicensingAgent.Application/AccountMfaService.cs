using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Application;

public interface IAccountMfaRemote
{
    Task<RemoteAccountMfaResult> StatusAsync(string accessToken, CancellationToken cancellationToken);
    Task<RemoteAccountMfaResult> EnrollStartAsync(string accessToken, string currentPassword, CancellationToken cancellationToken);
    Task<RemoteAccountMfaResult> EnrollCompleteAsync(string accessToken, string currentPassword, string challengeToken, string code, CancellationToken cancellationToken);
    Task<RemoteAccountMfaResult> ChallengeAsync(string accessToken, string currentPassword, CancellationToken cancellationToken);
    Task<RemoteAccountMfaResult> DisableAsync(string accessToken, string currentPassword, string challengeToken, string code, CancellationToken cancellationToken);
    Task<RemoteAccountMfaResult> RegenerateRecoveryAsync(string accessToken, string currentPassword, string challengeToken, string code, CancellationToken cancellationToken);
}

public interface IAccountMfaService
{
    Task<AccountMfaStatusResponse> StatusAsync(AccountMfaStatusRequest request, CancellationToken cancellationToken);
    Task<AccountMfaChallengeResponse> EnrollStartAsync(AccountMfaEnrollStartRequest request, CancellationToken cancellationToken);
    Task<AccountMfaMutationResponse> EnrollCompleteAsync(AccountMfaEnrollCompleteRequest request, CancellationToken cancellationToken);
    Task<AccountMfaChallengeResponse> ChallengeAsync(AccountMfaProofChallengeRequest request, CancellationToken cancellationToken);
    Task<AccountMfaMutationResponse> DisableAsync(AccountMfaMutationRequest request, CancellationToken cancellationToken);
    Task<AccountMfaMutationResponse> RegenerateRecoveryAsync(AccountMfaMutationRequest request, CancellationToken cancellationToken);
}

public sealed record RemoteAccountMfaResult(
    string Status,
    bool Enabled = false,
    bool EnrollmentPending = false,
    int RecoveryCodesRemaining = 0,
    string? ChallengeToken = null,
    string? ExpiresAt = null,
    bool EmailSent = false,
    string? MfaReference = null,
    bool ReauthenticationRequired = false,
    bool? EnrollmentRequired = null,
    IReadOnlyList<string>? RecoveryCodes = null,
    string? ErrorCode = null,
    bool Retryable = false);

public sealed class AccountMfaService : IAccountMfaService
{
    private readonly IAccountSessionService _accountSession;
    private readonly IAccountSessionSecretStore _secretStore;
    private readonly IAccountMfaRemote _remote;

    public AccountMfaService(
        IAccountSessionService accountSession,
        IAccountSessionSecretStore secretStore,
        IAccountMfaRemote remote)
    {
        _accountSession = accountSession;
        _secretStore = secretStore;
        _remote = remote;
    }

    public async Task<AccountMfaStatusResponse> StatusAsync(
        AccountMfaStatusRequest request,
        CancellationToken cancellationToken)
    {
        var active = await ActiveAsync(request.CorrelationId, cancellationToken);
        if (active is null)
        {
            return StatusResponse("AUTH_REQUIRED", false, false, 0,
                Error("AUTH_REQUIRED", "Sign in with BKE before opening account security.", false));
        }

        try
        {
            var result = await _remote.StatusAsync(active.AccessToken, cancellationToken);
            if (result.Status != "ready")
            {
                return StatusResponse("FAILED", false, false, 0,
                    Error(result.ErrorCode ?? "MFA_UNAVAILABLE", "BKE account security is temporarily unavailable.", result.Retryable));
            }
            return StatusResponse("READY", result.Enabled, result.EnrollmentPending, result.RecoveryCodesRemaining, null);
        }
        catch (UnauthorizedAccessException)
        {
            await _secretStore.ClearAsync(CancellationToken.None);
            return StatusResponse("AUTH_REQUIRED", false, false, 0,
                Error("SESSION_INVALID", "The BKE account session is no longer valid. Sign in again.", false));
        }
        catch (Exception error) when (error is HttpRequestException or InvalidDataException or TaskCanceledException)
        {
            return StatusResponse("FAILED", false, false, 0,
                Error("MFA_UNAVAILABLE", "BKE account security is temporarily unavailable.", true));
        }
    }

    public Task<AccountMfaChallengeResponse> EnrollStartAsync(
        AccountMfaEnrollStartRequest request,
        CancellationToken cancellationToken) =>
        ChallengeLikeAsync(request.CorrelationId, request.CurrentPassword, true, cancellationToken);

    public Task<AccountMfaChallengeResponse> ChallengeAsync(
        AccountMfaProofChallengeRequest request,
        CancellationToken cancellationToken) =>
        ChallengeLikeAsync(request.CorrelationId, request.CurrentPassword, false, cancellationToken);

    public Task<AccountMfaMutationResponse> EnrollCompleteAsync(
        AccountMfaEnrollCompleteRequest request,
        CancellationToken cancellationToken) =>
        MutationAsync(
            request.CorrelationId,
            (active, ct) => _remote.EnrollCompleteAsync(
                active.AccessToken,
                request.CurrentPassword,
                request.ChallengeToken,
                request.Code,
                ct),
            "MFA_ENABLED",
            cancellationToken);

    public Task<AccountMfaMutationResponse> DisableAsync(
        AccountMfaMutationRequest request,
        CancellationToken cancellationToken) =>
        MutationAsync(
            request.CorrelationId,
            (active, ct) => _remote.DisableAsync(
                active.AccessToken,
                request.CurrentPassword,
                request.ChallengeToken,
                request.Code,
                ct),
            "MFA_DISABLED",
            cancellationToken);

    public Task<AccountMfaMutationResponse> RegenerateRecoveryAsync(
        AccountMfaMutationRequest request,
        CancellationToken cancellationToken) =>
        MutationAsync(
            request.CorrelationId,
            (active, ct) => _remote.RegenerateRecoveryAsync(
                active.AccessToken,
                request.CurrentPassword,
                request.ChallengeToken,
                request.Code,
                ct),
            "RECOVERY_CODES_REGENERATED",
            cancellationToken);

    private async Task<AccountMfaChallengeResponse> ChallengeLikeAsync(
        string correlationId,
        string currentPassword,
        bool enrollment,
        CancellationToken cancellationToken)
    {
        var active = await ActiveAsync(correlationId, cancellationToken);
        if (active is null)
        {
            return ChallengeResponse("AUTH_REQUIRED", null,
                Error("AUTH_REQUIRED", "Sign in with BKE before changing account security.", false));
        }

        try
        {
            var result = enrollment
                ? await _remote.EnrollStartAsync(active.AccessToken, currentPassword, cancellationToken)
                : await _remote.ChallengeAsync(active.AccessToken, currentPassword, cancellationToken);

            return result.Status switch
            {
                "challenge_issued" => ChallengeResponse("CHALLENGE_ISSUED", result, null),
                "invalid_credentials" => ChallengeResponse("INVALID_CREDENTIALS", null,
                    Error("INVALID_CREDENTIALS", "The current password was not accepted.", false)),
                "rate_limited" => ChallengeResponse("FAILED", null,
                    Error(result.ErrorCode ?? "RATE_LIMITED", "Account security is temporarily rate limited.", true)),
                "password_provider_unavailable" or "mfa_unavailable" => ChallengeResponse("FAILED", null,
                    Error(result.ErrorCode ?? "MFA_UNAVAILABLE", "BKE account security is temporarily unavailable.", true)),
                _ => ChallengeResponse("FAILED", null,
                    Error(result.ErrorCode ?? "INVALID_REMOTE_RESPONSE", "BKE account security returned an invalid state.", false)),
            };
        }
        catch (UnauthorizedAccessException)
        {
            await _secretStore.ClearAsync(CancellationToken.None);
            return ChallengeResponse("AUTH_REQUIRED", null,
                Error("SESSION_INVALID", "The BKE account session is no longer valid. Sign in again.", false));
        }
        catch (Exception error) when (error is HttpRequestException or InvalidDataException or TaskCanceledException)
        {
            return ChallengeResponse("FAILED", null,
                Error("MFA_UNAVAILABLE", "BKE account security is temporarily unavailable.", true));
        }
    }

    private async Task<AccountMfaMutationResponse> MutationAsync(
        string correlationId,
        Func<ActiveAccountSessionState, CancellationToken, Task<RemoteAccountMfaResult>> operation,
        string successStatus,
        CancellationToken cancellationToken)
    {
        var active = await ActiveAsync(correlationId, cancellationToken);
        if (active is null)
        {
            return MutationResponse("AUTH_REQUIRED", false, null, null,
                Error("AUTH_REQUIRED", "Sign in with BKE before changing account security.", false));
        }

        try
        {
            var result = await operation(active, cancellationToken);
            if (result.Status == "completed")
            {
                await _secretStore.ClearAsync(CancellationToken.None);
                return MutationResponse(
                    successStatus,
                    true,
                    result.EnrollmentRequired,
                    result.RecoveryCodes,
                    null);
            }

            if (result.Status is "invalid_credentials" or "invalid_mfa_challenge" or "invalid_mfa_code" or "invalid_input")
            {
                return MutationResponse(
                    result.Status.ToUpperInvariant(),
                    false,
                    null,
                    null,
                    Error(
                        result.ErrorCode ?? result.Status.ToUpperInvariant(),
                        result.Status == "invalid_credentials"
                            ? "The current password was not accepted."
                            : "The MFA proof was not accepted.",
                        false));
            }

            await _secretStore.ClearAsync(CancellationToken.None);
            return MutationResponse(
                "REAUTHENTICATION_REQUIRED",
                true,
                null,
                null,
                Error(
                    result.ErrorCode ?? "MFA_MUTATION_OUTCOME_UNKNOWN",
                    "The account-security result requires signing in again before retrying.",
                    result.Retryable));
        }
        catch (UnauthorizedAccessException)
        {
            await _secretStore.ClearAsync(CancellationToken.None);
            return MutationResponse("AUTH_REQUIRED", true, null, null,
                Error("SESSION_INVALID", "The BKE account session is no longer valid. Sign in again.", false));
        }
        catch (OperationCanceledException)
        {
            await _secretStore.ClearAsync(CancellationToken.None);
            throw;
        }
        catch (Exception error) when (error is HttpRequestException or InvalidDataException or TaskCanceledException)
        {
            await _secretStore.ClearAsync(CancellationToken.None);
            return MutationResponse(
                "REAUTHENTICATION_REQUIRED",
                true,
                null,
                null,
                Error(
                    "MFA_MUTATION_OUTCOME_UNKNOWN",
                    "The account-security result could not be confirmed. Sign in again before retrying.",
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
        if (status.Status != "AUTHENTICATED") return null;
        return await _secretStore.ReadAsync(cancellationToken) as ActiveAccountSessionState;
    }

    private static AccountMfaStatusResponse StatusResponse(
        string status,
        bool enabled,
        bool pending,
        int remaining,
        AccountMfaError? error) =>
        new(
            LocalAgentContract.AccountMfaCapabilityId,
            LocalAgentContract.AccountMfaContractVersion,
            status,
            enabled,
            pending,
            remaining,
            error);

    private static AccountMfaChallengeResponse ChallengeResponse(
        string status,
        RemoteAccountMfaResult? result,
        AccountMfaError? error) =>
        new(
            LocalAgentContract.AccountMfaCapabilityId,
            LocalAgentContract.AccountMfaContractVersion,
            status,
            result?.ChallengeToken,
            result?.ExpiresAt,
            result?.EmailSent ?? false,
            result?.MfaReference,
            error);

    private static AccountMfaMutationResponse MutationResponse(
        string status,
        bool reauthenticationRequired,
        bool? enrollmentRequired,
        IReadOnlyList<string>? recoveryCodes,
        AccountMfaError? error) =>
        new(
            LocalAgentContract.AccountMfaCapabilityId,
            LocalAgentContract.AccountMfaContractVersion,
            status,
            reauthenticationRequired,
            enrollmentRequired,
            recoveryCodes,
            error);

    private static AccountMfaError Error(string code, string message, bool retryable) =>
        new(code, message, retryable);
}
