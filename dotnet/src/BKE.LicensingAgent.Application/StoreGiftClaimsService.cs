using System.Text.Json;
using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Application;

public interface IStoreGiftClaimsRemote
{
    Task<RemoteStoreGiftClaimsListResult> ListAsync(
        string accessToken,
        string correlationId,
        CancellationToken cancellationToken);

    Task<RemoteStoreGiftClaimPersistentRevealResult> RevealAsync(
        string accessToken,
        string correlationId,
        string giftClaimHandle,
        CancellationToken cancellationToken);
}

public interface IStoreGiftClaimsService
{
    Task<StoreGiftClaimsResponse> ListAsync(
        StoreGiftClaimsRequest request,
        CancellationToken cancellationToken);

    Task<StoreGiftClaimPersistentRevealResponse> RevealAsync(
        StoreGiftClaimPersistentRevealRequest request,
        CancellationToken cancellationToken);
}

public sealed record RemoteStoreGiftClaimsListResult(
    string Status,
    string CorrelationId,
    string? AccountLifecycleState = null,
    IReadOnlyList<StoreGiftClaimItem>? Claims = null,
    string? ErrorCode = null,
    bool Retryable = false);

public sealed record RemoteStoreGiftClaimPersistentRevealResult(
    string Status,
    string CorrelationId,
    string? GiftClaimHandle = null,
    string? ClaimCode = null,
    string? ErrorCode = null,
    bool Retryable = false);

public sealed class StoreGiftClaimsService : IStoreGiftClaimsService
{
    private readonly IAccountSessionService _accountSession;
    private readonly IAccountSessionSecretStore _secretStore;
    private readonly IStoreGiftClaimsRemote _remote;

    public StoreGiftClaimsService(
        IAccountSessionService accountSession,
        IAccountSessionSecretStore secretStore,
        IStoreGiftClaimsRemote remote)
    {
        _accountSession = accountSession;
        _secretStore = secretStore;
        _remote = remote;
    }

    public async Task<StoreGiftClaimsResponse> ListAsync(
        StoreGiftClaimsRequest request,
        CancellationToken cancellationToken)
    {
        var active = await ActiveAsync(
            request.CorrelationId,
            cancellationToken);
        if (active is null)
        {
            return ListResponse(
                "AUTH_REQUIRED",
                request.CorrelationId,
                error: Error(
                    "AUTH_REQUIRED",
                    "Sign in with BKE before viewing purchased Gift Claim Codes.",
                    false));
        }

        RemoteStoreGiftClaimsListResult result;
        try
        {
            result = await _remote.ListAsync(
                active.AccessToken,
                request.CorrelationId,
                cancellationToken);
        }
        catch (UnauthorizedAccessException)
        {
            await _secretStore.ClearAsync(CancellationToken.None);
            return ListResponse(
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
            return ListResponse(
                "UNAVAILABLE",
                request.CorrelationId,
                error: Error(
                    "GIFT_CLAIMS_UNAVAILABLE",
                    "Gift Claim Code history is temporarily unavailable.",
                    true));
        }
        catch (Exception error) when (
            error is InvalidDataException or JsonException)
        {
            return ListResponse(
                "FAILED",
                request.CorrelationId,
                error: Error(
                    "INVALID_REMOTE_RESPONSE",
                    "Gift Claim Code authority returned an invalid response.",
                    false));
        }

        if (!string.Equals(
                result.CorrelationId,
                request.CorrelationId,
                StringComparison.Ordinal))
        {
            return ListResponse(
                "FAILED",
                request.CorrelationId,
                error: Error(
                    "CORRELATION_MISMATCH",
                    "Gift Claim Code authority returned a mismatched correlation identifier.",
                    false));
        }

        if (result.Status == "ready")
        {
            if (string.IsNullOrWhiteSpace(result.AccountLifecycleState) ||
                result.Claims is null)
            {
                return ListResponse(
                    "FAILED",
                    request.CorrelationId,
                    error: Error(
                        "INVALID_REMOTE_RESPONSE",
                        "Gift Claim Code authority omitted required metadata.",
                        false));
            }

            return ListResponse(
                "READY",
                request.CorrelationId,
                result.AccountLifecycleState,
                result.Claims);
        }

        return result.Status switch
        {
            "account_forbidden" =>
                ListResponse(
                    "ACCOUNT_FORBIDDEN",
                    request.CorrelationId,
                    error: Error(
                        result.ErrorCode ?? "ACCOUNT_ROLE_FORBIDDEN",
                        "This BKE account role cannot manage Gift Claim Codes.",
                        false)),
            "account_not_found" or "account_not_active" or
            "suspended_account" or "closed_account" =>
                ListResponse(
                    "ACCOUNT_UNAVAILABLE",
                    request.CorrelationId,
                    error: Error(
                        result.ErrorCode ?? "ACCOUNT_UNAVAILABLE",
                        "The selected BKE account cannot manage Gift Claim Codes.",
                        false)),
            "legal_reacceptance_required" =>
                ListResponse(
                    "LEGAL_REACCEPTANCE_REQUIRED",
                    request.CorrelationId,
                    error: Error(
                        result.ErrorCode ?? "LEGAL_REACCEPTANCE_REQUIRED",
                        "Current BKE Legal documents must be accepted before Gift Claim Codes can be managed.",
                        false)),
            "rate_limited" =>
                ListResponse(
                    "UNAVAILABLE",
                    request.CorrelationId,
                    error: Error(
                        result.ErrorCode ?? "RATE_LIMITED",
                        "Gift Claim Code history is temporarily rate limited.",
                        true)),
            _ =>
                ListResponse(
                    "FAILED",
                    request.CorrelationId,
                    error: Error(
                        result.ErrorCode ?? "GIFT_CLAIMS_FAILED",
                        "Gift Claim Code history could not be loaded.",
                        result.Retryable)),
        };
    }

    public async Task<StoreGiftClaimPersistentRevealResponse> RevealAsync(
        StoreGiftClaimPersistentRevealRequest request,
        CancellationToken cancellationToken)
    {
        var active = await ActiveAsync(
            request.CorrelationId,
            cancellationToken);
        if (active is null)
        {
            return RevealResponse(
                "AUTH_REQUIRED",
                request.CorrelationId,
                error: Error(
                    "AUTH_REQUIRED",
                    "Sign in with BKE before revealing a Gift Claim Code.",
                    false));
        }

        RemoteStoreGiftClaimPersistentRevealResult result;
        try
        {
            result = await _remote.RevealAsync(
                active.AccessToken,
                request.CorrelationId,
                request.GiftClaimHandle,
                cancellationToken);
        }
        catch (UnauthorizedAccessException)
        {
            await _secretStore.ClearAsync(CancellationToken.None);
            return RevealResponse(
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
            return RevealResponse(
                "RESULT_UNKNOWN",
                request.CorrelationId,
                error: Error(
                    "GIFT_CLAIM_REVEAL_RESULT_UNKNOWN",
                    "The reveal request may have reached BKE Digital Solutions, but the result could not be confirmed. Do not automatically replay the secret reveal.",
                    false));
        }
        catch (Exception error) when (
            error is InvalidDataException or JsonException)
        {
            return RevealResponse(
                "FAILED",
                request.CorrelationId,
                error: Error(
                    "INVALID_REMOTE_RESPONSE",
                    "Gift Claim Code authority returned an invalid reveal response.",
                    false));
        }

        if (!string.Equals(
                result.CorrelationId,
                request.CorrelationId,
                StringComparison.Ordinal))
        {
            return RevealResponse(
                "FAILED",
                request.CorrelationId,
                error: Error(
                    "CORRELATION_MISMATCH",
                    "Gift Claim Code authority returned a mismatched correlation identifier.",
                    false));
        }

        return result.Status switch
        {
            "available" when
                string.Equals(
                    result.GiftClaimHandle,
                    request.GiftClaimHandle,
                    StringComparison.Ordinal) &&
                !string.IsNullOrWhiteSpace(result.ClaimCode) =>
                RevealResponse(
                    "AVAILABLE",
                    request.CorrelationId,
                    result.GiftClaimHandle,
                    result.ClaimCode),
            "available" =>
                RevealResponse(
                    "FAILED",
                    request.CorrelationId,
                    error: Error(
                        "INVALID_REMOTE_RESPONSE",
                        "Gift Claim Code authority omitted required reveal fields.",
                        false)),
            "recent_auth_required" =>
                RevealResponse(
                    "RECENT_AUTH_REQUIRED",
                    request.CorrelationId,
                    error: Error(
                        "RECENT_AUTH_REQUIRED",
                        "Confirm the current account credentials before revealing this Gift Claim Code.",
                        false)),
            "account_forbidden" =>
                RevealResponse(
                    "ACCOUNT_FORBIDDEN",
                    request.CorrelationId,
                    error: Error(
                        "ACCOUNT_ROLE_FORBIDDEN",
                        "This BKE account role cannot reveal Gift Claim Codes.",
                        false)),
            "account_not_found" or "account_not_active" or
            "suspended_account" or "closed_account" =>
                RevealResponse(
                    "ACCOUNT_UNAVAILABLE",
                    request.CorrelationId,
                    error: Error(
                        "ACCOUNT_UNAVAILABLE",
                        "The selected BKE account cannot reveal this Gift Claim Code.",
                        false)),
            "claim_code_not_found" =>
                RevealResponse(
                    "NOT_FOUND",
                    request.CorrelationId,
                    error: Error(
                        "CLAIM_CODE_NOT_FOUND",
                        "This Gift Claim Code is not available in the selected account.",
                        false)),
            "claim_code_already_used" =>
                RevealResponse(
                    "ALREADY_USED",
                    request.CorrelationId,
                    error: Error(
                        "CLAIM_CODE_ALREADY_USED",
                        "This Gift Claim Code has already been redeemed.",
                        false)),
            "claim_code_revoked" =>
                RevealResponse(
                    "REVOKED",
                    request.CorrelationId,
                    error: Error(
                        "CLAIM_CODE_REVOKED",
                        "This Gift Claim Code has been revoked.",
                        false)),
            "claim_code_expired" =>
                RevealResponse(
                    "EXPIRED",
                    request.CorrelationId,
                    error: Error(
                        "CLAIM_CODE_EXPIRED",
                        "This Gift Claim Code has expired.",
                        false)),
            "legal_reacceptance_required" =>
                RevealResponse(
                    "LEGAL_REACCEPTANCE_REQUIRED",
                    request.CorrelationId,
                    error: Error(
                        result.ErrorCode ?? "LEGAL_REACCEPTANCE_REQUIRED",
                        "Current BKE Legal documents must be accepted before this Gift Claim Code can be revealed.",
                        false)),
            "rate_limited" or "claim_code_unavailable" =>
                RevealResponse(
                    "UNAVAILABLE",
                    request.CorrelationId,
                    error: Error(
                        result.ErrorCode ?? "CLAIM_CODE_UNAVAILABLE",
                        "Gift Claim Code reveal is temporarily unavailable.",
                        true)),
            _ =>
                RevealResponse(
                    "FAILED",
                    request.CorrelationId,
                    error: Error(
                        result.ErrorCode ?? "GIFT_CLAIM_REVEAL_FAILED",
                        "Gift Claim Code reveal failed closed.",
                        result.Retryable)),
        };
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

    private static StoreGiftClaimsResponse ListResponse(
        string status,
        string correlationId,
        string? accountLifecycleState = null,
        IReadOnlyList<StoreGiftClaimItem>? claims = null,
        StoreGiftClaimsError? error = null) =>
        new(
            LocalAgentContract.StoreGiftClaimsCapabilityId,
            LocalAgentContract.StoreGiftClaimsContractVersion,
            status,
            correlationId,
            accountLifecycleState,
            claims ?? Array.Empty<StoreGiftClaimItem>(),
            error);

    private static StoreGiftClaimPersistentRevealResponse RevealResponse(
        string status,
        string correlationId,
        string? giftClaimHandle = null,
        string? claimCode = null,
        StoreGiftClaimsError? error = null) =>
        new(
            LocalAgentContract.StoreGiftClaimPersistentRevealCapabilityId,
            LocalAgentContract.StoreGiftClaimPersistentRevealContractVersion,
            status,
            correlationId,
            giftClaimHandle,
            claimCode,
            error);

    private static StoreGiftClaimsError Error(
        string code,
        string message,
        bool retryable) =>
        new(code, message, retryable);
}
