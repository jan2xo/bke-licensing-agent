using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Application;

public interface IClaimCodeRedemptionRemote
{
    Task<RemoteClaimCodeRedemptionResult> RedeemAsync(
        string accessToken,
        string code,
        CancellationToken cancellationToken);
}

public interface IClaimCodeRedemptionService
{
    Task<ClaimCodeRedeemResponse> RedeemAsync(
        ClaimCodeRedeemRequest request,
        CancellationToken cancellationToken);
}

public sealed record RemoteClaimCodeRedemptionResult(
    string Status,
    string? AccountId = null,
    string? EntitlementId = null);

public sealed class ClaimCodeRedemptionService : IClaimCodeRedemptionService
{
    private readonly IAccountSessionService _accountSession;
    private readonly IAccountSessionSecretStore _secretStore;
    private readonly IClaimCodeRedemptionRemote _remote;

    public ClaimCodeRedemptionService(
        IAccountSessionService accountSession,
        IAccountSessionSecretStore secretStore,
        IClaimCodeRedemptionRemote remote)
    {
        _accountSession = accountSession;
        _secretStore = secretStore;
        _remote = remote;
    }

    public async Task<ClaimCodeRedeemResponse> RedeemAsync(
        ClaimCodeRedeemRequest request,
        CancellationToken cancellationToken)
    {
        var session = await _accountSession.StatusAsync(
            new AccountSessionStatusRequest(request.CorrelationId),
            cancellationToken);

        if (session.Status != "AUTHENTICATED")
        {
            return Response(
                "AUTH_REQUIRED",
                null,
                null,
                session.Error is null
                    ? Error(
                        "AUTH_REQUIRED",
                        "Sign in with a BKE account before redeeming a Claim Code.",
                        false)
                    : Error(
                        session.Error.Code,
                        session.Error.Message,
                        session.Error.Retryable));
        }

        var stored = await _secretStore.ReadAsync(cancellationToken);
        if (stored is not ActiveAccountSessionState active)
        {
            return Response(
                "AUTH_REQUIRED",
                null,
                null,
                Error(
                    "SESSION_STATE_UNAVAILABLE",
                    "The BKE account session is not available to Claim Code redemption.",
                    false));
        }

        RemoteClaimCodeRedemptionResult result;
        try
        {
            result = await _remote.RedeemAsync(
                active.AccessToken,
                request.Code,
                cancellationToken);
        }
        catch (UnauthorizedAccessException)
        {
            await _secretStore.ClearAsync(cancellationToken);
            return Response(
                "AUTH_REQUIRED",
                null,
                null,
                Error(
                    "SESSION_INVALID",
                    "The BKE account session is no longer valid. Sign in again.",
                    false));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (HttpRequestException)
        {
            return Response(
                "FAILED",
                null,
                null,
                Error(
                    "REMOTE_UNAVAILABLE",
                    "Claim Code redemption is temporarily unavailable.",
                    true));
        }
        catch (InvalidDataException)
        {
            return Response(
                "FAILED",
                null,
                null,
                Error(
                    "INVALID_REMOTE_RESPONSE",
                    "Claim Code redemption returned an invalid response.",
                    false));
        }

        return result.Status switch
        {
            "claimed" => Response(
                "CLAIMED",
                result.AccountId,
                result.EntitlementId,
                null),
            "claim_code_not_found" => Response(
                "NOT_FOUND",
                null,
                null,
                Error(
                    "CLAIM_CODE_NOT_FOUND",
                    "The Claim Code was not found.",
                    false)),
            "claim_code_already_used" => Response(
                "ALREADY_USED",
                null,
                null,
                Error(
                    "CLAIM_CODE_ALREADY_USED",
                    "The Claim Code has already been redeemed.",
                    false)),
            "claim_code_revoked" => Response(
                "REVOKED",
                null,
                null,
                Error(
                    "CLAIM_CODE_REVOKED",
                    "The Claim Code has been revoked.",
                    false)),
            "claim_code_expired" => Response(
                "EXPIRED",
                null,
                null,
                Error(
                    "CLAIM_CODE_EXPIRED",
                    "The Claim Code has expired.",
                    false)),
            "account_forbidden" => Response(
                "ACCOUNT_FORBIDDEN",
                null,
                null,
                Error(
                    "ACCOUNT_FORBIDDEN",
                    "This account role cannot receive Claim Code entitlements.",
                    false)),
            "account_not_found" or "account_not_active" or
            "suspended_account" or "closed_account" => Response(
                "ACCOUNT_UNAVAILABLE",
                null,
                null,
                Error(
                    "ACCOUNT_UNAVAILABLE",
                    "The authenticated BKE account cannot receive this Claim Code.",
                    false)),
            _ => throw new InvalidDataException(
                "Unknown Claim Code redemption authority status."),
        };
    }

    private static ClaimCodeRedeemResponse Response(
        string status,
        string? accountId,
        string? entitlementId,
        ClaimCodeRedeemError? error) =>
        new(
            LocalAgentContract.ClaimCodeRedemptionCapabilityId,
            LocalAgentContract.ClaimCodeRedemptionContractVersion,
            status,
            accountId,
            entitlementId,
            error);

    private static ClaimCodeRedeemError Error(
        string code,
        string message,
        bool retryable) =>
        new(code, message, retryable);
}
