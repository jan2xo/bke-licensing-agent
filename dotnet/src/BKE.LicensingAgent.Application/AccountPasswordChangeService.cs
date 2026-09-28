using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Application;

public interface IAccountPasswordChangeRemote
{
    Task<RemoteAccountPasswordChangeResult> ChangeAsync(
        string accessToken,
        string currentPassword,
        string newPassword,
        CancellationToken cancellationToken);
}

public interface IAccountPasswordChangeService
{
    Task<AccountPasswordChangeResponse> ChangeAsync(
        AccountPasswordChangeRequest request,
        CancellationToken cancellationToken);
}

public sealed record RemoteAccountPasswordChangeResult(
    string Status,
    string? ErrorCode = null,
    bool Retryable = false);

public sealed class AccountPasswordChangeService : IAccountPasswordChangeService
{
    private readonly IAccountSessionService _accountSession;
    private readonly IAccountSessionSecretStore _secretStore;
    private readonly IAccountPasswordChangeRemote _remote;

    public AccountPasswordChangeService(
        IAccountSessionService accountSession,
        IAccountSessionSecretStore secretStore,
        IAccountPasswordChangeRemote remote)
    {
        _accountSession = accountSession;
        _secretStore = secretStore;
        _remote = remote;
    }

    public async Task<AccountPasswordChangeResponse> ChangeAsync(
        AccountPasswordChangeRequest request,
        CancellationToken cancellationToken)
    {
        var session = await _accountSession.StatusAsync(
            new AccountSessionStatusRequest(request.CorrelationId),
            cancellationToken);

        if (session.Status != "AUTHENTICATED")
        {
            return Response(
                "AUTH_REQUIRED",
                true,
                session.Error is null
                    ? Error(
                        "AUTH_REQUIRED",
                        "Sign in with BKE before changing the account password.",
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
                true,
                Error(
                    "SESSION_STATE_UNAVAILABLE",
                    "The BKE account session is not available to password change.",
                    false));
        }

        RemoteAccountPasswordChangeResult result;
        try
        {
            result = await _remote.ChangeAsync(
                active.AccessToken,
                request.CurrentPassword,
                request.NewPassword,
                cancellationToken);
        }
        catch (UnauthorizedAccessException)
        {
            await _secretStore.ClearAsync(CancellationToken.None);
            return Response(
                "AUTH_REQUIRED",
                true,
                Error(
                    "SESSION_INVALID",
                    "The BKE account session is no longer valid. Sign in again.",
                    false));
        }
        catch (OperationCanceledException)
        {
            // Once a credential mutation is submitted, cancellation can make the
            // outcome unknowable. Fail closed instead of retaining local custody.
            await _secretStore.ClearAsync(CancellationToken.None);
            throw;
        }
        catch (Exception error) when (
            error is HttpRequestException or InvalidDataException or TaskCanceledException)
        {
            await _secretStore.ClearAsync(CancellationToken.None);
            return Response(
                "REAUTHENTICATION_REQUIRED",
                true,
                Error(
                    "PASSWORD_CHANGE_OUTCOME_UNKNOWN",
                    "The password-change result could not be confirmed. Sign in again before retrying.",
                    false));
        }

        switch (result.Status)
        {
            case "changed":
                await _secretStore.ClearAsync(CancellationToken.None);
                return Response("CHANGED", true, null);
            case "invalid_credentials":
                return Response(
                    "INVALID_CREDENTIALS",
                    false,
                    Error(
                        "INVALID_CREDENTIALS",
                        "The current password was not accepted.",
                        false));
            case "invalid_input":
                return Response(
                    "INVALID_INPUT",
                    false,
                    Error(
                        result.ErrorCode ?? "INVALID_INPUT",
                        "The new password does not satisfy BKE account requirements.",
                        false));
            case "rate_limited":
                return Response(
                    "FAILED",
                    false,
                    Error(
                        result.ErrorCode ?? "RATE_LIMITED",
                        "Password change is temporarily rate limited. Try again later.",
                        true));
            case "password_provider_unavailable":
                return Response(
                    "FAILED",
                    false,
                    Error(
                        result.ErrorCode ?? "PASSWORD_PROVIDER_UNAVAILABLE",
                        "Password change is temporarily unavailable.",
                        true));
            default:
                await _secretStore.ClearAsync(CancellationToken.None);
                return Response(
                    "REAUTHENTICATION_REQUIRED",
                    true,
                    Error(
                        "INVALID_REMOTE_RESPONSE",
                        "Password change returned an unrecognized result. Sign in again before retrying.",
                        false));
        }
    }

    private static AccountPasswordChangeResponse Response(
        string status,
        bool reauthenticationRequired,
        AccountPasswordChangeError? error) =>
        new(
            LocalAgentContract.AccountPasswordChangeCapabilityId,
            LocalAgentContract.AccountPasswordChangeContractVersion,
            status,
            reauthenticationRequired,
            error);

    private static AccountPasswordChangeError Error(
        string code,
        string message,
        bool retryable) =>
        new(code, message, retryable);
}
