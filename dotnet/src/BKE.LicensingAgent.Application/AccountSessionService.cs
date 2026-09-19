using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Application;

public interface IAccountSessionRemote
{
    Task<RemoteAccountSessionStart> StartAsync(CancellationToken cancellationToken);

    Task<RemoteAccountSessionPoll> PollAsync(string deviceCode, CancellationToken cancellationToken);

    Task RevokeAsync(string? sessionId, string? refreshToken, string? deviceCode, CancellationToken cancellationToken);
}

public interface IAccountSessionSecretStore
{
    Task<AccountSessionStoredState?> ReadAsync(CancellationToken cancellationToken);

    Task WriteAsync(AccountSessionStoredState state, CancellationToken cancellationToken);

    Task ClearAsync(CancellationToken cancellationToken);
}

public abstract record AccountSessionStoredState;

public sealed record PendingAccountSessionState(
    string DeviceCode,
    string VerificationUri,
    string UserCode,
    DateTimeOffset ExpiresAt,
    TimeSpan PollInterval,
    DateTimeOffset NextPollAt) : AccountSessionStoredState;

public sealed record ActiveAccountSessionState(
    string AccessToken,
    string RefreshToken,
    string? SessionId,
    DateTimeOffset AccessTokenExpiresAt,
    AccountSessionAccount Account) : AccountSessionStoredState;

public sealed record RemoteAccountSessionStart(
    string DeviceCode,
    string VerificationUri,
    string UserCode,
    TimeSpan ExpiresIn,
    TimeSpan PollInterval);

public sealed record RemoteAccountSessionPoll(
    string Status,
    string? AccessToken = null,
    string? RefreshToken = null,
    string? SessionId = null,
    TimeSpan? ExpiresIn = null,
    AccountSessionAccount? Account = null);

public sealed class AccountSessionService : IAccountSessionService
{
    private static readonly TimeSpan SlowDownIncrement = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan MaxPollInterval = TimeSpan.FromSeconds(60);

    private readonly IAccountSessionRemote _remote;
    private readonly IAccountSessionSecretStore _store;
    private readonly TimeProvider _timeProvider;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public AccountSessionService(
        IAccountSessionRemote remote,
        IAccountSessionSecretStore store,
        TimeProvider? timeProvider = null)
    {
        _remote = remote;
        _store = store;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async Task<AccountSessionStartResponse> StartAsync(
        AccountSessionStartRequest request,
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var now = _timeProvider.GetUtcNow();
            var existing = await _store.ReadAsync(cancellationToken);

            if (existing is ActiveAccountSessionState active)
            {
                return StartResponse("AUTHENTICATED", null, null, null, null);
            }

            if (existing is PendingAccountSessionState pending && pending.ExpiresAt > now)
            {
                return StartResponse(
                    "PENDING",
                    pending.VerificationUri,
                    pending.UserCode,
                    pending.ExpiresAt,
                    null);
            }

            if (existing is not null)
            {
                await _store.ClearAsync(cancellationToken);
            }

            RemoteAccountSessionStart started;
            try
            {
                started = await _remote.StartAsync(cancellationToken);
            }
            catch
            {
                return StartResponse(
                    "FAILED",
                    null,
                    null,
                    null,
                    Error("REMOTE_UNAVAILABLE", "BKE account authorization is unavailable.", true));
            }

            if (!ValidRemoteStart(started, now))
            {
                return StartResponse(
                    "FAILED",
                    null,
                    null,
                    null,
                    Error("INVALID_REMOTE_RESPONSE", "BKE account authorization returned an invalid response.", false));
            }

            var expiresAt = now.Add(started.ExpiresIn);
            var state = new PendingAccountSessionState(
                started.DeviceCode,
                started.VerificationUri,
                started.UserCode,
                expiresAt,
                started.PollInterval,
                now);

            await _store.WriteAsync(state, cancellationToken);
            return StartResponse("PENDING", started.VerificationUri, started.UserCode, expiresAt, null);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<AccountSessionStatusResponse> StatusAsync(
        AccountSessionStatusRequest request,
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var now = _timeProvider.GetUtcNow();
            var state = await _store.ReadAsync(cancellationToken);

            if (state is null)
            {
                return StatusResponse("SIGNED_OUT", null, null);
            }

            if (state is ActiveAccountSessionState active)
            {
                return StatusResponse("AUTHENTICATED", active.Account, null);
            }

            var pending = (PendingAccountSessionState)state;
            if (pending.ExpiresAt <= now)
            {
                await _store.ClearAsync(cancellationToken);
                return StatusResponse(
                    "EXPIRED",
                    null,
                    Error("AUTHORIZATION_EXPIRED", "BKE account authorization expired.", false));
            }

            if (pending.NextPollAt > now)
            {
                return StatusResponse("PENDING", null, null);
            }

            RemoteAccountSessionPoll poll;
            try
            {
                poll = await _remote.PollAsync(pending.DeviceCode, cancellationToken);
            }
            catch
            {
                return StatusResponse(
                    "PENDING",
                    null,
                    Error("REMOTE_UNAVAILABLE", "BKE account authorization status is temporarily unavailable.", true));
            }

            return await ApplyPollAsync(pending, poll, now, cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<AccountSessionLogoutResponse> LogoutAsync(
        AccountSessionLogoutRequest request,
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var state = await _store.ReadAsync(cancellationToken);
            AccountSessionError? remoteError = null;

            try
            {
                switch (state)
                {
                    case ActiveAccountSessionState active:
                        await _remote.RevokeAsync(
                            active.SessionId,
                            active.RefreshToken,
                            null,
                            cancellationToken);
                        break;
                    case PendingAccountSessionState pending:
                        await _remote.RevokeAsync(
                            null,
                            null,
                            pending.DeviceCode,
                            cancellationToken);
                        break;
                }
            }
            catch
            {
                remoteError = Error(
                    "REMOTE_REVOKE_FAILED",
                    "The local BKE account session was cleared, but remote revocation could not be confirmed.",
                    true);
            }
            finally
            {
                await _store.ClearAsync(cancellationToken);
            }

            return new AccountSessionLogoutResponse(
                LocalAgentContract.AccountSessionCapabilityId,
                LocalAgentContract.AccountSessionContractVersion,
                "SIGNED_OUT",
                remoteError);
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<AccountSessionStatusResponse> ApplyPollAsync(
        PendingAccountSessionState pending,
        RemoteAccountSessionPoll poll,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        switch (poll.Status)
        {
            case "authorization_pending":
            {
                var next = pending with { NextPollAt = now.Add(pending.PollInterval) };
                await _store.WriteAsync(next, cancellationToken);
                return StatusResponse("PENDING", null, null);
            }
            case "slow_down":
            {
                var interval = pending.PollInterval.Add(SlowDownIncrement);
                if (interval > MaxPollInterval)
                {
                    interval = MaxPollInterval;
                }
                var next = pending with
                {
                    PollInterval = interval,
                    NextPollAt = now.Add(interval),
                };
                await _store.WriteAsync(next, cancellationToken);
                return StatusResponse("PENDING", null, null);
            }
            case "access_denied":
                await _store.ClearAsync(cancellationToken);
                return StatusResponse(
                    "DENIED",
                    null,
                    Error("ACCESS_DENIED", "BKE account authorization was denied.", false));
            case "expired_token":
                await _store.ClearAsync(cancellationToken);
                return StatusResponse(
                    "EXPIRED",
                    null,
                    Error("AUTHORIZATION_EXPIRED", "BKE account authorization expired.", false));
            case "approved":
                if (!ValidApprovedPoll(poll, now))
                {
                    await _store.ClearAsync(cancellationToken);
                    return StatusResponse(
                        "FAILED",
                        null,
                        Error("INVALID_REMOTE_RESPONSE", "BKE account authorization returned an invalid approval.", false));
                }
                var active = new ActiveAccountSessionState(
                    poll.AccessToken!,
                    poll.RefreshToken!,
                    poll.SessionId,
                    now.Add(poll.ExpiresIn!.Value),
                    poll.Account!);
                await _store.WriteAsync(active, cancellationToken);
                return StatusResponse("AUTHENTICATED", active.Account, null);
            default:
                await _store.ClearAsync(cancellationToken);
                return StatusResponse(
                    "FAILED",
                    null,
                    Error("INVALID_REMOTE_RESPONSE", "BKE account authorization returned an unknown state.", false));
        }
    }

    private static bool ValidRemoteStart(RemoteAccountSessionStart started, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(started.DeviceCode) ||
            string.IsNullOrWhiteSpace(started.UserCode) ||
            started.DeviceCode.Length > 2048 ||
            started.UserCode.Length > 64 ||
            started.ExpiresIn <= TimeSpan.Zero ||
            started.ExpiresIn > TimeSpan.FromMinutes(30) ||
            started.PollInterval < TimeSpan.FromSeconds(2) ||
            started.PollInterval > MaxPollInterval)
        {
            return false;
        }

        return Uri.TryCreate(started.VerificationUri, UriKind.Absolute, out var uri) &&
               uri.Scheme == Uri.UriSchemeHttps &&
               !string.IsNullOrWhiteSpace(uri.Host);
    }

    private static bool ValidApprovedPoll(RemoteAccountSessionPoll poll, DateTimeOffset now)
    {
        var account = poll.Account;
        return !string.IsNullOrWhiteSpace(poll.AccessToken) &&
               !string.IsNullOrWhiteSpace(poll.RefreshToken) &&
               poll.AccessToken!.Length <= 8192 &&
               poll.RefreshToken!.Length <= 8192 &&
               poll.ExpiresIn is { } expiresIn &&
               expiresIn > TimeSpan.Zero &&
               expiresIn <= TimeSpan.FromHours(24) &&
               account is not null &&
               !string.IsNullOrWhiteSpace(account.UserId) &&
               !string.IsNullOrWhiteSpace(account.Email) &&
               !string.IsNullOrWhiteSpace(account.AccountId) &&
               !string.IsNullOrWhiteSpace(account.DisplayName) &&
               account.AccountType is "INDIVIDUAL" or "ORGANIZATION";
    }

    private static AccountSessionStartResponse StartResponse(
        string status,
        string? verificationUri,
        string? userCode,
        DateTimeOffset? expiresAt,
        AccountSessionError? error) =>
        new(
            LocalAgentContract.AccountSessionCapabilityId,
            LocalAgentContract.AccountSessionContractVersion,
            status,
            verificationUri,
            userCode,
            expiresAt?.ToString("O"),
            error);

    private static AccountSessionStatusResponse StatusResponse(
        string status,
        AccountSessionAccount? account,
        AccountSessionError? error) =>
        new(
            LocalAgentContract.AccountSessionCapabilityId,
            LocalAgentContract.AccountSessionContractVersion,
            status,
            account,
            error);

    private static AccountSessionError Error(string code, string message, bool retryable) =>
        new(code, message, retryable);
}
