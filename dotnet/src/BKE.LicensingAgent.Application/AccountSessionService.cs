using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Application;

public interface IAccountSessionRemote
{
    Task<RemoteAccountSessionStart> StartAsync(CancellationToken cancellationToken);

    Task<RemoteAccountSessionPoll> PollAsync(string deviceCode, CancellationToken cancellationToken);

    Task<RemoteAccountSessionPoll> ExchangeNativeHandoffAsync(
        string handoffCode,
        string deviceId,
        CancellationToken cancellationToken);

    Task<RemoteAccountSessionRefresh> RefreshAsync(
        string refreshToken,
        CancellationToken cancellationToken);

    Task AcknowledgeAsync(string accessToken, CancellationToken cancellationToken);

    Task RevokeAsync(string? sessionId, string? refreshToken, string? deviceCode, CancellationToken cancellationToken);
}

public interface IAccountSessionSecretStore
{
    Task<AccountSessionStoredState?> ReadAsync(CancellationToken cancellationToken);

    Task WriteAsync(AccountSessionStoredState state, CancellationToken cancellationToken);

    Task ClearAsync(CancellationToken cancellationToken);
}

public sealed record AccountSessionDeviceContext(
    string DeviceId,
    string DeviceName,
    string Platform,
    string Architecture);

public interface IAccountSessionDeviceContextProvider
{
    AccountSessionDeviceContext Get();
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
    DateTimeOffset RefreshTokenExpiresAt,
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
    TimeSpan? RefreshExpiresIn = null,
    AccountSessionAccount? Account = null);

public sealed record RemoteAccountSessionRefresh(
    string Status,
    string? AccessToken = null,
    string? RefreshToken = null,
    string? SessionId = null,
    TimeSpan? ExpiresIn = null,
    TimeSpan? RefreshExpiresIn = null,
    AccountSessionAccount? Account = null);

public sealed class AccountSessionService : IAccountSessionService
{
    private static readonly TimeSpan SlowDownIncrement = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan MaxPollInterval = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan RefreshWindow = TimeSpan.FromMinutes(2);

    private readonly IAccountSessionRemote _remote;
    private readonly IAccountSessionSecretStore _store;
    private readonly IAccountSessionDeviceContextProvider _deviceContextProvider;
    private readonly TimeProvider _timeProvider;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public AccountSessionService(
        IAccountSessionRemote remote,
        IAccountSessionSecretStore store,
        IAccountSessionDeviceContextProvider deviceContextProvider,
        TimeProvider? timeProvider = null)
    {
        _remote = remote;
        _store = store;
        _deviceContextProvider = deviceContextProvider;
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

    public Task<AccountSessionNativeContextResponse> NativeContextAsync(
        AccountSessionNativeContextRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            var context = _deviceContextProvider.Get();
            if (!ValidDeviceContext(context))
            {
                return Task.FromResult(NativeContextResponse(
                    "FAILED",
                    null,
                    Error(
                        "INVALID_DEVICE_CONTEXT",
                        "BKE Licensing Agent could not resolve a valid native sign-in context.",
                        false)));
            }

            return Task.FromResult(NativeContextResponse("READY", context, null));
        }
        catch
        {
            return Task.FromResult(NativeContextResponse(
                "FAILED",
                null,
                Error(
                    "DEVICE_CONTEXT_UNAVAILABLE",
                    "BKE Licensing Agent could not resolve native sign-in context.",
                    true)));
        }
    }

    public async Task<AccountSessionNativeCompleteResponse> CompleteNativeAsync(
        AccountSessionNativeCompleteRequest request,
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var now = _timeProvider.GetUtcNow();
            var existing = await _store.ReadAsync(cancellationToken);

            if (existing is ActiveAccountSessionState active)
            {
                return NativeCompleteResponse("AUTHENTICATED", active.Account, null);
            }

            if (existing is PendingAccountSessionState pending)
            {
                try
                {
                    await _remote.RevokeAsync(
                        null,
                        null,
                        pending.DeviceCode,
                        cancellationToken);
                }
                catch
                {
                    // Native completion replaces any legacy pending browser/device
                    // authorization locally. Its server TTL still bounds the stale flow.
                }

                await _store.ClearAsync(cancellationToken);
            }

            AccountSessionDeviceContext context;
            try
            {
                context = _deviceContextProvider.Get();
            }
            catch
            {
                return NativeCompleteResponse(
                    "FAILED",
                    null,
                    Error(
                        "DEVICE_CONTEXT_UNAVAILABLE",
                        "BKE Licensing Agent could not resolve native sign-in context.",
                        true));
            }

            if (!ValidDeviceContext(context))
            {
                return NativeCompleteResponse(
                    "FAILED",
                    null,
                    Error(
                        "INVALID_DEVICE_CONTEXT",
                        "BKE Licensing Agent could not resolve a valid native sign-in context.",
                        false));
            }

            RemoteAccountSessionPoll exchange;
            try
            {
                exchange = await _remote.ExchangeNativeHandoffAsync(
                    request.HandoffCode,
                    context.DeviceId,
                    cancellationToken);
            }
            catch
            {
                return NativeCompleteResponse(
                    "FAILED",
                    null,
                    Error(
                        "REMOTE_UNAVAILABLE",
                        "BKE account sign-in handoff is unavailable.",
                        true));
            }

            switch (exchange.Status)
            {
                case "approved":
                {
                    var finalized = await FinalizeApprovedAsync(
                        exchange,
                        now,
                        cancellationToken);
                    return finalized.Status == "AUTHENTICATED"
                        ? NativeCompleteResponse(
                            "AUTHENTICATED",
                            finalized.Account,
                            null)
                        : NativeCompleteResponse(
                            finalized.Status,
                            null,
                            finalized.Error);
                }
                case "expired_token":
                    return NativeCompleteResponse(
                        "EXPIRED",
                        null,
                        Error(
                            "HANDOFF_EXPIRED",
                            "The BKE sign-in handoff expired. Sign in again.",
                            false));
                case "access_denied":
                    return NativeCompleteResponse(
                        "DENIED",
                        null,
                        Error(
                            "HANDOFF_DENIED",
                            "The BKE sign-in handoff was denied.",
                            false));
                default:
                    return NativeCompleteResponse(
                        "FAILED",
                        null,
                        Error(
                            "INVALID_REMOTE_RESPONSE",
                            "BKE account sign-in returned an invalid handoff state.",
                            false));
            }
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
                return await EnsureActiveSessionAsync(active, now, cancellationToken);
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
                return await FinalizeApprovedAsync(
                    poll,
                    now,
                    cancellationToken);
            default:
                await _store.ClearAsync(cancellationToken);
                return StatusResponse(
                    "FAILED",
                    null,
                    Error("INVALID_REMOTE_RESPONSE", "BKE account authorization returned an unknown state.", false));
        }
    }

    private async Task<AccountSessionStatusResponse> FinalizeApprovedAsync(
        RemoteAccountSessionPoll poll,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (!ValidApprovedPoll(poll, now))
        {
            await _store.ClearAsync(cancellationToken);
            return StatusResponse(
                "FAILED",
                null,
                Error(
                    "INVALID_REMOTE_RESPONSE",
                    "BKE account authorization returned an invalid approval.",
                    false));
        }

        var active = new ActiveAccountSessionState(
            poll.AccessToken!,
            poll.RefreshToken!,
            poll.SessionId,
            now.Add(poll.ExpiresIn!.Value),
            now.Add(poll.RefreshExpiresIn!.Value),
            poll.Account!);
        await _store.WriteAsync(active, cancellationToken);
        try
        {
            await _remote.AcknowledgeAsync(active.AccessToken, cancellationToken);
        }
        catch
        {
            // The tokens are already durably protected locally. The server-side
            // handoff bundle has a short TTL and refresh also erases it.
        }

        return StatusResponse("AUTHENTICATED", active.Account, null);
    }

    private async Task<AccountSessionStatusResponse> EnsureActiveSessionAsync(
        ActiveAccountSessionState active,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (active.RefreshTokenExpiresAt <= now)
        {
            await _store.ClearAsync(cancellationToken);
            return StatusResponse(
                "SIGNED_OUT",
                null,
                Error("SESSION_EXPIRED", "The BKE account session expired. Sign in again.", false));
        }

        if (active.AccessTokenExpiresAt - now > RefreshWindow)
        {
            return StatusResponse("AUTHENTICATED", active.Account, null);
        }

        RemoteAccountSessionRefresh refreshed;
        try
        {
            refreshed = await _remote.RefreshAsync(active.RefreshToken, cancellationToken);
        }
        catch
        {
            if (active.AccessTokenExpiresAt > now)
            {
                return StatusResponse(
                    "AUTHENTICATED",
                    active.Account,
                    Error("REMOTE_UNAVAILABLE", "BKE account session refresh is temporarily unavailable.", true));
            }
            return StatusResponse(
                "FAILED",
                null,
                Error("REMOTE_UNAVAILABLE", "BKE account session refresh is unavailable.", true));
        }

        if (refreshed.Status is "invalid_grant" or "replay_detected")
        {
            await _store.ClearAsync(cancellationToken);
            return StatusResponse(
                "SIGNED_OUT",
                null,
                Error(
                    refreshed.Status == "replay_detected" ? "SESSION_REPLAY_DETECTED" : "SESSION_INVALID",
                    "The BKE account session is no longer valid. Sign in again.",
                    false));
        }

        if (!ValidRefresh(refreshed))
        {
            await _store.ClearAsync(cancellationToken);
            return StatusResponse(
                "FAILED",
                null,
                Error("INVALID_REMOTE_RESPONSE", "BKE account session refresh returned an invalid response.", false));
        }

        var next = new ActiveAccountSessionState(
            refreshed.AccessToken!,
            refreshed.RefreshToken!,
            refreshed.SessionId,
            now.Add(refreshed.ExpiresIn!.Value),
            now.Add(refreshed.RefreshExpiresIn!.Value),
            refreshed.Account!);
        await _store.WriteAsync(next, cancellationToken);
        return StatusResponse("AUTHENTICATED", next.Account, null);
    }

    private static bool ValidDeviceContext(AccountSessionDeviceContext context) =>
        !string.IsNullOrWhiteSpace(context.DeviceId) &&
        context.DeviceId.Length is >= 16 and <= 256 &&
        !string.IsNullOrWhiteSpace(context.DeviceName) &&
        context.DeviceName.Length <= 128 &&
        context.Platform is "windows" or "macos" or "linux" &&
        context.Architecture is "x64" or "arm64" or "x86";

    private static bool ValidRefresh(RemoteAccountSessionRefresh refreshed)
    {
        var account = refreshed.Account;
        return refreshed.Status == "refreshed" &&
               !string.IsNullOrWhiteSpace(refreshed.AccessToken) &&
               !string.IsNullOrWhiteSpace(refreshed.RefreshToken) &&
               refreshed.AccessToken!.Length <= 8192 &&
               refreshed.RefreshToken!.Length <= 8192 &&
               refreshed.ExpiresIn is { } expiresIn &&
               expiresIn > TimeSpan.Zero &&
               expiresIn <= TimeSpan.FromHours(24) &&
               refreshed.RefreshExpiresIn is { } refreshExpiresIn &&
               refreshExpiresIn > expiresIn &&
               refreshExpiresIn <= TimeSpan.FromDays(90) &&
               account is not null &&
               !string.IsNullOrWhiteSpace(account.UserId) &&
               !string.IsNullOrWhiteSpace(account.Email) &&
               !string.IsNullOrWhiteSpace(account.AccountId) &&
               !string.IsNullOrWhiteSpace(account.DisplayName) &&
               account.AccountType is "INDIVIDUAL" or "ORGANIZATION";
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
               poll.RefreshExpiresIn is { } refreshExpiresIn &&
               refreshExpiresIn > expiresIn &&
               refreshExpiresIn <= TimeSpan.FromDays(90) &&
               account is not null &&
               !string.IsNullOrWhiteSpace(account.UserId) &&
               !string.IsNullOrWhiteSpace(account.Email) &&
               !string.IsNullOrWhiteSpace(account.AccountId) &&
               !string.IsNullOrWhiteSpace(account.DisplayName) &&
               account.AccountType is "INDIVIDUAL" or "ORGANIZATION";
    }

    private static AccountSessionNativeContextResponse NativeContextResponse(
        string status,
        AccountSessionDeviceContext? context,
        AccountSessionError? error) =>
        new(
            LocalAgentContract.AccountSessionCapabilityId,
            LocalAgentContract.AccountSessionContractVersion,
            status,
            context?.DeviceId,
            context?.DeviceName,
            context?.Platform,
            context?.Architecture,
            error);

    private static AccountSessionNativeCompleteResponse NativeCompleteResponse(
        string status,
        AccountSessionAccount? account,
        AccountSessionError? error) =>
        new(
            LocalAgentContract.AccountSessionCapabilityId,
            LocalAgentContract.AccountSessionContractVersion,
            status,
            account,
            error);

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
