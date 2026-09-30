using System.Text.Json;
using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Application;

public interface IAccountLicenseSeatsRemote
{
    Task<RemoteAccountLicenseSeatsResult> GetAsync(
        string accessToken,
        string licenseManagementHandle,
        CancellationToken cancellationToken);

    Task<RemoteAccountLicenseSeatsManageResult> ManageAsync(
        string accessToken,
        string action,
        string licenseManagementHandle,
        string targetManagementHandle,
        CancellationToken cancellationToken);
}

public interface IAccountLicenseSeatsService
{
    Task<AccountLicenseSeatsResponse> GetAsync(
        AccountLicenseSeatsRequest request,
        CancellationToken cancellationToken);

    Task<AccountLicenseSeatsManageResponse> ManageAsync(
        AccountLicenseSeatsManageRequest request,
        CancellationToken cancellationToken);
}

public sealed record RemoteAccountLicenseSeatsResult(
    string Status,
    AccountLicenseSeatInfo? License = null,
    IReadOnlyList<AccountLicenseSeatTarget>? Targets = null,
    string? ErrorCode = null,
    bool Retryable = false);

public sealed record RemoteAccountLicenseSeatsManageResult(
    string Status,
    string? ErrorCode = null,
    bool Retryable = false);

public sealed class AccountLicenseSeatsService :
    IAccountLicenseSeatsService
{
    private readonly IAccountSessionService _accountSession;
    private readonly IAccountSessionSecretStore _secretStore;
    private readonly IAccountLicenseSeatsRemote _remote;

    public AccountLicenseSeatsService(
        IAccountSessionService accountSession,
        IAccountSessionSecretStore secretStore,
        IAccountLicenseSeatsRemote remote)
    {
        _accountSession = accountSession;
        _secretStore = secretStore;
        _remote = remote;
    }

    public async Task<AccountLicenseSeatsResponse> GetAsync(
        AccountLicenseSeatsRequest request,
        CancellationToken cancellationToken)
    {
        var active = await ActiveAsync(
            request.CorrelationId,
            cancellationToken);
        if (active is null)
        {
            return ReadResponse(
                "AUTH_REQUIRED",
                error: Error(
                    "AUTH_REQUIRED",
                    "Sign in with BKE before managing license seats.",
                    false));
        }

        try
        {
            var result = await _remote.GetAsync(
                active.AccessToken,
                request.LicenseManagementHandle,
                cancellationToken);

            if (result.Status == "ready" &&
                result.License is not null &&
                result.Targets is not null)
            {
                return ReadResponse(
                    "READY",
                    result.License,
                    result.Targets);
            }

            var status = result.Status switch
            {
                "account_forbidden" => "FORBIDDEN",
                "license_not_found" => "NOT_FOUND",
                "account_not_active" => "ACCOUNT_NOT_ACTIVE",
                "license_not_active" => "LICENSE_NOT_ACTIVE",
                _ => "FAILED",
            };

            return ReadResponse(
                status,
                error: Error(
                    result.ErrorCode ?? "LICENSE_SEATS_UNAVAILABLE",
                    ReadFailureMessage(result.Status),
                    result.Retryable));
        }
        catch (UnauthorizedAccessException)
        {
            await _secretStore.ClearAsync(CancellationToken.None);
            return ReadResponse(
                "AUTH_REQUIRED",
                error: Error(
                    "SESSION_INVALID",
                    "The BKE account session is no longer valid. Sign in again.",
                    false));
        }
        catch (Exception error) when (
            error is HttpRequestException or
            InvalidDataException or
            JsonException or
            TaskCanceledException)
        {
            return ReadResponse(
                "FAILED",
                error: Error(
                    "LICENSE_SEATS_UNAVAILABLE",
                    "BKE license seat state is temporarily unavailable.",
                    true));
        }
    }

    public async Task<AccountLicenseSeatsManageResponse> ManageAsync(
        AccountLicenseSeatsManageRequest request,
        CancellationToken cancellationToken)
    {
        var active = await ActiveAsync(
            request.CorrelationId,
            cancellationToken);
        if (active is null)
        {
            return ManageResponse(
                "AUTH_REQUIRED",
                Error(
                    "AUTH_REQUIRED",
                    "Sign in with BKE before changing license seats.",
                    false));
        }

        try
        {
            var result = await _remote.ManageAsync(
                active.AccessToken,
                request.Action,
                request.LicenseManagementHandle,
                request.TargetManagementHandle,
                cancellationToken);

            if (result.Status is
                "assigned" or
                "existing" or
                "removed" or
                "not_assigned")
            {
                return ManageResponse(
                    result.Status.ToUpperInvariant());
            }

            var status = result.Status switch
            {
                "account_forbidden" => "FORBIDDEN",
                "license_not_found" or "target_not_found" =>
                    "NOT_FOUND",
                "account_not_active" => "ACCOUNT_NOT_ACTIVE",
                "license_not_active" => "LICENSE_NOT_ACTIVE",
                "target_not_account_member" or "license_seat_limit" =>
                    "CONFLICT",
                "invalid_input" => "INVALID_INPUT",
                _ => "FAILED",
            };

            return ManageResponse(
                status,
                Error(
                    result.ErrorCode ?? "LICENSE_SEAT_MANAGE_UNAVAILABLE",
                    ManageFailureMessage(result.Status),
                    result.Retryable));
        }
        catch (UnauthorizedAccessException)
        {
            await _secretStore.ClearAsync(CancellationToken.None);
            return ManageResponse(
                "AUTH_REQUIRED",
                Error(
                    "SESSION_INVALID",
                    "The BKE account session is no longer valid. Sign in again.",
                    false));
        }
        catch (Exception error) when (
            error is HttpRequestException or
            InvalidDataException or
            JsonException or
            TaskCanceledException)
        {
            return ManageResponse(
                "OUTCOME_UNKNOWN",
                Error(
                    "LICENSE_SEAT_MANAGE_OUTCOME_UNKNOWN",
                    "The license seat change could not be confirmed. Refresh the authoritative seat state before trying another change.",
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

    private static string ReadFailureMessage(string status) =>
        status switch
        {
            "account_forbidden" =>
                "The selected BKE account role cannot manage license seats.",
            "license_not_found" =>
                "This managed license is no longer available.",
            "account_not_active" =>
                "License seats cannot be managed while the selected BKE account is inactive.",
            "license_not_active" =>
                "License seats cannot be managed for an inactive license.",
            "rate_limited" =>
                "BKE license seat reads are temporarily rate limited.",
            _ =>
                "BKE license seat state is temporarily unavailable.",
        };

    private static string ManageFailureMessage(string status) =>
        status switch
        {
            "account_forbidden" =>
                "The selected BKE account role cannot change license seats.",
            "license_not_found" =>
                "This managed license is no longer available.",
            "target_not_found" =>
                "The selected seat target is no longer available.",
            "account_not_active" =>
                "License seats cannot be changed while the selected BKE account is inactive.",
            "license_not_active" =>
                "License seats cannot be changed for an inactive license.",
            "target_not_account_member" =>
                "The selected person is no longer eligible for a new seat.",
            "license_seat_limit" =>
                "All purchased seats are already assigned.",
            "rate_limited" =>
                "License seat changes are temporarily rate limited.",
            _ =>
                "BKE could not apply the license seat change.",
        };

    private static AccountLicenseSeatsResponse ReadResponse(
        string status,
        AccountLicenseSeatInfo? license = null,
        IReadOnlyList<AccountLicenseSeatTarget>? targets = null,
        AccountLicenseSeatsError? error = null) =>
        new(
            LocalAgentContract.AccountLicenseSeatsCapabilityId,
            LocalAgentContract.AccountLicenseSeatsContractVersion,
            status,
            license,
            targets ?? Array.Empty<AccountLicenseSeatTarget>(),
            error);

    private static AccountLicenseSeatsManageResponse ManageResponse(
        string status,
        AccountLicenseSeatsError? error = null) =>
        new(
            LocalAgentContract.AccountLicenseSeatsCapabilityId,
            LocalAgentContract.AccountLicenseSeatsContractVersion,
            status,
            error);

    private static AccountLicenseSeatsError Error(
        string code,
        string message,
        bool retryable) =>
        new(code, message, retryable);
}
