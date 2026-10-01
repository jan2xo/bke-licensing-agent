using System.Text.Json;
using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Application;

public interface IAccountLicenseDevicesRemote
{
    Task<RemoteAccountLicenseDevicesResult> GetAsync(
        string accessToken,
        string licenseManagementHandle,
        CancellationToken cancellationToken);

    Task<RemoteAccountLicenseDeviceDeactivateResult> DeactivateAsync(
        string accessToken,
        string licenseManagementHandle,
        string deviceManagementHandle,
        CancellationToken cancellationToken);
}

public interface IAccountLicenseDevicesService
{
    Task<AccountLicenseDevicesResponse> GetAsync(
        AccountLicenseDevicesRequest request,
        CancellationToken cancellationToken);

    Task<AccountLicenseDeviceDeactivateResponse> DeactivateAsync(
        AccountLicenseDeviceDeactivateRequest request,
        CancellationToken cancellationToken);
}

public sealed record RemoteAccountLicenseDevicesResult(
    string Status,
    AccountLicenseDeviceInfo? License = null,
    IReadOnlyList<AccountAuthorizedDevice>? Devices = null,
    string? ErrorCode = null,
    bool Retryable = false);

public sealed record RemoteAccountLicenseDeviceDeactivateResult(
    string Status,
    string? ErrorCode = null,
    bool Retryable = false);

public sealed class AccountLicenseDevicesService :
    IAccountLicenseDevicesService
{
    private readonly IAccountSessionService _accountSession;
    private readonly IAccountSessionSecretStore _secretStore;
    private readonly IAccountLicenseDevicesRemote _remote;

    public AccountLicenseDevicesService(
        IAccountSessionService accountSession,
        IAccountSessionSecretStore secretStore,
        IAccountLicenseDevicesRemote remote)
    {
        _accountSession = accountSession;
        _secretStore = secretStore;
        _remote = remote;
    }

    public async Task<AccountLicenseDevicesResponse> GetAsync(
        AccountLicenseDevicesRequest request,
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
                    "Sign in with BKE before managing authorized devices.",
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
                result.Devices is not null)
            {
                return ReadResponse(
                    "READY",
                    result.License,
                    result.Devices);
            }

            var status = result.Status switch
            {
                "account_forbidden" => "FORBIDDEN",
                "license_not_found" => "NOT_FOUND",
                "account_not_active" => "ACCOUNT_NOT_ACTIVE",
                "invalid_input" => "INVALID_INPUT",
                _ => "FAILED",
            };

            return ReadResponse(
                status,
                error: Error(
                    result.ErrorCode ?? "LICENSE_DEVICES_UNAVAILABLE",
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
                    "LICENSE_DEVICES_UNAVAILABLE",
                    "BKE authorized-device state is temporarily unavailable.",
                    true));
        }
    }

    public async Task<AccountLicenseDeviceDeactivateResponse>
        DeactivateAsync(
            AccountLicenseDeviceDeactivateRequest request,
            CancellationToken cancellationToken)
    {
        var active = await ActiveAsync(
            request.CorrelationId,
            cancellationToken);
        if (active is null)
        {
            return DeactivateResponse(
                "AUTH_REQUIRED",
                Error(
                    "AUTH_REQUIRED",
                    "Sign in with BKE before deactivating an authorized device.",
                    false));
        }

        try
        {
            var result = await _remote.DeactivateAsync(
                active.AccessToken,
                request.LicenseManagementHandle,
                request.DeviceManagementHandle,
                cancellationToken);

            if (result.Status == "deactivated")
            {
                return DeactivateResponse("DEACTIVATED");
            }

            var status = result.Status switch
            {
                "account_forbidden" => "FORBIDDEN",
                "license_not_found" or "device_not_found" =>
                    "NOT_FOUND",
                "account_not_active" => "ACCOUNT_NOT_ACTIVE",
                "invalid_input" => "INVALID_INPUT",
                _ => "FAILED",
            };

            return DeactivateResponse(
                status,
                Error(
                    result.ErrorCode ??
                        "LICENSE_DEVICE_DEACTIVATE_UNAVAILABLE",
                    DeactivateFailureMessage(result.Status),
                    result.Retryable));
        }
        catch (UnauthorizedAccessException)
        {
            await _secretStore.ClearAsync(CancellationToken.None);
            return DeactivateResponse(
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
            return DeactivateResponse(
                "OUTCOME_UNKNOWN",
                Error(
                    "LICENSE_DEVICE_DEACTIVATE_OUTCOME_UNKNOWN",
                    "The authorized-device deactivation could not be confirmed. Refresh the authoritative device state before trying another change.",
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
                "The selected BKE account role cannot manage authorized devices.",
            "license_not_found" =>
                "This managed license is no longer available.",
            "account_not_active" =>
                "Authorized devices cannot be managed while the selected BKE account is inactive.",
            "rate_limited" =>
                "BKE authorized-device reads are temporarily rate limited.",
            _ =>
                "BKE authorized-device state is temporarily unavailable.",
        };

    private static string DeactivateFailureMessage(string status) =>
        status switch
        {
            "account_forbidden" =>
                "The selected BKE account role cannot deactivate authorized devices.",
            "license_not_found" =>
                "This managed license is no longer available.",
            "device_not_found" =>
                "The selected authorized device is no longer active or available.",
            "account_not_active" =>
                "Authorized devices cannot be changed while the selected BKE account is inactive.",
            "rate_limited" =>
                "Authorized-device changes are temporarily rate limited.",
            _ =>
                "BKE could not deactivate the authorized device.",
        };

    private static AccountLicenseDevicesResponse ReadResponse(
        string status,
        AccountLicenseDeviceInfo? license = null,
        IReadOnlyList<AccountAuthorizedDevice>? devices = null,
        AccountLicenseDevicesError? error = null) =>
        new(
            LocalAgentContract.AccountLicenseDevicesCapabilityId,
            LocalAgentContract.AccountLicenseDevicesContractVersion,
            status,
            license,
            devices ?? Array.Empty<AccountAuthorizedDevice>(),
            error);

    private static AccountLicenseDeviceDeactivateResponse
        DeactivateResponse(
            string status,
            AccountLicenseDevicesError? error = null) =>
        new(
            LocalAgentContract.AccountLicenseDevicesCapabilityId,
            LocalAgentContract.AccountLicenseDevicesContractVersion,
            status,
            error);

    private static AccountLicenseDevicesError Error(
        string code,
        string message,
        bool retryable) =>
        new(code, message, retryable);
}
