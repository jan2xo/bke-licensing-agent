using System.Text.Json;
using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Application;

public interface IAccountRegistrationRemote
{
    Task<RemoteAccountRegistrationPreflightResult> PreflightAsync(
        string correlationId,
        CancellationToken cancellationToken);

    Task<RemoteAccountRegistrationMutationResult> RegisterAsync(
        string correlationId,
        string email,
        string name,
        string password,
        IReadOnlyList<string> legalVersionIds,
        CancellationToken cancellationToken);

    Task<RemoteAccountRegistrationMutationResult> VerifyEmailAsync(
        string correlationId,
        string email,
        string code,
        CancellationToken cancellationToken);

    Task<RemoteAccountRegistrationMutationResult> ResendAsync(
        string correlationId,
        string email,
        CancellationToken cancellationToken);
}

public interface IAccountRegistrationService
{
    Task<AccountRegistrationPreflightResponse> PreflightAsync(
        AccountRegistrationPreflightRequest request,
        CancellationToken cancellationToken);

    Task<AccountRegistrationResponse> RegisterAsync(
        AccountRegistrationRequest request,
        CancellationToken cancellationToken);

    Task<AccountRegistrationResponse> VerifyEmailAsync(
        AccountRegistrationVerifyEmailRequest request,
        CancellationToken cancellationToken);

    Task<AccountRegistrationResponse> ResendAsync(
        AccountRegistrationResendRequest request,
        CancellationToken cancellationToken);
}

public sealed record RemoteAccountRegistrationPreflightResult(
    string Status,
    IReadOnlyList<AccountRegistrationLegalDocument>? LegalDocuments = null,
    string? ErrorCode = null,
    bool Retryable = false);

public sealed record RemoteAccountRegistrationMutationResult(
    string Status,
    string? ErrorCode = null,
    bool Retryable = false);

public sealed class AccountRegistrationService : IAccountRegistrationService
{
    private readonly IAccountRegistrationRemote _remote;

    public AccountRegistrationService(IAccountRegistrationRemote remote)
    {
        _remote = remote;
    }

    public async Task<AccountRegistrationPreflightResponse> PreflightAsync(
        AccountRegistrationPreflightRequest request,
        CancellationToken cancellationToken)
    {
        try
        {
            var result = await _remote.PreflightAsync(
                request.CorrelationId,
                cancellationToken);

            return result.Status switch
            {
                "ready" when result.LegalDocuments is { Count: 2 } =>
                    new AccountRegistrationPreflightResponse(
                        LocalAgentContract.AccountRegistrationCapabilityId,
                        LocalAgentContract.AccountRegistrationContractVersion,
                        "READY",
                        request.CorrelationId,
                        result.LegalDocuments,
                        null),
                "registration_unavailable" =>
                    PreflightFailure(
                        "UNAVAILABLE",
                        request.CorrelationId,
                        result.ErrorCode ?? "REGISTRATION_UNAVAILABLE",
                        "Native BKE account registration is temporarily unavailable.",
                        result.Retryable),
                _ =>
                    PreflightFailure(
                        "FAILED",
                        request.CorrelationId,
                        result.ErrorCode ?? "INVALID_REMOTE_RESPONSE",
                        "Native registration authority returned an invalid state.",
                        false),
            };
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception error) when (
            error is HttpRequestException or TaskCanceledException)
        {
            return PreflightFailure(
                "UNAVAILABLE",
                request.CorrelationId,
                "REGISTRATION_PREFLIGHT_UNAVAILABLE",
                "Registration requirements could not be loaded.",
                true);
        }
        catch (Exception error) when (
            error is InvalidDataException or JsonException)
        {
            return PreflightFailure(
                "FAILED",
                request.CorrelationId,
                "INVALID_REMOTE_RESPONSE",
                "Registration authority returned an invalid response.",
                false);
        }
    }

    public Task<AccountRegistrationResponse> RegisterAsync(
        AccountRegistrationRequest request,
        CancellationToken cancellationToken) =>
        MutationAsync(
            request.CorrelationId,
            () => _remote.RegisterAsync(
                request.CorrelationId,
                request.Email,
                request.Name,
                request.Password,
                request.LegalVersionIds,
                cancellationToken),
            "REGISTRATION_RESULT_UNKNOWN",
            cancellationToken);

    public Task<AccountRegistrationResponse> VerifyEmailAsync(
        AccountRegistrationVerifyEmailRequest request,
        CancellationToken cancellationToken) =>
        MutationAsync(
            request.CorrelationId,
            () => _remote.VerifyEmailAsync(
                request.CorrelationId,
                request.Email,
                request.Code,
                cancellationToken),
            "EMAIL_VERIFICATION_RESULT_UNKNOWN",
            cancellationToken);

    public Task<AccountRegistrationResponse> ResendAsync(
        AccountRegistrationResendRequest request,
        CancellationToken cancellationToken) =>
        MutationAsync(
            request.CorrelationId,
            () => _remote.ResendAsync(
                request.CorrelationId,
                request.Email,
                cancellationToken),
            "VERIFICATION_RESEND_RESULT_UNKNOWN",
            cancellationToken);

    private static async Task<AccountRegistrationResponse> MutationAsync(
        string correlationId,
        Func<Task<RemoteAccountRegistrationMutationResult>> action,
        string ambiguityCode,
        CancellationToken cancellationToken)
    {
        try
        {
            var result = await action();
            return result.Status switch
            {
                "verification_required" =>
                    Response("VERIFICATION_REQUIRED", correlationId),
                "verified" =>
                    Response("VERIFIED", correlationId),
                "accepted" =>
                    Response("ACCEPTED", correlationId),
                "account_exists" =>
                    Failure(
                        "ACCOUNT_EXISTS",
                        correlationId,
                        result.ErrorCode ?? "ACCOUNT_EXISTS",
                        "A BKE account already exists for this email address.",
                        false),
                "invalid_input" =>
                    Failure(
                        "INVALID_INPUT",
                        correlationId,
                        result.ErrorCode ?? "INVALID_INPUT",
                        "The registration request was rejected.",
                        false),
                "invalid_verification_code" =>
                    Failure(
                        "INVALID_VERIFICATION_CODE",
                        correlationId,
                        result.ErrorCode ?? "INVALID_VERIFICATION_CODE",
                        "The email verification code is invalid or expired.",
                        false),
                "legal_acceptance_required" =>
                    Failure(
                        "LEGAL_REACCEPTANCE_REQUIRED",
                        correlationId,
                        result.ErrorCode ?? "LEGAL_ACCEPTANCE_REQUIRED",
                        "Registration Legal documents changed. Refresh them before registering.",
                        false),
                "rate_limited" =>
                    Failure(
                        "RATE_LIMITED",
                        correlationId,
                        result.ErrorCode ?? "RATE_LIMITED",
                        "Native account registration is temporarily rate limited.",
                        true),
                "registration_unavailable" =>
                    Failure(
                        "UNAVAILABLE",
                        correlationId,
                        result.ErrorCode ?? "REGISTRATION_UNAVAILABLE",
                        "Native BKE account registration is temporarily unavailable.",
                        result.Retryable),
                _ =>
                    Failure(
                        "FAILED",
                        correlationId,
                        result.ErrorCode ?? "INVALID_REMOTE_RESPONSE",
                        "Native registration authority returned an invalid state.",
                        false),
            };
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception error) when (
            error is HttpRequestException or TaskCanceledException)
        {
            return Failure(
                "RESULT_UNKNOWN",
                correlationId,
                ambiguityCode,
                "The request may have reached BKE Digital Solutions, but the result could not be confirmed. Do not automatically replay it.",
                false);
        }
        catch (Exception error) when (
            error is InvalidDataException or JsonException)
        {
            return Failure(
                "FAILED",
                correlationId,
                "INVALID_REMOTE_RESPONSE",
                "Registration authority returned an invalid response.",
                false);
        }
    }

    private static AccountRegistrationPreflightResponse PreflightFailure(
        string status,
        string correlationId,
        string code,
        string message,
        bool retryable) =>
        new(
            LocalAgentContract.AccountRegistrationCapabilityId,
            LocalAgentContract.AccountRegistrationContractVersion,
            status,
            correlationId,
            Array.Empty<AccountRegistrationLegalDocument>(),
            new AccountRegistrationError(code, message, retryable));

    private static AccountRegistrationResponse Response(
        string status,
        string correlationId) =>
        new(
            LocalAgentContract.AccountRegistrationCapabilityId,
            LocalAgentContract.AccountRegistrationContractVersion,
            status,
            correlationId,
            null);

    private static AccountRegistrationResponse Failure(
        string status,
        string correlationId,
        string code,
        string message,
        bool retryable) =>
        new(
            LocalAgentContract.AccountRegistrationCapabilityId,
            LocalAgentContract.AccountRegistrationContractVersion,
            status,
            correlationId,
            new AccountRegistrationError(code, message, retryable));
}
