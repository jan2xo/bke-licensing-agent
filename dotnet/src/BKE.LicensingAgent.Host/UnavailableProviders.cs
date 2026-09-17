using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Host;

internal sealed class UnavailableProviders :
    IAuthorizationService,
    IActivationService,
    ILicenseCenterService,
    INotificationService,
    IUpdateService
{
    internal const string NotMigratedReason = "gen2_provider_not_migrated";

    private static NotificationCapabilityError NotificationUnavailable() =>
        new("ProviderUnavailable", "The .NET 10 notification provider has not been migrated yet.", true);

    public Task<AuthorizationResponse> AuthorizeAsync(
        AuthorizeRequest request,
        CancellationToken cancellationToken) =>
        Task.FromResult(new AuthorizationResponse(false, NotMigratedReason));

    public Task<AuthorizationResponse> ActivateAsync(
        ActivateRequest request,
        CancellationToken cancellationToken) =>
        Task.FromResult(new AuthorizationResponse(false, NotMigratedReason));

    public Task<OpenLicenseCenterResponse> OpenAsync(
        OpenLicenseCenterRequest request,
        CancellationToken cancellationToken) =>
        Task.FromResult(new OpenLicenseCenterResponse(
            "agent_unavailable",
            NotMigratedReason,
            false,
            request.CorrelationId));

    public Task<TypedNotificationResponse> RequestAsync(
        TypedNotificationRequest request,
        CancellationToken cancellationToken) =>
        Task.FromResult(new TypedNotificationResponse(
            LocalAgentContract.TypedNotificationCapabilityId,
            LocalAgentContract.TypedNotificationContractVersion,
            "rejected",
            null,
            request.Code,
            NotMigratedReason));

    public Task<NotificationFeedResponse> FeedAsync(
        NotificationFeedRequest request,
        CancellationToken cancellationToken) =>
        Task.FromResult(new NotificationFeedResponse(
            LocalAgentContract.NotificationInboxCapabilityId,
            LocalAgentContract.NotificationInboxContractVersion,
            "Failed",
            Array.Empty<NotificationItem>(),
            NotificationUnavailable()));

    public Task<NotificationMutationResponse> MarkReadAsync(
        NotificationMutationRequest request,
        CancellationToken cancellationToken) =>
        Task.FromResult(new NotificationMutationResponse(
            LocalAgentContract.NotificationInboxCapabilityId,
            LocalAgentContract.NotificationInboxContractVersion,
            "Failed",
            NotificationUnavailable()));

    public Task<NotificationMutationResponse> DismissAsync(
        NotificationMutationRequest request,
        CancellationToken cancellationToken) =>
        Task.FromResult(new NotificationMutationResponse(
            LocalAgentContract.NotificationInboxCapabilityId,
            LocalAgentContract.NotificationInboxContractVersion,
            "Failed",
            NotificationUnavailable()));

    public Task<NotificationUnreadCountResponse> UnreadCountAsync(
        NotificationContextRequest request,
        CancellationToken cancellationToken) =>
        Task.FromResult(new NotificationUnreadCountResponse(
            LocalAgentContract.NotificationInboxCapabilityId,
            LocalAgentContract.NotificationInboxContractVersion,
            "Failed",
            0,
            NotificationUnavailable()));

    public Task<UpdateCheckResponse> CheckAsync(
        UpdateCheckRequest request,
        CancellationToken cancellationToken) =>
        Task.FromResult(new UpdateCheckResponse(
            LocalAgentContract.UpdateCapabilityId,
            LocalAgentContract.UpdateContractVersion,
            "Failed",
            null,
            new UpdateCapabilityError(
                "ProviderUnavailable",
                "The .NET 10 update provider has not been migrated yet.",
                true)));

    public Task<OpenUpdateCenterResponse> OpenCenterAsync(
        OpenUpdateCenterRequest request,
        CancellationToken cancellationToken) =>
        Task.FromResult(new OpenUpdateCenterResponse(
            "agent_unavailable",
            NotMigratedReason,
            request.CorrelationId));
}
