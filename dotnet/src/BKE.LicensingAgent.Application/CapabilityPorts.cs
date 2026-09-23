using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Application;

// Capability-oriented ports keep the Host as a composition root rather than a God service.
public interface IAuthorizationService
{
    Task<AuthorizationResponse> AuthorizeAsync(AuthorizeRequest request, CancellationToken cancellationToken);
}

public interface IActivationService
{
    Task<AuthorizationResponse> ActivateAsync(ActivateRequest request, CancellationToken cancellationToken);
}

public interface ILicenseCenterService
{
    Task<OpenLicenseCenterResponse> OpenAsync(OpenLicenseCenterRequest request, CancellationToken cancellationToken);
}

public interface INotificationService
{
    Task<TypedNotificationResponse> RequestAsync(TypedNotificationRequest request, CancellationToken cancellationToken);

    Task<NotificationFeedResponse> FeedAsync(NotificationFeedRequest request, CancellationToken cancellationToken);

    Task<NotificationMutationResponse> MarkReadAsync(NotificationMutationRequest request, CancellationToken cancellationToken);

    Task<NotificationMutationResponse> DismissAsync(NotificationMutationRequest request, CancellationToken cancellationToken);

    Task<NotificationUnreadCountResponse> UnreadCountAsync(NotificationContextRequest request, CancellationToken cancellationToken);
}

public interface IUpdateService
{
    Task<UpdateCheckResponse> CheckAsync(UpdateCheckRequest request, CancellationToken cancellationToken);

    Task<OpenUpdateCenterResponse> OpenCenterAsync(OpenUpdateCenterRequest request, CancellationToken cancellationToken);
}


public interface IAccountSessionService
{
    Task<AccountSessionCompleteResponse> CompleteAsync(
        AccountSessionCompleteRequest request,
        CancellationToken cancellationToken);

    Task<AccountSessionStartResponse> StartAsync(
        AccountSessionStartRequest request,
        CancellationToken cancellationToken);

    Task<AccountSessionStatusResponse> StatusAsync(
        AccountSessionStatusRequest request,
        CancellationToken cancellationToken);

    Task<AccountSessionLogoutResponse> LogoutAsync(
        AccountSessionLogoutRequest request,
        CancellationToken cancellationToken);
}

public interface ISoftwareCatalogService
{
    Task<SoftwareCatalogResponse> GetAsync(
        SoftwareCatalogRequest request,
        CancellationToken cancellationToken);
}
