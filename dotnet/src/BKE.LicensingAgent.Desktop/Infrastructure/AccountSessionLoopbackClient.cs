using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Desktop.Infrastructure;

internal sealed class AccountSessionLoopbackClient : IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = false,
    };

    private readonly HttpClient _http = new(new HttpClientHandler
    {
        AllowAutoRedirect = false,
    })
    {
        BaseAddress = new Uri($"http://{LocalAgentContract.BindHost}:{LocalAgentContract.DefaultPort}", UriKind.Absolute),
        Timeout = TimeSpan.FromSeconds(5),
    };

    public Task<AccountSessionStartResponse> StartAsync(CancellationToken cancellationToken) =>
        PostAsync<AccountSessionStartRequest, AccountSessionStartResponse>(
            LocalAgentContract.AccountSessionStartPath,
            new AccountSessionStartRequest(NewCorrelationId()),
            cancellationToken);

    public Task<AccountSessionStatusResponse> StatusAsync(CancellationToken cancellationToken) =>
        PostAsync<AccountSessionStatusRequest, AccountSessionStatusResponse>(
            LocalAgentContract.AccountSessionStatusPath,
            new AccountSessionStatusRequest(NewCorrelationId()),
            cancellationToken);

    public Task<AccountSessionLogoutResponse> LogoutAsync(CancellationToken cancellationToken) =>
        PostAsync<AccountSessionLogoutRequest, AccountSessionLogoutResponse>(
            LocalAgentContract.AccountSessionLogoutPath,
            new AccountSessionLogoutRequest(NewCorrelationId()),
            cancellationToken);

    private async Task<TResponse> PostAsync<TRequest, TResponse>(
        string path,
        TRequest request,
        CancellationToken cancellationToken)
    {
        using var response = await _http.PostAsJsonAsync(
            path,
            request,
            JsonOptions,
            cancellationToken);

        if ((int)response.StatusCode is >= 300 and <= 399)
        {
            throw new HttpRequestException("BKE Licensing Agent loopback endpoint redirected.");
        }

        response.EnsureSuccessStatusCode();

        return await response.Content.ReadFromJsonAsync<TResponse>(
            JsonOptions,
            cancellationToken)
            ?? throw new InvalidDataException("BKE Licensing Agent returned an empty account-session response.");
    }

    private static string NewCorrelationId() => Guid.NewGuid().ToString("N");

    public void Dispose() => _http.Dispose();
}
