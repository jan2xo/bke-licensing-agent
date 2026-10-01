using System.Net;
using System.Text;
using System.Text.Json;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;
using BKE.LicensingAgent.Infrastructure;

static class AccountRegistrationCertification
{
    private const string ExpectedDigitalSolutionsSource =
        "b84965a513f6cdcd9574c8da8fef86785f5f207d";

    public static async Task RunAsync()
    {
        CertifyStaticBoundaries();
        await CertifyServiceBoundaryAsync();
        await CertifyTransportBoundaryAsync();
    }

    private static void CertifyStaticBoundaries()
    {
        Require(
            File.ReadAllText(
                Path.Combine(
                    "eng",
                    "digital-solutions-source.sha")).Trim() ==
                ExpectedDigitalSolutionsSource,
            "Agent native registration is not pinned to the merged Digital Solutions authority.");

        Require(
            LocalAgentContract.AccountRegistrationCapabilityId ==
                "bke.account-registration" &&
            LocalAgentContract.AccountRegistrationContractVersion == 1 &&
            LocalAgentContract.AccountRegistrationPreflightPath ==
                "/v1/account/registration/preflight" &&
            LocalAgentContract.AccountRegistrationRegisterPath ==
                "/v1/account/registration/register" &&
            LocalAgentContract.AccountRegistrationVerifyEmailPath ==
                "/v1/account/registration/verify-email" &&
            LocalAgentContract.AccountRegistrationResendPath ==
                "/v1/account/registration/resend",
            "Native registration local contract drifted.");

        Require(
            typeof(AccountRegistrationRequest)
                .GetProperties()
                .Select(property => property.Name)
                .SequenceEqual([
                    "CorrelationId",
                    "Email",
                    "Name",
                    "Password",
                    "LegalVersionIds",
                ]) &&
            typeof(AccountRegistrationVerifyEmailRequest)
                .GetProperties()
                .Select(property => property.Name)
                .SequenceEqual([
                    "CorrelationId",
                    "Email",
                    "Code",
                ]) &&
            typeof(AccountRegistrationResendRequest)
                .GetProperties()
                .Select(property => property.Name)
                .SequenceEqual([
                    "CorrelationId",
                    "Email",
                ]),
            "Native registration request boundary widened.");

        foreach (var type in new[]
        {
            typeof(AccountRegistrationPreflightResponse),
            typeof(AccountRegistrationResponse),
            typeof(AccountRegistrationLegalDocument),
        })
        {
            Require(
                type.GetProperties().All(property =>
                    !property.Name.Contains(
                        "AccountId",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Contains(
                        "UserId",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Contains(
                        "Session",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Contains(
                        "Token",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Equals(
                        "Password",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Equals(
                        "Code",
                        StringComparison.OrdinalIgnoreCase)),
                $"{type.Name} exposes identity/session secret material.");
        }

        var hostSource = File.ReadAllText(
            Path.Combine(
                "dotnet",
                "src",
                "BKE.LicensingAgent.Host",
                "Program.cs"));
        var serviceSource = File.ReadAllText(
            Path.Combine(
                "dotnet",
                "src",
                "BKE.LicensingAgent.Application",
                "AccountRegistrationService.cs"));
        var remoteSource = File.ReadAllText(
            Path.Combine(
                "dotnet",
                "src",
                "BKE.LicensingAgent.Infrastructure",
                "AccountRegistrationRemote.cs"));

        foreach (var route in new[]
        {
            "AccountRegistrationPreflightPath",
            "AccountRegistrationRegisterPath",
            "AccountRegistrationVerifyEmailPath",
            "AccountRegistrationResendPath",
        })
        {
            Require(
                hostSource.Contains(
                    $"app.MapPost(LocalAgentContract.{route}",
                    StringComparison.Ordinal),
                $"Agent Host route {route} is not mediated.");
        }

        Require(
            hostSource.Contains(
                "AddSingleton<IAccountRegistrationService>",
                StringComparison.Ordinal) &&
            hostSource.Contains(
                "AddSingleton<IAccountRegistrationRemote>",
                StringComparison.Ordinal),
            "Native registration Host DI wiring drifted.");

        Require(
            remoteSource.Contains(
                "/api/agent-sessions/native/registration",
                StringComparison.Ordinal) &&
            remoteSource.Contains(
                "/api/agent-sessions/native/register",
                StringComparison.Ordinal) &&
            remoteSource.Contains(
                "/api/agent-sessions/native/verify-email",
                StringComparison.Ordinal) &&
            remoteSource.Contains(
                "/api/agent-sessions/native/verification/resend",
                StringComparison.Ordinal) &&
            remoteSource.Contains(
                "AllowAutoRedirect = false",
                StringComparison.Ordinal) &&
            remoteSource.Contains(
                "for (var attempt = 0; attempt <= 2; attempt++)",
                StringComparison.Ordinal) &&
            remoteSource.Split(
                "_http.SendAsync(",
                StringSplitOptions.None).Length == 3,
            "Native registration transport retry/no-redirect ownership drifted.");

        var mutationSegment = remoteSource[
            remoteSource.IndexOf(
                "private async Task<HttpResponseMessage> SendMutationAsync",
                StringComparison.Ordinal)..];
        mutationSegment = mutationSegment[
            ..mutationSegment.IndexOf(
                "private HttpRequestMessage CreateRequest",
                StringComparison.Ordinal)];
        Require(
            !mutationSegment.Contains(
                "for (",
                StringComparison.Ordinal) &&
            mutationSegment.Split(
                "_http.SendAsync(",
                StringSplitOptions.None).Length == 2,
            "Native registration mutations gained automatic replay.");

        Require(
            !serviceSource.Contains(
                "AgentDatabase",
                StringComparison.Ordinal) &&
            !serviceSource.Contains(
                "File.",
                StringComparison.Ordinal) &&
            !serviceSource.Contains(
                "Console.",
                StringComparison.Ordinal) &&
            serviceSource.Contains(
                "\"RESULT_UNKNOWN\"",
                StringComparison.Ordinal),
            "Native registration service introduced persistence/logging or lost ambiguity handling.");
    }

    private static async Task CertifyServiceBoundaryAsync()
    {
        var legal = new[]
        {
            new AccountRegistrationLegalDocument(
                "TERMS_OF_SERVICE",
                "Terms of Service",
                "terms",
                "legal-version-terms",
                3,
                "2026-10-01T00:00:00.000Z",
                "# Terms\nCertification."),
            new AccountRegistrationLegalDocument(
                "PRIVACY_POLICY",
                "Privacy Policy",
                "privacy",
                "legal-version-privacy",
                4,
                null,
                "# Privacy\nCertification."),
        };

        var fake = new FakeAccountRegistrationRemote(
            new RemoteAccountRegistrationPreflightResult(
                "ready",
                legal),
            new RemoteAccountRegistrationMutationResult(
                "verification_required"),
            new RemoteAccountRegistrationMutationResult(
                "verified"),
            new RemoteAccountRegistrationMutationResult(
                "accepted"));
        var service = new AccountRegistrationService(fake);

        var preflight = await service.PreflightAsync(
            new AccountRegistrationPreflightRequest(
                "register-preflight-cert"),
            CancellationToken.None);
        Require(
            preflight.Status == "READY" &&
            preflight.LegalDocuments.Count == 2 &&
            preflight.LegalDocuments[0].VersionId ==
                "legal-version-terms" &&
            fake.PreflightCalls == 1,
            "Native registration preflight mediation drifted.");

        var register = await service.RegisterAsync(
            new AccountRegistrationRequest(
                "register-cert",
                "new@example.test",
                "New User",
                "NativeRegistrationPassword123",
                [
                    "legal-version-terms",
                    "legal-version-privacy",
                ]),
            CancellationToken.None);
        Require(
            register.Status == "VERIFICATION_REQUIRED" &&
            fake.RegisterCalls == 1 &&
            fake.LastPassword ==
                "NativeRegistrationPassword123",
            "Native registration mutation mediation drifted.");

        var registerWire = JsonSerializer.Serialize(register);
        foreach (var forbidden in new[]
        {
            "NativeRegistrationPassword123",
            "registration-access-token",
            "registration-session",
        })
        {
            Require(
                !registerWire.Contains(
                    forbidden,
                    StringComparison.Ordinal),
                "Native registration response leaked credential/session material.");
        }

        var verify = await service.VerifyEmailAsync(
            new AccountRegistrationVerifyEmailRequest(
                "verify-cert",
                "new@example.test",
                "ABCDEFGH"),
            CancellationToken.None);
        Require(
            verify.Status == "VERIFIED" &&
            fake.VerifyCalls == 1 &&
            fake.LastCode == "ABCDEFGH",
            "Native email verification mediation drifted.");

        var resend = await service.ResendAsync(
            new AccountRegistrationResendRequest(
                "resend-cert",
                "new@example.test"),
            CancellationToken.None);
        Require(
            resend.Status == "ACCEPTED" &&
            fake.ResendCalls == 1,
            "Native verification resend mediation drifted.");

        var ambiguous = await new AccountRegistrationService(
            new ThrowingAccountRegistrationRemote(
                new HttpRequestException(
                    "certified ambiguous mutation")))
            .RegisterAsync(
                new AccountRegistrationRequest(
                    "register-ambiguous",
                    "new@example.test",
                    "New User",
                    "NativeRegistrationPassword123",
                    [
                        "legal-version-terms",
                        "legal-version-privacy",
                    ]),
                CancellationToken.None);
        Require(
            ambiguous.Status == "RESULT_UNKNOWN" &&
            ambiguous.Error?.Retryable == false,
            "Native registration ambiguity became an automatic-retry state.");
    }

    private static async Task CertifyTransportBoundaryAsync()
    {
        const string baseUrl =
            "https://registration-cert.example.test";

        var preflightHandler = new RegistrationTransportHandler(
            HttpStatusCode.OK,
            """
            {
              "status":"ready",
              "legal_documents":[
                {
                  "document_type":"TERMS_OF_SERVICE",
                  "title":"Terms of Service",
                  "slug":"terms",
                  "version_id":"legal-version-terms",
                  "version_number":3,
                  "effective_at":"2026-10-01T00:00:00.000Z",
                  "content_markdown":"# Terms\nCertification."
                },
                {
                  "document_type":"PRIVACY_POLICY",
                  "title":"Privacy Policy",
                  "slug":"privacy",
                  "version_id":"legal-version-privacy",
                  "version_number":4,
                  "effective_at":null,
                  "content_markdown":"# Privacy\nCertification."
                }
              ]
            }
            """,
            "/api/agent-sessions/native/registration",
            HttpMethod.Get,
            transientFailures: 2);
        using (var client = new HttpClient(preflightHandler))
        using (var remote = new AccountRegistrationRemote(
            client,
            baseUrl))
        {
            var result = await remote.PreflightAsync(
                "preflight-transport",
                CancellationToken.None);
            Require(
                result.Status == "ready" &&
                result.LegalDocuments?.Count == 2 &&
                preflightHandler.RequestCount == 3 &&
                preflightHandler.SawProtocol &&
                preflightHandler.SawExpectedPath &&
                preflightHandler.SawNoAuthorization &&
                preflightHandler.SawNoBody,
                "Native registration preflight transport drifted.");
        }

        var registerHandler = new RegistrationTransportHandler(
            HttpStatusCode.Created,
            """{"status":"verification_required"}""",
            "/api/agent-sessions/native/register",
            HttpMethod.Post);
        using (var client = new HttpClient(registerHandler))
        using (var remote = new AccountRegistrationRemote(
            client,
            baseUrl))
        {
            var result = await remote.RegisterAsync(
                "register-transport",
                "new@example.test",
                "New User",
                "NativeRegistrationPassword123",
                [
                    "legal-version-terms",
                    "legal-version-privacy",
                ],
                CancellationToken.None);
            Require(
                result.Status == "verification_required" &&
                registerHandler.RequestCount == 1 &&
                registerHandler.SawProtocol &&
                registerHandler.SawExpectedPath &&
                registerHandler.SawNoAuthorization &&
                registerHandler.BodyContains(
                    "email",
                    "new@example.test") &&
                registerHandler.BodyContains(
                    "password",
                    "NativeRegistrationPassword123") &&
                registerHandler.BodyArrayEquals(
                    "legal_version_ids",
                    [
                        "legal-version-terms",
                        "legal-version-privacy",
                    ]) &&
                !registerHandler.BodyHasKey(
                    "correlation_id"),
                "Native registration transport widened or drifted.");
        }

        var verifyHandler = new RegistrationTransportHandler(
            HttpStatusCode.OK,
            """{"status":"verified"}""",
            "/api/agent-sessions/native/verify-email",
            HttpMethod.Post);
        using (var client = new HttpClient(verifyHandler))
        using (var remote = new AccountRegistrationRemote(
            client,
            baseUrl))
        {
            var result = await remote.VerifyEmailAsync(
                "verify-transport",
                "new@example.test",
                "abcd2345",
                CancellationToken.None);
            Require(
                result.Status == "verified" &&
                verifyHandler.RequestCount == 1 &&
                verifyHandler.BodyContains(
                    "code",
                    "ABCD2345"),
                "Native email verification transport drifted.");
        }

        var resendHandler = new RegistrationTransportHandler(
            HttpStatusCode.Accepted,
            """{"status":"accepted"}""",
            "/api/agent-sessions/native/verification/resend",
            HttpMethod.Post);
        using (var client = new HttpClient(resendHandler))
        using (var remote = new AccountRegistrationRemote(
            client,
            baseUrl))
        {
            var result = await remote.ResendAsync(
                "resend-transport",
                "missing-or-present@example.test",
                CancellationToken.None);
            Require(
                result.Status == "accepted" &&
                resendHandler.RequestCount == 1 &&
                resendHandler.BodyContains(
                    "email",
                    "missing-or-present@example.test"),
                "Native verification resend lost enumeration-resistant accepted semantics.");
        }

        var widenedResend = new RegistrationTransportHandler(
            HttpStatusCode.Accepted,
            """
            {
              "status":"accepted",
              "email_sent":true
            }
            """,
            "/api/agent-sessions/native/verification/resend",
            HttpMethod.Post);
        using (var client = new HttpClient(widenedResend))
        using (var remote = new AccountRegistrationRemote(
            client,
            baseUrl))
        {
            await RequireThrowsAsync<InvalidDataException>(
                () => remote.ResendAsync(
                    "resend-widened",
                    "new@example.test",
                    CancellationToken.None),
                "Native verification resend accepted enumeration metadata.");
        }

        var mutationThrow = new RegistrationTransportHandler(
            HttpStatusCode.Created,
            """{"status":"verification_required"}""",
            "/api/agent-sessions/native/register",
            HttpMethod.Post,
            throwTransport: true);
        using (var client = new HttpClient(mutationThrow))
        using (var remote = new AccountRegistrationRemote(
            client,
            baseUrl))
        {
            await RequireThrowsAsync<HttpRequestException>(
                () => remote.RegisterAsync(
                    "register-single-attempt",
                    "new@example.test",
                    "New User",
                    "NativeRegistrationPassword123",
                    [
                        "legal-version-terms",
                        "legal-version-privacy",
                    ],
                    CancellationToken.None),
                "Native registration transport failure was hidden.");
            Require(
                mutationThrow.RequestCount == 1,
                "Native registration mutation was automatically replayed.");
        }

        var missingProtocol = new RegistrationTransportHandler(
            HttpStatusCode.OK,
            """
            {
              "status":"ready",
              "legal_documents":[]
            }
            """,
            "/api/agent-sessions/native/registration",
            HttpMethod.Get,
            includeProtocol: false);
        using (var client = new HttpClient(missingProtocol))
        using (var remote = new AccountRegistrationRemote(
            client,
            baseUrl))
        {
            await RequireThrowsAsync<InvalidDataException>(
                () => remote.PreflightAsync(
                    "preflight-no-protocol",
                    CancellationToken.None),
                "Native registration response without protocol was accepted.");
        }

        var redirect = new RegistrationTransportHandler(
            HttpStatusCode.Redirect,
            "{}",
            "/api/agent-sessions/native/register",
            HttpMethod.Post);
        using (var client = new HttpClient(redirect))
        using (var remote = new AccountRegistrationRemote(
            client,
            baseUrl))
        {
            await RequireThrowsAsync<InvalidDataException>(
                () => remote.RegisterAsync(
                    "register-redirect",
                    "new@example.test",
                    "New User",
                    "NativeRegistrationPassword123",
                    [
                        "legal-version-terms",
                        "legal-version-privacy",
                    ],
                    CancellationToken.None),
                "Native registration redirect was accepted.");
            Require(
                redirect.RequestCount == 1,
                "Native registration redirect was replayed.");
        }
    }

    private static async Task RequireThrowsAsync<TException>(
        Func<Task> action,
        string message)
        where TException : Exception
    {
        try
        {
            await action();
        }
        catch (TException)
        {
            return;
        }

        throw new InvalidOperationException(message);
    }

    private static void Require(
        bool condition,
        string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }
}

sealed class FakeAccountRegistrationRemote(
    RemoteAccountRegistrationPreflightResult preflight,
    RemoteAccountRegistrationMutationResult register,
    RemoteAccountRegistrationMutationResult verify,
    RemoteAccountRegistrationMutationResult resend)
    : IAccountRegistrationRemote
{
    public int PreflightCalls { get; private set; }
    public int RegisterCalls { get; private set; }
    public int VerifyCalls { get; private set; }
    public int ResendCalls { get; private set; }
    public string? LastPassword { get; private set; }
    public string? LastCode { get; private set; }

    public Task<RemoteAccountRegistrationPreflightResult>
        PreflightAsync(
            string correlationId,
            CancellationToken cancellationToken)
    {
        PreflightCalls += 1;
        return Task.FromResult(preflight);
    }

    public Task<RemoteAccountRegistrationMutationResult>
        RegisterAsync(
            string correlationId,
            string email,
            string name,
            string password,
            IReadOnlyList<string> legalVersionIds,
            CancellationToken cancellationToken)
    {
        RegisterCalls += 1;
        LastPassword = password;
        return Task.FromResult(register);
    }

    public Task<RemoteAccountRegistrationMutationResult>
        VerifyEmailAsync(
            string correlationId,
            string email,
            string code,
            CancellationToken cancellationToken)
    {
        VerifyCalls += 1;
        LastCode = code;
        return Task.FromResult(verify);
    }

    public Task<RemoteAccountRegistrationMutationResult>
        ResendAsync(
            string correlationId,
            string email,
            CancellationToken cancellationToken)
    {
        ResendCalls += 1;
        return Task.FromResult(resend);
    }
}

sealed class ThrowingAccountRegistrationRemote(Exception error)
    : IAccountRegistrationRemote
{
    public Task<RemoteAccountRegistrationPreflightResult>
        PreflightAsync(
            string correlationId,
            CancellationToken cancellationToken) =>
        Task.FromException<RemoteAccountRegistrationPreflightResult>(
            error);

    public Task<RemoteAccountRegistrationMutationResult>
        RegisterAsync(
            string correlationId,
            string email,
            string name,
            string password,
            IReadOnlyList<string> legalVersionIds,
            CancellationToken cancellationToken) =>
        Task.FromException<RemoteAccountRegistrationMutationResult>(
            error);

    public Task<RemoteAccountRegistrationMutationResult>
        VerifyEmailAsync(
            string correlationId,
            string email,
            string code,
            CancellationToken cancellationToken) =>
        Task.FromException<RemoteAccountRegistrationMutationResult>(
            error);

    public Task<RemoteAccountRegistrationMutationResult>
        ResendAsync(
            string correlationId,
            string email,
            CancellationToken cancellationToken) =>
        Task.FromException<RemoteAccountRegistrationMutationResult>(
            error);
}

sealed class RegistrationTransportHandler(
    HttpStatusCode statusCode,
    string json,
    string expectedPath,
    HttpMethod expectedMethod,
    int transientFailures = 0,
    bool includeProtocol = true,
    bool throwTransport = false) : HttpMessageHandler
{
    private JsonDocument? _lastBody;

    public int RequestCount { get; private set; }
    public bool SawProtocol { get; private set; }
    public bool SawExpectedPath { get; private set; }
    public bool SawNoAuthorization { get; private set; }
    public bool SawNoBody { get; private set; }

    public bool BodyHasKey(string key) =>
        _lastBody?.RootElement.TryGetProperty(
            key,
            out _) == true;

    public bool BodyContains(
        string key,
        string expected) =>
        _lastBody?.RootElement.TryGetProperty(
            key,
            out var value) == true &&
        value.ValueKind == JsonValueKind.String &&
        value.GetString() == expected;

    public bool BodyArrayEquals(
        string key,
        IReadOnlyList<string> expected)
    {
        if (_lastBody?.RootElement.TryGetProperty(
                key,
                out var value) != true ||
            value.ValueKind != JsonValueKind.Array)
        {
            return false;
        }

        return value.EnumerateArray()
            .Select(item => item.GetString())
            .SequenceEqual(expected);
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        RequestCount += 1;
        SawProtocol =
            request.Headers.TryGetValues(
                "x-bke-account-session-version",
                out var versions) &&
            versions.SingleOrDefault() ==
                AccountSessionRemote.ProtocolVersion;
        SawExpectedPath =
            request.Method == expectedMethod &&
            request.RequestUri?.AbsolutePath ==
                expectedPath;
        SawNoAuthorization =
            request.Headers.Authorization is null;
        SawNoBody = request.Content is null;

        _lastBody?.Dispose();
        _lastBody = null;
        if (request.Content is not null)
        {
            var body = await request.Content.ReadAsStringAsync(
                cancellationToken);
            _lastBody = JsonDocument.Parse(body);
        }

        if (throwTransport)
        {
            throw new HttpRequestException(
                "certified registration transport failure");
        }

        var transient = RequestCount <= transientFailures;
        var response = new HttpResponseMessage(
            transient
                ? HttpStatusCode.ServiceUnavailable
                : statusCode)
        {
            Content = new StringContent(
                transient
                    ? """{"error":"REGISTRATION_UNAVAILABLE"}"""
                    : json,
                Encoding.UTF8,
                "application/json"),
        };

        if (includeProtocol)
        {
            response.Headers.TryAddWithoutValidation(
                "x-bke-account-session-version",
                AccountSessionRemote.ProtocolVersion);
        }

        return response;
    }
}
