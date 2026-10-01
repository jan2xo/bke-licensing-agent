using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Infrastructure;

public sealed class AccountRegistrationRemote :
    IAccountRegistrationRemote,
    IDisposable
{
    private static readonly HashSet<HttpStatusCode>
        RetryablePreflightStatuses = new()
        {
            HttpStatusCode.RequestTimeout,
            (HttpStatusCode)425,
            (HttpStatusCode)429,
            HttpStatusCode.InternalServerError,
            HttpStatusCode.BadGateway,
            HttpStatusCode.ServiceUnavailable,
            HttpStatusCode.GatewayTimeout,
        };

    private readonly Uri _platformBaseUri;
    private readonly HttpClient _http;
    private readonly bool _ownsHttpClient;

    public AccountRegistrationRemote(
        HttpClient? httpClient = null,
        string? platformBaseUrl = null)
    {
        var rawBaseUrl = (
            platformBaseUrl ??
            Environment.GetEnvironmentVariable(
                "BKE_PLATFORM_BASE_URL") ??
            AgentRuntimeEnvironmentLoader.ProductionPlatformBaseUrl
        ).TrimEnd('/');

        if (!Uri.TryCreate(
                rawBaseUrl,
                UriKind.Absolute,
                out var baseUri))
        {
            throw new InvalidOperationException(
                "BKE_PLATFORM_BASE_URL is invalid.");
        }

        var allowLocal =
            Environment.GetEnvironmentVariable(
                "BKE_AGENT_VNEXT_ALLOW_INSECURE_LOCAL") == "1" &&
            baseUri.IsLoopback &&
            baseUri.Scheme == Uri.UriSchemeHttp;

        if (baseUri.Scheme != Uri.UriSchemeHttps && !allowLocal)
        {
            throw new InvalidOperationException(
                "Native registration authority requires HTTPS outside isolated loopback certification.");
        }

        if (!string.IsNullOrEmpty(baseUri.Query) ||
            !string.IsNullOrEmpty(baseUri.Fragment))
        {
            throw new InvalidOperationException(
                "BKE_PLATFORM_BASE_URL must not contain query or fragment.");
        }

        _platformBaseUri = baseUri;
        if (httpClient is null)
        {
            _http = new HttpClient(
                new HttpClientHandler
                {
                    AllowAutoRedirect = false,
                })
            {
                Timeout = TimeSpan.FromSeconds(30),
            };
            _ownsHttpClient = true;
        }
        else
        {
            _http = httpClient;
            _ownsHttpClient = false;
        }
    }

    public async Task<RemoteAccountRegistrationPreflightResult>
        PreflightAsync(
            string correlationId,
            CancellationToken cancellationToken)
    {
        ValidateCorrelationId(correlationId);

        using var response = await SendPreflightAsync(
            correlationId,
            cancellationToken);
        EnsureProtocol(response);

        await using var stream =
            await response.Content.ReadAsStreamAsync(
                cancellationToken);
        using var document = await JsonDocument.ParseAsync(
            stream,
            new JsonDocumentOptions { MaxDepth = 12 },
            cancellationToken);
        var root = document.RootElement;

        if (response.StatusCode == HttpStatusCode.OK)
        {
            RequireObjectKeys(root, [
                "status",
                "legal_documents",
            ]);
            if (RequiredString(root, "status", 64) != "ready")
            {
                throw new InvalidDataException(
                    "Native registration preflight status drifted.");
            }

            if (!root.TryGetProperty(
                    "legal_documents",
                    out var documents) ||
                documents.ValueKind != JsonValueKind.Array)
            {
                throw new InvalidDataException(
                    "Native registration Legal documents are invalid.");
            }

            var parsed = documents
                .EnumerateArray()
                .Select(ParseLegalDocument)
                .ToArray();

            if (parsed.Length != 2 ||
                parsed.Select(item => item.DocumentType)
                    .Distinct(StringComparer.Ordinal)
                    .Count() != 2 ||
                parsed.Any(item =>
                    item.DocumentType is not (
                        "TERMS_OF_SERVICE" or
                        "PRIVACY_POLICY")))
            {
                throw new InvalidDataException(
                    "Native registration Legal document set drifted.");
            }

            return new RemoteAccountRegistrationPreflightResult(
                "ready",
                parsed);
        }

        if (response.StatusCode ==
            HttpStatusCode.ServiceUnavailable)
        {
            RequireObjectKeys(root, ["error"]);
            var error = RequiredString(root, "error", 128);
            if (error != "REGISTRATION_UNAVAILABLE")
            {
                throw new InvalidDataException(
                    "Native registration preflight error drifted.");
            }

            return new RemoteAccountRegistrationPreflightResult(
                "registration_unavailable",
                ErrorCode: error,
                Retryable: true);
        }

        throw new InvalidDataException(
            "Native registration preflight returned an unsupported response.");
    }

    public async Task<RemoteAccountRegistrationMutationResult>
        RegisterAsync(
            string correlationId,
            string email,
            string name,
            string password,
            IReadOnlyList<string> legalVersionIds,
            CancellationToken cancellationToken)
    {
        ValidateCorrelationId(correlationId);
        ValidateEmail(email);
        if (string.IsNullOrWhiteSpace(name) ||
            name.Trim().Length is < 2 or > 100 ||
            name.Any(character => character < 32) ||
            string.IsNullOrEmpty(password) ||
            password.Length > 128 ||
            legalVersionIds.Count != 2 ||
            legalVersionIds.Any(value =>
                string.IsNullOrWhiteSpace(value) ||
                value.Length > 256 ||
                value.Any(character => character < 32)) ||
            legalVersionIds.Distinct(
                StringComparer.Ordinal).Count() != 2)
        {
            throw new InvalidDataException(
                "Invalid native registration request.");
        }

        using var response = await SendMutationAsync(
            "/api/agent-sessions/native/register",
            correlationId,
            JsonSerializer.Serialize(new
            {
                email = email.Trim(),
                name = name.Trim(),
                password,
                legal_version_ids = legalVersionIds,
            }),
            cancellationToken);

        return await ParseMutationAsync(
            response,
            HttpStatusCode.Created,
            "verification_required",
            new Dictionary<string, string>(
                StringComparer.Ordinal)
            {
                ["INVALID_INPUT"] = "invalid_input",
                ["RATE_LIMITED"] = "rate_limited",
                ["ACCOUNT_EXISTS"] = "account_exists",
                ["LEGAL_ACCEPTANCE_REQUIRED"] =
                    "legal_acceptance_required",
                ["REGISTRATION_UNAVAILABLE"] =
                    "registration_unavailable",
            },
            cancellationToken);
    }

    public async Task<RemoteAccountRegistrationMutationResult>
        VerifyEmailAsync(
            string correlationId,
            string email,
            string code,
            CancellationToken cancellationToken)
    {
        ValidateCorrelationId(correlationId);
        ValidateEmail(email);

        var normalizedCode =
            code.Trim().ToUpperInvariant();
        if (!ValidVerificationCode(normalizedCode))
        {
            throw new InvalidDataException(
                "Invalid native email verification code.");
        }

        using var response = await SendMutationAsync(
            "/api/agent-sessions/native/verify-email",
            correlationId,
            JsonSerializer.Serialize(new
            {
                email = email.Trim(),
                code = normalizedCode,
            }),
            cancellationToken);

        return await ParseMutationAsync(
            response,
            HttpStatusCode.OK,
            "verified",
            new Dictionary<string, string>(
                StringComparer.Ordinal)
            {
                ["INVALID_INPUT"] = "invalid_input",
                ["INVALID_VERIFICATION_CODE"] =
                    "invalid_verification_code",
                ["RATE_LIMITED"] = "rate_limited",
            },
            cancellationToken);
    }

    public async Task<RemoteAccountRegistrationMutationResult>
        ResendAsync(
            string correlationId,
            string email,
            CancellationToken cancellationToken)
    {
        ValidateCorrelationId(correlationId);
        ValidateEmail(email);

        using var response = await SendMutationAsync(
            "/api/agent-sessions/native/verification/resend",
            correlationId,
            JsonSerializer.Serialize(new
            {
                email = email.Trim(),
            }),
            cancellationToken);

        return await ParseMutationAsync(
            response,
            HttpStatusCode.Accepted,
            "accepted",
            new Dictionary<string, string>(
                StringComparer.Ordinal)
            {
                ["INVALID_INPUT"] = "invalid_input",
            },
            cancellationToken);
    }

    private async Task<HttpResponseMessage> SendPreflightAsync(
        string correlationId,
        CancellationToken cancellationToken)
    {
        Exception? lastError = null;

        for (var attempt = 0; attempt <= 2; attempt++)
        {
            using var request = CreateRequest(
                HttpMethod.Get,
                "/api/agent-sessions/native/registration",
                correlationId);

            try
            {
                var response = await _http.SendAsync(
                    request,
                    HttpCompletionOption.ResponseHeadersRead,
                    cancellationToken);

                if ((int)response.StatusCode is >= 300 and <= 399)
                {
                    response.Dispose();
                    throw new InvalidDataException(
                        "Native registration preflight redirected.");
                }

                if (RetryablePreflightStatuses.Contains(
                        response.StatusCode) &&
                    attempt < 2)
                {
                    response.Dispose();
                    await Task.Delay(
                        TimeSpan.FromSeconds(
                            0.25 * Math.Pow(2, attempt)),
                        cancellationToken);
                    continue;
                }

                return response;
            }
            catch (OperationCanceledException)
                when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception error) when (
                attempt < 2 &&
                error is HttpRequestException or TaskCanceledException)
            {
                lastError = error;
                await Task.Delay(
                    TimeSpan.FromSeconds(
                        0.25 * Math.Pow(2, attempt)),
                    cancellationToken);
            }
            catch (Exception error)
            {
                lastError = error;
                break;
            }
        }

        throw new HttpRequestException(
            "Native registration preflight request failed.",
            lastError);
    }

    private async Task<HttpResponseMessage> SendMutationAsync(
        string path,
        string correlationId,
        string json,
        CancellationToken cancellationToken)
    {
        using var request = CreateRequest(
            HttpMethod.Post,
            path,
            correlationId);
        request.Content = new StringContent(
            json,
            Encoding.UTF8,
            "application/json");

        var response = await _http.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);

        if ((int)response.StatusCode is >= 300 and <= 399)
        {
            response.Dispose();
            throw new InvalidDataException(
                "Native registration endpoint redirected.");
        }

        return response;
    }

    private HttpRequestMessage CreateRequest(
        HttpMethod method,
        string path,
        string correlationId)
    {
        var request = new HttpRequestMessage(
            method,
            new Uri(_platformBaseUri, path));
        request.Headers.Accept.Add(
            new MediaTypeWithQualityHeaderValue(
                "application/json"));
        request.Headers.UserAgent.ParseAdd(
            "bke-licensing-agent");
        request.Headers.TryAddWithoutValidation(
            "x-bke-account-session-version",
            AccountSessionRemote.ProtocolVersion);
        request.Headers.TryAddWithoutValidation(
            "x-request-id",
            correlationId);
        return request;
    }

    private static async Task<RemoteAccountRegistrationMutationResult>
        ParseMutationAsync(
            HttpResponseMessage response,
            HttpStatusCode successStatusCode,
            string successStatus,
            IReadOnlyDictionary<string, string> errorMap,
            CancellationToken cancellationToken)
    {
        EnsureProtocol(response);

        await using var stream =
            await response.Content.ReadAsStreamAsync(
                cancellationToken);
        using var document = await JsonDocument.ParseAsync(
            stream,
            new JsonDocumentOptions { MaxDepth = 8 },
            cancellationToken);
        var root = document.RootElement;

        if (response.StatusCode == successStatusCode)
        {
            RequireObjectKeys(root, ["status"]);
            if (RequiredString(root, "status", 64) != successStatus)
            {
                throw new InvalidDataException(
                    "Native registration success state drifted.");
            }

            return new RemoteAccountRegistrationMutationResult(
                successStatus);
        }

        RequireObjectKeys(root, ["error"]);
        var error = RequiredString(root, "error", 128);
        if (!errorMap.TryGetValue(
                error,
                out var normalized))
        {
            throw new InvalidDataException(
                "Native registration error code drifted.");
        }

        return new RemoteAccountRegistrationMutationResult(
            normalized,
            error,
            response.StatusCode == (HttpStatusCode)429 ||
            response.StatusCode ==
                HttpStatusCode.ServiceUnavailable);
    }

    private static AccountRegistrationLegalDocument
        ParseLegalDocument(JsonElement item)
    {
        RequireObjectKeys(item, [
            "document_type",
            "title",
            "slug",
            "version_id",
            "version_number",
            "effective_at",
            "content_markdown",
        ]);

        var documentType =
            RequiredString(item, "document_type", 64);
        var versionNumber =
            RequiredPositiveInt(item, "version_number");
        var effectiveAt =
            OptionalTimestamp(item, "effective_at");

        return new AccountRegistrationLegalDocument(
            documentType,
            RequiredString(item, "title", 256),
            RequiredString(item, "slug", 256),
            RequiredString(item, "version_id", 256),
            versionNumber,
            effectiveAt,
            RequiredString(item, "content_markdown", 524_288));
    }

    private static void EnsureProtocol(
        HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues(
                "x-bke-account-session-version",
                out var values))
        {
            throw new InvalidDataException(
                "Native registration response is missing its protocol version.");
        }

        var versions = values.ToArray();
        if (versions.Length != 1 ||
            versions[0] != AccountSessionRemote.ProtocolVersion)
        {
            throw new InvalidDataException(
                "Native registration protocol version drifted.");
        }
    }

    private static void RequireObjectKeys(
        JsonElement item,
        IReadOnlyCollection<string> expected)
    {
        if (item.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException(
                "Native registration response shape is invalid.");
        }

        var keys = item.EnumerateObject()
            .Select(property => property.Name)
            .ToHashSet(StringComparer.Ordinal);
        if (!keys.SetEquals(expected))
        {
            throw new InvalidDataException(
                "Native registration response shape drifted.");
        }
    }

    private static string RequiredString(
        JsonElement root,
        string name,
        int maximumLength)
    {
        if (!root.TryGetProperty(name, out var value) ||
            value.ValueKind != JsonValueKind.String ||
            string.IsNullOrWhiteSpace(value.GetString()) ||
            value.GetString()!.Length > maximumLength)
        {
            throw new InvalidDataException(
                $"Missing or invalid {name}.");
        }

        return value.GetString()!;
    }

    private static int RequiredPositiveInt(
        JsonElement root,
        string name)
    {
        if (!root.TryGetProperty(name, out var value) ||
            !value.TryGetInt32(out var result) ||
            result <= 0)
        {
            throw new InvalidDataException(
                $"Missing or invalid {name}.");
        }

        return result;
    }

    private static string? OptionalTimestamp(
        JsonElement root,
        string name)
    {
        if (!root.TryGetProperty(name, out var value))
        {
            throw new InvalidDataException(
                $"Missing {name}.");
        }

        if (value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        if (value.ValueKind != JsonValueKind.String ||
            !DateTimeOffset.TryParse(
                value.GetString(),
                out _))
        {
            throw new InvalidDataException(
                $"Invalid {name}.");
        }

        return value.GetString();
    }

    private static void ValidateCorrelationId(
        string correlationId)
    {
        if (string.IsNullOrWhiteSpace(correlationId) ||
            correlationId.Length > 128 ||
            correlationId.Any(character => character < 32))
        {
            throw new InvalidDataException(
                "Invalid correlation identifier.");
        }
    }

    private static void ValidateEmail(string email)
    {
        if (string.IsNullOrWhiteSpace(email) ||
            email.Length > 320 ||
            !System.Net.Mail.MailAddress.TryCreate(
                email,
                out var parsed) ||
            !string.Equals(
                parsed.Address,
                email.Trim(),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "Invalid registration email.");
        }
    }

    private static bool ValidVerificationCode(string code)
    {
        const string alphabet =
            "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        return code.Length == 8 &&
            code.All(alphabet.Contains);
    }

    public void Dispose()
    {
        if (_ownsHttpClient)
        {
            _http.Dispose();
        }
    }
}
