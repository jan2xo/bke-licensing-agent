using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;

namespace BKE.LicensingAgent.Infrastructure;

public sealed class AccountOrganizationRemote :
    IAccountOrganizationRemote,
    IDisposable
{
    private const string Endpoint =
        "/api/agent-sessions/account/organization";
    private const string CreateEndpoint =
        "/api/agent-sessions/account/organization/create";
    private const string ProfileEndpoint =
        "/api/agent-sessions/account/organization/profile";
    private const string InvitationCreateEndpoint =
        "/api/agent-sessions/account/organization/invitations/create";
    private const string InvitationManageEndpoint =
        "/api/agent-sessions/account/organization/invitations/manage";
    private const string MemberManageEndpoint =
        "/api/agent-sessions/account/organization/members/manage";

    private readonly Uri _platformBaseUri;
    private readonly HttpClient _http;
    private readonly bool _ownsHttpClient;

    public AccountOrganizationRemote(
        HttpClient? httpClient = null,
        string? platformBaseUrl = null)
    {
        var rawBaseUrl = (
            platformBaseUrl ??
            Environment.GetEnvironmentVariable("BKE_PLATFORM_BASE_URL") ??
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
                "Organization authority requires HTTPS outside isolated loopback certification.");
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
                new HttpClientHandler { AllowAutoRedirect = false })
            {
                Timeout = TimeSpan.FromSeconds(20),
            };
            _ownsHttpClient = true;
        }
        else
        {
            _http = httpClient;
            _ownsHttpClient = false;
        }
    }

    public async Task<RemoteAccountOrganizationResult> GetAsync(
        string accessToken,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(accessToken) ||
            accessToken.Length > 8192)
        {
            return new RemoteAccountOrganizationResult(
                "failed",
                ErrorCode: "INVALID_INPUT");
        }

        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            new Uri(_platformBaseUri, Endpoint));
        request.Headers.Accept.Add(
            new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.UserAgent.ParseAdd("bke-licensing-agent");
        request.Headers.Authorization =
            new AuthenticationHeaderValue("Bearer", accessToken);
        request.Headers.TryAddWithoutValidation(
            "x-bke-account-session-version",
            AccountSessionRemote.ProtocolVersion);
        request.Headers.TryAddWithoutValidation(
            "x-request-id",
            Guid.NewGuid().ToString("N"));

        using var response = await _http.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);

        if ((int)response.StatusCode is >= 300 and <= 399)
        {
            throw new HttpRequestException(
                "BKE organization authority redirected.");
        }

        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return new RemoteAccountOrganizationResult(
                "failed",
                ErrorCode: "ORGANIZATION_UNAVAILABLE",
                Retryable: true);
        }

        EnsureProtocol(response);
        using var document = await ReadJsonAsync(
            response,
            cancellationToken);
        var root = document.RootElement;

        if (!response.IsSuccessStatusCode)
        {
            var error = OptionalString(root, "error") ??
                "ORGANIZATION_UNAVAILABLE";
            if (
                response.StatusCode == HttpStatusCode.Unauthorized ||
                (response.StatusCode == HttpStatusCode.Forbidden &&
                    error == "ACCOUNT_FORBIDDEN")
            )
            {
                throw new UnauthorizedAccessException(
                    "BKE organization authority rejected the selected account session.");
            }

            return new RemoteAccountOrganizationResult(
                "failed",
                ErrorCode: error,
                Retryable:
                    (int)response.StatusCode == 429 ||
                    response.StatusCode ==
                        HttpStatusCode.ServiceUnavailable);
        }

        var status = RequiredString(root, "status");
        if (status == "not_organization")
        {
            return new RemoteAccountOrganizationResult(
                "not_organization");
        }
        if (status != "ready")
        {
            throw new InvalidDataException(
                "Organization overview status drifted.");
        }

        var account = RequiredObject(root, "account");
        if (RequiredString(account, "type") != "ORGANIZATION")
        {
            throw new InvalidDataException(
                "Organization account type drifted.");
        }
        var role = RequiredRole(account, "role");

        var permissions = RequiredObject(root, "permissions");
        var organization = RequiredObject(root, "organization");
        var counts = RequiredObject(root, "counts");

        var members = RequiredMembers(root, "members");
        var invitations = RequiredInvitations(
            root,
            "invitations");

        return new RemoteAccountOrganizationResult(
            "ready",
            Account: new AccountOrganizationAccount(
                RequiredBoundedString(account, "display_name", 120),
                RequiredUppercaseToken(
                    account,
                    "lifecycle_state",
                    64),
                role),
            Permissions: new AccountOrganizationPermissions(
                RequiredBoolean(
                    permissions,
                    "manage_members"),
                RequiredBoolean(
                    permissions,
                    "view_billing"),
                RequiredBoolean(
                    permissions,
                    "view_licenses")),
            Organization: new AccountOrganizationProfile(
                RequiredBoundedString(
                    organization,
                    "legal_name",
                    180),
                OptionalBoundedString(
                    organization,
                    "registration_number",
                    80)),
            BillingEmail: OptionalBoundedString(
                root,
                "billing_email",
                320),
            TaxId: OptionalBoundedString(
                root,
                "tax_id",
                80),
            Counts: new AccountOrganizationCounts(
                OptionalNonNegativeInteger(counts, "licenses"),
                OptionalNonNegativeInteger(
                    counts,
                    "subscriptions"),
                OptionalNonNegativeInteger(counts, "orders")),
            Members: members,
            Invitations: invitations);
    }

    public async Task<RemoteAccountOrganizationCreateResult> CreateAsync(
        string accessToken,
        string displayName,
        string legalName,
        string billingEmail,
        string? registrationNumber,
        string? taxId,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(accessToken) ||
            accessToken.Length > 8192 ||
            !ValidBounded(displayName, 2, 120) ||
            !ValidBounded(legalName, 2, 180) ||
            !ValidBounded(billingEmail, 3, 320) ||
            (registrationNumber is not null &&
                !ValidOptionalBounded(registrationNumber, 80)) ||
            (taxId is not null &&
                !ValidOptionalBounded(taxId, 80)))
        {
            return new RemoteAccountOrganizationCreateResult(
                "invalid_input",
                ErrorCode: "INVALID_INPUT");
        }

        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            new Uri(_platformBaseUri, CreateEndpoint));
        request.Headers.Accept.Add(
            new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.UserAgent.ParseAdd("bke-licensing-agent");
        request.Headers.Authorization =
            new AuthenticationHeaderValue("Bearer", accessToken);
        request.Headers.TryAddWithoutValidation(
            "x-bke-account-session-version",
            AccountSessionRemote.ProtocolVersion);
        request.Headers.TryAddWithoutValidation(
            "x-request-id",
            Guid.NewGuid().ToString("N"));
        request.Content = new StringContent(
            JsonSerializer.Serialize(new
            {
                display_name = displayName,
                legal_name = legalName,
                billing_email = billingEmail,
                registration_number = registrationNumber,
                tax_id = taxId,
            }),
            Encoding.UTF8,
            "application/json");

        // Organization creation is deliberately single-attempt.
        // Replaying an ambiguous POST can create a duplicate organization.
        using var response = await _http.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);

        if ((int)response.StatusCode is >= 300 and <= 399)
        {
            throw new HttpRequestException(
                "BKE organization creation authority redirected.");
        }

        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return new RemoteAccountOrganizationCreateResult(
                "organization_unavailable",
                ErrorCode: "ORGANIZATION_CREATE_UNAVAILABLE",
                Retryable: true);
        }

        EnsureProtocol(response);
        using var document = await ReadJsonAsync(
            response,
            cancellationToken);
        var root = document.RootElement;

        if (!response.IsSuccessStatusCode)
        {
            var error = OptionalString(root, "error") ??
                "ORGANIZATION_CREATE_UNAVAILABLE";
            if (response.StatusCode == HttpStatusCode.Unauthorized &&
                error == "INVALID_TOKEN")
            {
                throw new UnauthorizedAccessException(
                    "BKE organization creation authority rejected the account session.");
            }

            var status = error switch
            {
                "INVALID_INPUT" => "invalid_input",
                "EMAIL_NOT_VERIFIED" => "email_not_verified",
                "LEGAL_REACCEPTANCE_REQUIRED" =>
                    "legal_reacceptance_required",
                "RATE_LIMITED" => "rate_limited",
                "LEGAL_DOCUMENTS_UNAVAILABLE" =>
                    "legal_documents_unavailable",
                _ => "organization_unavailable",
            };
            return new RemoteAccountOrganizationCreateResult(
                status,
                ErrorCode: error,
                Retryable:
                    (int)response.StatusCode == 429 ||
                    response.StatusCode ==
                        HttpStatusCode.ServiceUnavailable);
        }

        if (RequiredString(root, "status") != "created" ||
            !RequiredBoolean(root, "switch_required"))
        {
            throw new InvalidDataException(
                "Organization creation response drifted.");
        }
        if (root.TryGetProperty("account_id", out _) ||
            root.TryGetProperty("user_id", out _) ||
            root.TryGetProperty("owner_id", out _))
        {
            throw new InvalidDataException(
                "Organization creation response exposed authority identifiers.");
        }

        var account = RequiredObject(root, "account");
        if (RequiredString(account, "type") != "ORGANIZATION" ||
            account.TryGetProperty("id", out _) ||
            account.TryGetProperty("account_id", out _) ||
            account.TryGetProperty("owner_id", out _))
        {
            throw new InvalidDataException(
                "Organization creation account response drifted.");
        }

        return new RemoteAccountOrganizationCreateResult(
            "created",
            DisplayName:
                RequiredBoundedString(account, "display_name", 120),
            SwitchRequired: true);
    }

    public async Task<RemoteAccountOrganizationProfileUpdateResult>
        UpdateProfileAsync(
            string accessToken,
            bool updateOrganizationProfile,
            string? displayName,
            string? legalName,
            string? registrationNumber,
            bool updateBillingProfile,
            string? billingEmail,
            string? taxId,
            CancellationToken cancellationToken)
    {
        var organizationValid =
            !updateOrganizationProfile
                ? displayName is null &&
                  legalName is null &&
                  registrationNumber is null
                : ValidBounded(displayName, 2, 120) &&
                  ValidBounded(legalName, 2, 180) &&
                  (registrationNumber is null ||
                   ValidOptionalBounded(registrationNumber, 80));

        var billingValid =
            !updateBillingProfile
                ? billingEmail is null && taxId is null
                : ValidBounded(billingEmail, 3, 320) &&
                  (taxId is null ||
                   ValidOptionalBounded(taxId, 80));

        if (string.IsNullOrWhiteSpace(accessToken) ||
            accessToken.Length > 8192 ||
            (!updateOrganizationProfile && !updateBillingProfile) ||
            !organizationValid ||
            !billingValid)
        {
            return new RemoteAccountOrganizationProfileUpdateResult(
                "invalid_input",
                ErrorCode: "INVALID_INPUT");
        }

        var payload = new Dictionary<string, object?>();
        if (updateOrganizationProfile)
        {
            payload["display_name"] = displayName!.Trim();
            payload["legal_name"] = legalName!.Trim();
            payload["registration_number"] =
                string.IsNullOrWhiteSpace(registrationNumber)
                    ? null
                    : registrationNumber.Trim();
        }
        if (updateBillingProfile)
        {
            payload["billing_email"] = billingEmail!.Trim();
            payload["tax_id"] =
                string.IsNullOrWhiteSpace(taxId)
                    ? null
                    : taxId.Trim();
        }

        using var request = new HttpRequestMessage(
            HttpMethod.Patch,
            new Uri(_platformBaseUri, ProfileEndpoint));
        request.Headers.Accept.Add(
            new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.UserAgent.ParseAdd("bke-licensing-agent");
        request.Headers.Authorization =
            new AuthenticationHeaderValue("Bearer", accessToken);
        request.Headers.TryAddWithoutValidation(
            "x-bke-account-session-version",
            AccountSessionRemote.ProtocolVersion);
        request.Headers.TryAddWithoutValidation(
            "x-request-id",
            Guid.NewGuid().ToString("N"));
        request.Content = new StringContent(
            JsonSerializer.Serialize(payload),
            Encoding.UTF8,
            "application/json");

        // Profile mutation is deliberately single-attempt. A transport
        // failure after Digital Solutions commits the update is ambiguous,
        // so automatic replay is forbidden.
        using var response = await _http.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);

        if ((int)response.StatusCode is >= 300 and <= 399)
        {
            throw new HttpRequestException(
                "BKE organization profile authority redirected.");
        }

        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return new RemoteAccountOrganizationProfileUpdateResult(
                "profile_unavailable",
                ErrorCode: "ORGANIZATION_PROFILE_UPDATE_UNAVAILABLE",
                Retryable: true);
        }

        EnsureProtocol(response);
        using var document = await ReadJsonAsync(
            response,
            cancellationToken);
        var root = document.RootElement;

        if (!response.IsSuccessStatusCode)
        {
            var error = OptionalString(root, "error") ??
                "ORGANIZATION_PROFILE_UPDATE_UNAVAILABLE";

            if (response.StatusCode == HttpStatusCode.Unauthorized &&
                error == "INVALID_TOKEN")
            {
                throw new UnauthorizedAccessException(
                    "BKE organization profile authority rejected the account session.");
            }

            var status = error switch
            {
                "INVALID_INPUT" => "invalid_input",
                "ACCOUNT_NOT_ORGANIZATION" => "not_organization",
                "ACCOUNT_ROLE_FORBIDDEN" => "account_forbidden",
                "RATE_LIMITED" => "rate_limited",
                _ => "profile_unavailable",
            };
            return new RemoteAccountOrganizationProfileUpdateResult(
                status,
                ErrorCode: error,
                Retryable:
                    (int)response.StatusCode == 429 ||
                    response.StatusCode ==
                        HttpStatusCode.ServiceUnavailable);
        }

        if (RequiredString(root, "status") != "updated")
        {
            throw new InvalidDataException(
                "Organization profile update response drifted.");
        }
        if (root.TryGetProperty("account_id", out _) ||
            root.TryGetProperty("user_id", out _) ||
            root.TryGetProperty("owner_id", out _) ||
            root.TryGetProperty("member_id", out _) ||
            root.TryGetProperty("invitation_id", out _))
        {
            throw new InvalidDataException(
                "Organization profile update response exposed authority identifiers.");
        }

        return new RemoteAccountOrganizationProfileUpdateResult(
            "updated");
    }

    public async Task<RemoteAccountOrganizationInvitationCreateResult>
        CreateInvitationAsync(
            string accessToken,
            string email,
            string role,
            CancellationToken cancellationToken)
    {
        var normalizedEmail = email?.Trim();
        var emailValid =
            !string.IsNullOrWhiteSpace(normalizedEmail) &&
            normalizedEmail.Length <= 320 &&
            System.Net.Mail.MailAddress.TryCreate(
                normalizedEmail,
                out var parsedEmail) &&
            string.Equals(
                parsedEmail.Address,
                normalizedEmail,
                StringComparison.OrdinalIgnoreCase);
        var roleValid =
            role is "OWNER" or "BILLING" or
                "LICENSE_MANAGER" or "MEMBER";

        if (string.IsNullOrWhiteSpace(accessToken) ||
            accessToken.Length > 8192 ||
            !emailValid ||
            !roleValid)
        {
            return new RemoteAccountOrganizationInvitationCreateResult(
                "invalid_input",
                ErrorCode: "INVALID_INPUT");
        }

        var payload = new Dictionary<string, object?>
        {
            ["email"] = normalizedEmail,
            ["role"] = role,
        };

        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            new Uri(_platformBaseUri, InvitationCreateEndpoint));
        request.Headers.Accept.Add(
            new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.UserAgent.ParseAdd("bke-licensing-agent");
        request.Headers.Authorization =
            new AuthenticationHeaderValue("Bearer", accessToken);
        request.Headers.TryAddWithoutValidation(
            "x-bke-account-session-version",
            AccountSessionRemote.ProtocolVersion);
        request.Headers.TryAddWithoutValidation(
            "x-request-id",
            Guid.NewGuid().ToString("N"));
        request.Content = new StringContent(
            JsonSerializer.Serialize(payload),
            Encoding.UTF8,
            "application/json");

        // Invitation issuance is deliberately single-attempt. A transport
        // failure after Digital Solutions commits the invitation is
        // ambiguous, and replay could create or rotate invitation state.
        using var response = await _http.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);

        if ((int)response.StatusCode is >= 300 and <= 399)
        {
            throw new HttpRequestException(
                "BKE organization invitation authority redirected.");
        }

        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return new RemoteAccountOrganizationInvitationCreateResult(
                "invitation_unavailable",
                ErrorCode: "ORGANIZATION_INVITATION_UNAVAILABLE",
                Retryable: true);
        }

        EnsureProtocol(response);
        using var document = await ReadJsonAsync(
            response,
            cancellationToken);
        var root = document.RootElement;

        if (!response.IsSuccessStatusCode)
        {
            var error = OptionalString(root, "error") ??
                "ORGANIZATION_INVITATION_UNAVAILABLE";

            if (response.StatusCode == HttpStatusCode.Unauthorized &&
                error == "INVALID_TOKEN")
            {
                throw new UnauthorizedAccessException(
                    "BKE organization invitation authority rejected the account session.");
            }

            var status = error switch
            {
                "INVALID_INPUT" => "invalid_input",
                "ACCOUNT_NOT_ORGANIZATION" => "not_organization",
                "ACCOUNT_ROLE_FORBIDDEN" => "account_forbidden",
                "INVITATION_ALREADY_PENDING" => "conflict",
                "ACCOUNT_MEMBER_EXISTS" => "conflict",
                "MEMBER_ALREADY_EXISTS" => "conflict",
                "RATE_LIMITED" => "rate_limited",
                _ => "invitation_unavailable",
            };

            return new RemoteAccountOrganizationInvitationCreateResult(
                status,
                ErrorCode: error,
                Retryable:
                    (int)response.StatusCode == 429 ||
                    response.StatusCode ==
                        HttpStatusCode.ServiceUnavailable);
        }

        if (RequiredString(root, "status") != "created" ||
            !root.TryGetProperty("invitation", out var invitation) ||
            invitation.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException(
                "Organization invitation response drifted.");
        }

        var invitedEmail = RequiredString(invitation, "email");
        var invitedRole = RequiredString(invitation, "role");
        var invitationStatus = RequiredString(invitation, "status");
        var expiresAt = RequiredString(invitation, "expires_at");
        var createdAt = RequiredString(invitation, "created_at");
        var invitationCode = RequiredString(root, "invitation_code");

        if (invitedEmail.Length > 320 ||
            !System.Net.Mail.MailAddress.TryCreate(
                invitedEmail,
                out var parsedInvitedEmail) ||
            !string.Equals(
                parsedInvitedEmail.Address,
                invitedEmail,
                StringComparison.OrdinalIgnoreCase) ||
            invitedRole is not (
                "OWNER" or "BILLING" or
                "LICENSE_MANAGER" or "MEMBER") ||
            invitationStatus.Length > 32 ||
            !DateTimeOffset.TryParse(expiresAt, out _) ||
            !DateTimeOffset.TryParse(createdAt, out _) ||
            invitationCode.Length is < 8 or > 1024 ||
            invitationCode.Any(character => character < 32))
        {
            throw new InvalidDataException(
                "Organization invitation response contained invalid fields.");
        }

        if (root.TryGetProperty("account_id", out _) ||
            root.TryGetProperty("user_id", out _) ||
            root.TryGetProperty("owner_id", out _) ||
            root.TryGetProperty("invitation_id", out _) ||
            root.TryGetProperty("token_hash", out _) ||
            invitation.TryGetProperty("account_id", out _) ||
            invitation.TryGetProperty("user_id", out _) ||
            invitation.TryGetProperty("owner_id", out _) ||
            invitation.TryGetProperty("id", out _) ||
            invitation.TryGetProperty("token_hash", out _))
        {
            throw new InvalidDataException(
                "Organization invitation response exposed authority identifiers.");
        }

        return new RemoteAccountOrganizationInvitationCreateResult(
            "created",
            new AccountOrganizationInvitationIssued(
                invitedEmail,
                invitedRole,
                invitationStatus,
                expiresAt,
                createdAt),
            invitationCode);
    }

    public async Task<RemoteAccountOrganizationInvitationManageResult>
        ManageInvitationAsync(
            string accessToken,
            string action,
            string managementHandle,
            CancellationToken cancellationToken)
    {
        var actionValue = action switch
        {
            "RESEND" => "resend",
            "REVOKE" => "revoke",
            _ => null,
        };
        var handleValid =
            !string.IsNullOrWhiteSpace(managementHandle) &&
            System.Text.RegularExpressions.Regex.IsMatch(
                managementHandle,
                "^bke-org-invite-v1_[0-9a-f]{64}$",
                System.Text.RegularExpressions.RegexOptions.CultureInvariant);

        if (string.IsNullOrWhiteSpace(accessToken) ||
            accessToken.Length > 8192 ||
            actionValue is null ||
            !handleValid)
        {
            return new RemoteAccountOrganizationInvitationManageResult(
                "invalid_input",
                ErrorCode: "INVALID_INPUT");
        }

        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            new Uri(_platformBaseUri, InvitationManageEndpoint));
        request.Headers.Accept.Add(
            new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.UserAgent.ParseAdd("bke-licensing-agent");
        request.Headers.Authorization =
            new AuthenticationHeaderValue("Bearer", accessToken);
        request.Headers.TryAddWithoutValidation(
            "x-bke-account-session-version",
            AccountSessionRemote.ProtocolVersion);
        request.Headers.TryAddWithoutValidation(
            "x-request-id",
            Guid.NewGuid().ToString("N"));
        request.Content = new StringContent(
            JsonSerializer.Serialize(new
            {
                action = actionValue,
                management_handle = managementHandle,
            }),
            Encoding.UTF8,
            "application/json");

        // Resend/revoke are deliberately single-attempt. A transport
        // failure after Digital Solutions commits either mutation is
        // ambiguous, and automatic replay can rotate or repeat state.
        using var response = await _http.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);

        if ((int)response.StatusCode is >= 300 and <= 399)
        {
            throw new HttpRequestException(
                "BKE organization invitation management authority redirected.");
        }

        EnsureProtocol(response);
        using var document = await ReadJsonAsync(
            response,
            cancellationToken);
        var root = document.RootElement;

        if (!response.IsSuccessStatusCode)
        {
            var error = OptionalString(root, "error") ??
                "ORGANIZATION_INVITATION_MANAGEMENT_UNAVAILABLE";

            if (response.StatusCode == HttpStatusCode.Unauthorized &&
                error == "INVALID_TOKEN")
            {
                throw new UnauthorizedAccessException(
                    "BKE organization invitation management authority rejected the account session.");
            }

            var status = error switch
            {
                "INVALID_INPUT" => "invalid_input",
                "ACCOUNT_NOT_ORGANIZATION" => "not_organization",
                "ACCOUNT_ROLE_FORBIDDEN" => "account_forbidden",
                "INVITATION_NOT_FOUND" => "invitation_not_found",
                "INVITATION_NOT_PENDING" => "invitation_not_pending",
                "INVITATION_EXPIRED" => "invitation_expired",
                "RATE_LIMITED" => "rate_limited",
                _ => "management_unavailable",
            };

            return new RemoteAccountOrganizationInvitationManageResult(
                status,
                ErrorCode: error,
                Retryable:
                    (int)response.StatusCode == 429 ||
                    response.StatusCode ==
                        HttpStatusCode.ServiceUnavailable);
        }

        var statusValue = RequiredString(root, "status");
        if (statusValue is not ("resent" or "revoked") ||
            !root.TryGetProperty("invitation", out var invitation) ||
            invitation.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException(
                "Organization invitation management response drifted.");
        }

        var invitedEmail = RequiredBoundedString(
            invitation,
            "email",
            320);
        if (!System.Net.Mail.MailAddress.TryCreate(
                invitedEmail,
                out var parsedInvitedEmail) ||
            !string.Equals(
                parsedInvitedEmail.Address,
                invitedEmail,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "Organization invitation management email drifted.");
        }

        var issued = new AccountOrganizationInvitationIssued(
            invitedEmail,
            RequiredRole(invitation, "role"),
            RequiredUppercaseToken(
                invitation,
                "status",
                32),
            RequiredTimestamp(invitation, "expires_at"),
            RequiredTimestamp(invitation, "created_at"));

        var invitationCode = OptionalString(
            root,
            "invitation_code");
        if (statusValue == "resent")
        {
            if (string.IsNullOrWhiteSpace(invitationCode) ||
                invitationCode.Length is < 8 or > 1024 ||
                invitationCode.Any(character => character < 32))
            {
                throw new InvalidDataException(
                    "Organization invitation resend code drifted.");
            }
        }
        else if (invitationCode is not null)
        {
            throw new InvalidDataException(
                "Organization invitation revoke exposed a delivery secret.");
        }

        if (root.TryGetProperty("account_id", out _) ||
            root.TryGetProperty("user_id", out _) ||
            root.TryGetProperty("owner_id", out _) ||
            root.TryGetProperty("invitation_id", out _) ||
            root.TryGetProperty("token_hash", out _) ||
            invitation.TryGetProperty("account_id", out _) ||
            invitation.TryGetProperty("user_id", out _) ||
            invitation.TryGetProperty("owner_id", out _) ||
            invitation.TryGetProperty("id", out _) ||
            invitation.TryGetProperty("token_hash", out _))
        {
            throw new InvalidDataException(
                "Organization invitation management response exposed authority identifiers.");
        }

        return new RemoteAccountOrganizationInvitationManageResult(
            statusValue,
            issued,
            invitationCode);
    }

    public async Task<RemoteAccountOrganizationMemberManageResult>
        ManageMemberAsync(
            string accessToken,
            string action,
            string managementHandle,
            string? role,
            CancellationToken cancellationToken)
    {
        var actionValue = action switch
        {
            "UPDATE_ROLE" => "update_role",
            "REMOVE" => "remove",
            _ => null,
        };
        var handleValid =
            !string.IsNullOrWhiteSpace(managementHandle) &&
            System.Text.RegularExpressions.Regex.IsMatch(
                managementHandle,
                "^bke-org-member-v1_[0-9a-f]{64}$",
                System.Text.RegularExpressions.RegexOptions.CultureInvariant);
        var roleValid =
            action == "UPDATE_ROLE"
                ? role is "OWNER" or "BILLING" or
                    "LICENSE_MANAGER" or "MEMBER"
                : role is null;

        if (string.IsNullOrWhiteSpace(accessToken) ||
            accessToken.Length > 8192 ||
            actionValue is null ||
            !handleValid ||
            !roleValid)
        {
            return new RemoteAccountOrganizationMemberManageResult(
                "invalid_input",
                ErrorCode: "INVALID_INPUT");
        }

        var payload = new Dictionary<string, object?>
        {
            ["action"] = actionValue,
            ["management_handle"] = managementHandle,
        };
        if (action == "UPDATE_ROLE")
        {
            payload["role"] = role;
        }

        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            new Uri(_platformBaseUri, MemberManageEndpoint));
        request.Headers.Accept.Add(
            new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.UserAgent.ParseAdd("bke-licensing-agent");
        request.Headers.Authorization =
            new AuthenticationHeaderValue("Bearer", accessToken);
        request.Headers.TryAddWithoutValidation(
            "x-bke-account-session-version",
            AccountSessionRemote.ProtocolVersion);
        request.Headers.TryAddWithoutValidation(
            "x-request-id",
            Guid.NewGuid().ToString("N"));
        request.Content = new StringContent(
            JsonSerializer.Serialize(payload),
            Encoding.UTF8,
            "application/json");

        // Member role/removal mutations are deliberately single-attempt.
        // Transport ambiguity after Digital Solutions commits must never
        // be converted into an automatic replay.
        using var response = await _http.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);

        if ((int)response.StatusCode is >= 300 and <= 399)
        {
            throw new HttpRequestException(
                "BKE organization member management authority redirected.");
        }

        EnsureProtocol(response);
        using var document = await ReadJsonAsync(
            response,
            cancellationToken);
        var root = document.RootElement;

        if (!response.IsSuccessStatusCode)
        {
            var error = OptionalString(root, "error") ??
                "ORGANIZATION_MEMBER_MANAGEMENT_UNAVAILABLE";

            if (response.StatusCode == HttpStatusCode.Unauthorized &&
                error == "INVALID_TOKEN")
            {
                throw new UnauthorizedAccessException(
                    "BKE organization member management authority rejected the account session.");
            }

            var status = error switch
            {
                "INVALID_INPUT" => "invalid_input",
                "ACCOUNT_NOT_ORGANIZATION" => "not_organization",
                "ACCOUNT_ROLE_FORBIDDEN" => "account_forbidden",
                "MEMBER_NOT_FOUND" => "member_not_found",
                "LAST_OWNER_REQUIRED" => "last_owner_required",
                "CLOSED_ACCOUNT" => "closed_account",
                "SUSPENDED_ACCOUNT" => "suspended_account",
                "RATE_LIMITED" => "rate_limited",
                _ => "management_unavailable",
            };

            return new RemoteAccountOrganizationMemberManageResult(
                status,
                ErrorCode: error,
                Retryable:
                    (int)response.StatusCode == 429 ||
                    response.StatusCode ==
                        HttpStatusCode.ServiceUnavailable);
        }

        var statusValue = RequiredString(root, "status");
        if (statusValue is not ("updated" or "removed") ||
            root.EnumerateObject().Any(
                property => property.Name != "status"))
        {
            throw new InvalidDataException(
                "Organization member management response drifted.");
        }

        return new RemoteAccountOrganizationMemberManageResult(
            statusValue);
    }

    private static bool ValidBounded(
        string? value,
        int minimum,
        int maximum) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Trim().Length >= minimum &&
        value.Trim().Length <= maximum &&
        value.All(character => character >= 32);

    private static bool ValidOptionalBounded(
        string value,
        int maximum) =>
        value.Trim().Length <= maximum &&
        value.All(character => character >= 32);

    private static IReadOnlyList<AccountOrganizationMember> RequiredMembers(
        JsonElement root,
        string name)
    {
        if (!root.TryGetProperty(name, out var value) ||
            value.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException($"Invalid {name}.");
        }

        var items = value.EnumerateArray()
            .Select(item =>
            {
                if (item.ValueKind != JsonValueKind.Object)
                {
                    throw new InvalidDataException(
                        $"Invalid {name} item.");
                }

                return new AccountOrganizationMember(
                    RequiredBoundedString(item, "email", 320),
                    OptionalBoundedString(item, "name", 160),
                    RequiredRole(item, "role"),
                    RequiredMemberManagementHandle(
                        item,
                        "management_handle"));
            })
            .ToArray();

        if (items.Length > 500)
        {
            throw new InvalidDataException(
                "Organization member list is too large.");
        }
        return items;
    }

    private static IReadOnlyList<AccountOrganizationInvitation>
        RequiredInvitations(
            JsonElement root,
            string name)
    {
        if (!root.TryGetProperty(name, out var value) ||
            value.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException($"Invalid {name}.");
        }

        var items = value.EnumerateArray()
            .Select(item =>
            {
                if (item.ValueKind != JsonValueKind.Object)
                {
                    throw new InvalidDataException(
                        $"Invalid {name} item.");
                }

                return new AccountOrganizationInvitation(
                    RequiredBoundedString(item, "email", 320),
                    RequiredRole(item, "role"),
                    RequiredUppercaseToken(item, "status", 32),
                    RequiredTimestamp(item, "expires_at"),
                    RequiredTimestamp(item, "created_at"),
                    RequiredInvitationManagementHandle(
                        item,
                        "management_handle"));
            })
            .ToArray();

        if (items.Length > 500)
        {
            throw new InvalidDataException(
                "Organization invitation list is too large.");
        }
        return items;
    }

    private static JsonElement RequiredObject(
        JsonElement root,
        string name)
    {
        if (!root.TryGetProperty(name, out var value) ||
            value.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException($"Invalid {name}.");
        }
        return value;
    }

    private static string RequiredMemberManagementHandle(
        JsonElement root,
        string name)
    {
        var value = RequiredString(root, name);
        if (!System.Text.RegularExpressions.Regex.IsMatch(
            value,
            "^bke-org-member-v1_[0-9a-f]{64}$",
            System.Text.RegularExpressions.RegexOptions.CultureInvariant))
        {
            throw new InvalidDataException(
                $"Invalid {name}.");
        }
        return value;
    }

    private static string RequiredInvitationManagementHandle(
        JsonElement root,
        string name)
    {
        var value = RequiredString(root, name);
        if (!System.Text.RegularExpressions.Regex.IsMatch(
            value,
            "^bke-org-invite-v1_[0-9a-f]{64}$",
            System.Text.RegularExpressions.RegexOptions.CultureInvariant))
        {
            throw new InvalidDataException(
                $"Invalid {name}.");
        }
        return value;
    }

    private static string RequiredRole(
        JsonElement root,
        string name)
    {
        var value = RequiredString(root, name);
        if (value is not (
            "OWNER" or
            "BILLING" or
            "LICENSE_MANAGER" or
            "MEMBER"))
        {
            throw new InvalidDataException(
                $"Invalid {name}.");
        }
        return value;
    }

    private static bool RequiredBoolean(
        JsonElement root,
        string name)
    {
        if (!root.TryGetProperty(name, out var value) ||
            value.ValueKind is not (
                JsonValueKind.True or
                JsonValueKind.False))
        {
            throw new InvalidDataException(
                $"Invalid {name}.");
        }
        return value.GetBoolean();
    }

    private static int? OptionalNonNegativeInteger(
        JsonElement root,
        string name)
    {
        if (!root.TryGetProperty(name, out var value) ||
            value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }
        if (
            value.ValueKind != JsonValueKind.Number ||
            !value.TryGetInt32(out var parsed) ||
            parsed < 0)
        {
            throw new InvalidDataException(
                $"Invalid {name}.");
        }
        return parsed;
    }

    private static string RequiredTimestamp(
        JsonElement root,
        string name)
    {
        var value = RequiredString(root, name);
        if (!DateTimeOffset.TryParse(value, out _))
        {
            throw new InvalidDataException(
                $"Invalid {name} timestamp.");
        }
        return value;
    }

    private static string RequiredUppercaseToken(
        JsonElement root,
        string name,
        int maximum)
    {
        var value = RequiredString(root, name);
        if (
            value.Length > maximum ||
            value.Any(character =>
                character is not (>= 'A' and <= 'Z') &&
                character != '_'))
        {
            throw new InvalidDataException(
                $"Invalid {name}.");
        }
        return value;
    }

    private static string RequiredBoundedString(
        JsonElement root,
        string name,
        int maximum)
    {
        var value = RequiredString(root, name);
        if (value.Length > maximum)
        {
            throw new InvalidDataException(
                $"Invalid {name} length.");
        }
        return value;
    }

    private static string? OptionalBoundedString(
        JsonElement root,
        string name,
        int maximum)
    {
        var value = OptionalString(root, name);
        if (value is null)
        {
            return null;
        }
        if (value.Length > maximum)
        {
            throw new InvalidDataException(
                $"Invalid {name} length.");
        }
        return value;
    }

    private static string RequiredString(
        JsonElement root,
        string name)
    {
        if (
            !root.TryGetProperty(name, out var value) ||
            value.ValueKind != JsonValueKind.String ||
            string.IsNullOrWhiteSpace(value.GetString()))
        {
            throw new InvalidDataException(
                $"Missing or invalid {name}.");
        }
        return value.GetString()!;
    }

    private static string? OptionalString(
        JsonElement root,
        string name)
    {
        if (
            !root.TryGetProperty(name, out var value) ||
            value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }
        if (value.ValueKind != JsonValueKind.String)
        {
            throw new InvalidDataException(
                $"Invalid {name}.");
        }
        return value.GetString();
    }

    private static void EnsureProtocol(
        HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues(
            "x-bke-account-session-version",
            out var values))
        {
            throw new InvalidDataException(
                "Organization response is missing its protocol version.");
        }

        var versions = values.ToArray();
        if (
            versions.Length != 1 ||
            versions[0] != AccountSessionRemote.ProtocolVersion)
        {
            throw new InvalidDataException(
                "Organization protocol version drifted.");
        }
    }

    private static async Task<JsonDocument> ReadJsonAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        await using var stream =
            await response.Content.ReadAsStreamAsync(
                cancellationToken);
        return await JsonDocument.ParseAsync(
            stream,
            cancellationToken: cancellationToken);
    }

    public void Dispose()
    {
        if (_ownsHttpClient)
        {
            _http.Dispose();
        }
    }
}
