using System.Net;
using System.Text;
using BKE.LicensingAgent.Application;
using BKE.LicensingAgent.Contracts;
using BKE.LicensingAgent.Infrastructure;

static class AccountOrganizationCertification
{
    public static async Task RunAsync()
    {
        CertifyStaticBoundaries();
        await CertifyServiceBoundaryAsync();
        await CertifyRemoteTransportAsync();
    }

    private static void CertifyStaticBoundaries()
    {
        Require(
            LocalAgentContract.AccountOrganizationCapabilityId ==
                "bke.account-organization" &&
            LocalAgentContract.AccountOrganizationContractVersion == 1 &&
            LocalAgentContract.AccountOrganizationOverviewPath ==
                "/v1/account/organization" &&
            LocalAgentContract.AccountOrganizationCreatePath ==
                "/v1/account/organization/create" &&
            LocalAgentContract.AccountOrganizationProfileUpdatePath ==
                "/v1/account/organization/profile" &&
            LocalAgentContract.AccountOrganizationInvitationCreatePath ==
                "/v1/account/organization/invitations/create" &&
            LocalAgentContract.AccountOrganizationInvitationManagePath ==
                "/v1/account/organization/invitations/manage" &&
            LocalAgentContract.AccountOrganizationMemberManagePath ==
                "/v1/account/organization/members/manage" &&
            LocalAgentContract.AccountOrganizationOwnershipTransferPath ==
                "/v1/account/organization/ownership/transfer" &&
            LocalAgentContract.AccountOrganizationLeavePath ==
                "/v1/account/organization/leave",
            "account organization contract drifted");

        Require(
            typeof(AccountOrganizationOverviewRequest)
                .GetProperties()
                .Select(property => property.Name)
                .SequenceEqual(["CorrelationId"]),
            "account organization request widened");
        Require(
            typeof(AccountOrganizationCreateRequest)
                .GetProperties()
                .Select(property => property.Name)
                .SequenceEqual([
                    "CorrelationId",
                    "DisplayName",
                    "LegalName",
                    "BillingEmail",
                    "RegistrationNumber",
                    "TaxId"
                ]),
            "account organization create request drifted");
        Require(
            typeof(AccountOrganizationProfileUpdateRequest)
                .GetProperties()
                .Select(property => property.Name)
                .SequenceEqual([
                    "CorrelationId",
                    "UpdateOrganizationProfile",
                    "DisplayName",
                    "LegalName",
                    "RegistrationNumber",
                    "UpdateBillingProfile",
                    "BillingEmail",
                    "TaxId"
                ]),
            "account organization profile update request drifted");
        Require(
            typeof(AccountOrganizationInvitationCreateRequest)
                .GetProperties()
                .Select(property => property.Name)
                .SequenceEqual([
                    "CorrelationId",
                    "Email",
                    "Role"
                ]),
            "account organization invitation request widened");
        Require(
            typeof(AccountOrganizationInvitationManageRequest)
                .GetProperties()
                .Select(property => property.Name)
                .SequenceEqual([
                    "CorrelationId",
                    "Action",
                    "ManagementHandle"
                ]),
            "account organization invitation management request widened");
        Require(
            typeof(AccountOrganizationMemberManageRequest)
                .GetProperties()
                .Select(property => property.Name)
                .SequenceEqual([
                    "CorrelationId",
                    "Action",
                    "ManagementHandle",
                    "Role"
                ]),
            "account organization member management request widened");
        Require(
            typeof(AccountOrganizationOwnershipTransferRequest)
                .GetProperties()
                .Select(property => property.Name)
                .SequenceEqual([
                    "CorrelationId",
                    "ManagementHandle"
                ]),
            "account organization ownership transfer request widened");
        Require(
            typeof(AccountOrganizationLeaveRequest)
                .GetProperties()
                .Select(property => property.Name)
                .SequenceEqual(["CorrelationId"]),
            "account organization leave request widened");

        foreach (var type in new[]
        {
            typeof(AccountOrganizationOverviewResponse),
            typeof(AccountOrganizationCreateResponse),
            typeof(AccountOrganizationProfileUpdateResponse),
            typeof(AccountOrganizationInvitationCreateResponse),
            typeof(AccountOrganizationInvitationManageResponse),
            typeof(AccountOrganizationMemberManageResponse),
            typeof(AccountOrganizationOwnershipTransferResponse),
            typeof(AccountOrganizationLeaveResponse),
            typeof(AccountOrganizationInvitationIssued),
            typeof(AccountOrganizationAccount),
            typeof(AccountOrganizationMember),
            typeof(AccountOrganizationInvitation),
        })
        {
            Require(
                type.GetProperties().All(property =>
                    !property.Name.Contains(
                        "AccessToken",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Contains(
                        "RefreshToken",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Contains(
                        "Handoff",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Equals(
                        "AccountId",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Equals(
                        "UserId",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Equals(
                        "InvitationId",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Equals(
                        "MemberId",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Equals(
                        "MembershipId",
                        StringComparison.OrdinalIgnoreCase) &&
                    !property.Name.Equals(
                        "OwnerId",
                        StringComparison.OrdinalIgnoreCase)),
                $"account organization response {type.Name} exposes authority/mutation identifiers");
        }

        var host = File.ReadAllText(
            Path.Combine(
                "dotnet",
                "src",
                "BKE.LicensingAgent.Host",
                "Program.cs"));
        var remote = File.ReadAllText(
            Path.Combine(
                "dotnet",
                "src",
                "BKE.LicensingAgent.Infrastructure",
                "AccountOrganizationRemote.cs"));
        var service = File.ReadAllText(
            Path.Combine(
                "dotnet",
                "src",
                "BKE.LicensingAgent.Application",
                "AccountOrganizationService.cs"));

        Require(
            host.Contains(
                "app.MapPost(LocalAgentContract.AccountOrganizationOverviewPath",
                StringComparison.Ordinal) &&
            host.Contains(
                "AddSingleton<IAccountOrganizationService>",
                StringComparison.Ordinal) &&
            host.Contains(
                "app.MapPost(LocalAgentContract.AccountOrganizationCreatePath",
                StringComparison.Ordinal) &&
            host.Contains(
                "app.MapPost(LocalAgentContract.AccountOrganizationProfileUpdatePath",
                StringComparison.Ordinal) &&
            host.Contains(
                "app.MapPost(LocalAgentContract.AccountOrganizationInvitationCreatePath",
                StringComparison.Ordinal) &&
            host.Contains(
                "app.MapPost(LocalAgentContract.AccountOrganizationInvitationManagePath",
                StringComparison.Ordinal) &&
            host.Contains(
                "app.MapPost(LocalAgentContract.AccountOrganizationMemberManagePath",
                StringComparison.Ordinal) &&
            host.Contains(
                "app.MapPost(LocalAgentContract.AccountOrganizationOwnershipTransferPath",
                StringComparison.Ordinal) &&
            host.Contains(
                "app.MapPost(LocalAgentContract.AccountOrganizationLeavePath",
                StringComparison.Ordinal),
            "Agent organization Host wiring drifted");

        Require(
            remote.Contains(
                "/api/agent-sessions/account/organization",
                StringComparison.Ordinal) &&
            remote.Contains(
                "new AuthenticationHeaderValue(\"Bearer\", accessToken)",
                StringComparison.Ordinal) &&
            remote.Contains(
                "\"x-bke-account-session-version\"",
                StringComparison.Ordinal) &&
            remote.Contains(
                "AllowAutoRedirect = false",
                StringComparison.Ordinal) &&
            remote.Contains(
                "/api/agent-sessions/account/organization/create",
                StringComparison.Ordinal) &&
            remote.Contains(
                "/api/agent-sessions/account/organization/profile",
                StringComparison.Ordinal) &&
            remote.Contains(
                "/api/agent-sessions/account/organization/invitations/create",
                StringComparison.Ordinal) &&
            remote.Contains(
                "/api/agent-sessions/account/organization/invitations/manage",
                StringComparison.Ordinal) &&
            remote.Contains(
                "/api/agent-sessions/account/organization/members/manage",
                StringComparison.Ordinal) &&
            remote.Contains(
                "/api/agent-sessions/account/organization/ownership/transfer",
                StringComparison.Ordinal) &&
            remote.Contains(
                "/api/agent-sessions/account/organization/leave",
                StringComparison.Ordinal) &&
            remote.Contains(
                "Ownership transfer is deliberately single-attempt",
                StringComparison.Ordinal) &&
            remote.Contains(
                "Organization self-leave is deliberately single-attempt",
                StringComparison.Ordinal) &&
            remote.Contains(
                "Member role/removal mutations are deliberately single-attempt",
                StringComparison.Ordinal) &&
            remote.Contains(
                "Resend/revoke are deliberately single-attempt",
                StringComparison.Ordinal) &&
            remote.Contains(
                "HttpMethod.Patch",
                StringComparison.Ordinal) &&
            remote.Contains(
                "Invitation issuance is deliberately single-attempt",
                StringComparison.Ordinal) &&
            remote.Contains(
                "single-attempt",
                StringComparison.Ordinal) &&
            service.Contains(
                "\"OUTCOME_UNKNOWN\"",
                StringComparison.Ordinal),
            "Agent organization bearer/protocol/redirect mediation drifted");

        Require(
            !remote.Contains("Console.", StringComparison.Ordinal) &&
            !service.Contains("Console.", StringComparison.Ordinal) &&
            !service.Contains("AgentDatabase", StringComparison.Ordinal) &&
            !service.Contains("File.", StringComparison.Ordinal),
            "Agent organization overview introduced local persistence/logging");
    }

    private static async Task CertifyServiceBoundaryAsync()
    {
        var account = new AccountSessionAccount(
            "org-user",
            "org@example.test",
            "org-account",
            "ORGANIZATION",
            "Certification Organization");
        var store = OrganizationStore.Active(account);

        var ready = new RemoteAccountOrganizationResult(
            "ready",
            Account: new AccountOrganizationAccount(
                "Certification Organization",
                "ACTIVE",
                "OWNER"),
            Permissions: new AccountOrganizationPermissions(
                true,
                true,
                false,
                true,
                true),
            Organization: new AccountOrganizationProfile(
                "Certification Organization Legal",
                "REG-001"),
            BillingEmail: "billing@example.test",
            TaxId: "TAX-001",
            Counts: new AccountOrganizationCounts(2, 1, 3),
            Members: [
                new AccountOrganizationMember(
                    "owner@example.test",
                    "Owner",
                    "OWNER",
                    "bke-org-member-v1_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
            ],
            Invitations: [
                new AccountOrganizationInvitation(
                    "invitee@example.test",
                    "MEMBER",
                    "PENDING",
                    "2026-10-01T12:00:00.000Z",
                    "2026-09-29T12:00:00.000Z",
                    "bke-org-invite-v1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            ]);

        var remote = new FakeOrganizationRemote(ready);
        var service = new AccountOrganizationService(
            new OrganizationAuthenticatedSessionService(account),
            store,
            remote);

        var result = await service.GetAsync(
            new AccountOrganizationOverviewRequest(
                "organization-overview-cert"),
            CancellationToken.None);

        Require(
            result.Status == "READY" &&
            result.Account?.Role == "OWNER" &&
            result.Permissions?.TransferOwnership == true &&
            result.Permissions?.LeaveOrganization == false &&
            result.Members.Count == 1 &&
            result.Members[0].ManagementHandle ==
                "bke-org-member-v1_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" &&
            result.Invitations.Count == 1 &&
            result.Invitations[0].ManagementHandle ==
                "bke-org-invite-v1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &&
            remote.Calls == 1 &&
            remote.LastAccessToken == "organization-access-secret",
            "Agent organization overview did not use session custody correctly");

        var wire = System.Text.Json.JsonSerializer.Serialize(result);
        Require(
            !wire.Contains(
                "organization-access-secret",
                StringComparison.Ordinal) &&
            !wire.Contains(
                "organization-refresh-secret",
                StringComparison.Ordinal) &&
            !wire.Contains(
                "org-account",
                StringComparison.Ordinal),
            "Agent organization response leaked cloud/session account identifiers");

        var createResult = await service.CreateAsync(
            new AccountOrganizationCreateRequest(
                "organization-create-cert",
                "Created Organization",
                "Created Organization Legal",
                "billing-created@example.test",
                "REG-CREATE",
                "TAX-CREATE"),
            CancellationToken.None);
        Require(
            createResult.Status == "CREATED" &&
            createResult.DisplayName == "Created Organization" &&
            createResult.SwitchRequired &&
            remote.CreateCalls == 1 &&
            remote.LastAccessToken == "organization-access-secret",
            "Agent organization creation did not use session custody correctly");
        var createWire =
            System.Text.Json.JsonSerializer.Serialize(createResult);
        Require(
            !createWire.Contains(
                "organization-access-secret",
                StringComparison.Ordinal) &&
            !createWire.Contains(
                "organization-refresh-secret",
                StringComparison.Ordinal) &&
            !createWire.Contains(
                "org-account",
                StringComparison.Ordinal),
            "Agent organization create response leaked session/account identifiers");

        var profileResult = await service.UpdateProfileAsync(
            new AccountOrganizationProfileUpdateRequest(
                "organization-profile-cert",
                true,
                "Updated Organization",
                "Updated Organization Legal",
                null,
                true,
                "billing-updated@example.test",
                null),
            CancellationToken.None);
        Require(
            profileResult.Status == "UPDATED" &&
            profileResult.Error is null &&
            remote.ProfileUpdateCalls == 1 &&
            remote.LastAccessToken == "organization-access-secret" &&
            remote.LastUpdateOrganizationProfile &&
            remote.LastUpdateBillingProfile &&
            remote.LastRegistrationNumber is null &&
            remote.LastTaxId is null,
            "Agent organization profile update did not preserve field groups or session custody");
        var profileWire =
            System.Text.Json.JsonSerializer.Serialize(profileResult);
        Require(
            !profileWire.Contains(
                "organization-access-secret",
                StringComparison.Ordinal) &&
            !profileWire.Contains(
                "organization-refresh-secret",
                StringComparison.Ordinal) &&
            !profileWire.Contains(
                "org-account",
                StringComparison.Ordinal),
            "Agent organization profile update response leaked session/account identifiers");

        var invitationResult = await service.CreateInvitationAsync(
            new AccountOrganizationInvitationCreateRequest(
                "organization-invitation-cert",
                "new-member@example.test",
                "MEMBER"),
            CancellationToken.None);
        Require(
            invitationResult.Status == "CREATED" &&
            invitationResult.Invitation?.Email ==
                "new-member@example.test" &&
            invitationResult.Invitation?.Role == "MEMBER" &&
            invitationResult.InvitationCode ==
                "organization-invitation-code-cert" &&
            remote.InvitationCreateCalls == 1 &&
            remote.LastAccessToken == "organization-access-secret" &&
            remote.LastInvitationEmail ==
                "new-member@example.test" &&
            remote.LastInvitationRole == "MEMBER",
            "Agent organization invitation did not preserve session custody or transient delivery state");
        var invitationWire =
            System.Text.Json.JsonSerializer.Serialize(invitationResult);
        Require(
            invitationWire.Contains(
                "organization-invitation-code-cert",
                StringComparison.Ordinal) &&
            !invitationWire.Contains(
                "organization-access-secret",
                StringComparison.Ordinal) &&
            !invitationWire.Contains(
                "organization-refresh-secret",
                StringComparison.Ordinal) &&
            !invitationWire.Contains(
                "org-account",
                StringComparison.Ordinal) &&
            !invitationWire.Contains(
                "invitation-id",
                StringComparison.OrdinalIgnoreCase) &&
            !invitationWire.Contains(
                "token-hash",
                StringComparison.OrdinalIgnoreCase),
            "Agent organization invitation leaked session/authority identifiers or lost its one-time delivery secret");

        var resendResult = await service.ManageInvitationAsync(
            new AccountOrganizationInvitationManageRequest(
                "organization-invitation-resend-cert",
                "RESEND",
                "bke-org-invite-v1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            CancellationToken.None);
        Require(
            resendResult.Status == "RESENT" &&
            resendResult.Invitation?.Email ==
                "invitee@example.test" &&
            resendResult.InvitationCode ==
                "organization-invitation-resend-code-cert" &&
            remote.InvitationManageCalls == 1 &&
            remote.LastInvitationManageAction == "RESEND" &&
            remote.LastInvitationManagementHandle ==
                "bke-org-invite-v1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Agent invitation resend did not preserve opaque-handle/session boundaries");

        var revokeResult = await service.ManageInvitationAsync(
            new AccountOrganizationInvitationManageRequest(
                "organization-invitation-revoke-cert",
                "REVOKE",
                "bke-org-invite-v1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            CancellationToken.None);
        Require(
            revokeResult.Status == "REVOKED" &&
            revokeResult.Invitation?.Status == "REVOKED" &&
            revokeResult.InvitationCode is null &&
            remote.InvitationManageCalls == 2 &&
            remote.LastInvitationManageAction == "REVOKE",
            "Agent invitation revoke exposed a delivery secret or lost mutation intent");

        var roleUpdateResult = await service.ManageMemberAsync(
            new AccountOrganizationMemberManageRequest(
                "organization-member-role-cert",
                "UPDATE_ROLE",
                "bke-org-member-v1_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "BILLING"),
            CancellationToken.None);
        Require(
            roleUpdateResult.Status == "UPDATED" &&
            roleUpdateResult.Error is null &&
            remote.MemberManageCalls == 1 &&
            remote.LastMemberManageAction == "UPDATE_ROLE" &&
            remote.LastMemberManagementHandle ==
                "bke-org-member-v1_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" &&
            remote.LastMemberManageRole == "BILLING" &&
            remote.LastAccessToken == "organization-access-secret",
            "Agent member role update did not preserve opaque-handle/session boundaries");

        var removeMemberResult = await service.ManageMemberAsync(
            new AccountOrganizationMemberManageRequest(
                "organization-member-remove-cert",
                "REMOVE",
                "bke-org-member-v1_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                null),
            CancellationToken.None);
        Require(
            removeMemberResult.Status == "REMOVED" &&
            removeMemberResult.Error is null &&
            remote.MemberManageCalls == 2 &&
            remote.LastMemberManageAction == "REMOVE" &&
            remote.LastMemberManageRole is null,
            "Agent member removal widened mutation intent or lost session custody");

        var lastOwnerStore = OrganizationStore.Active(account);
        var lastOwner = new AccountOrganizationService(
            new OrganizationAuthenticatedSessionService(account),
            lastOwnerStore,
            new FakeOrganizationRemote(
                ready,
                memberManageResult:
                    new RemoteAccountOrganizationMemberManageResult(
                        "last_owner_required",
                        ErrorCode: "LAST_OWNER_REQUIRED")));
        var lastOwnerResult = await lastOwner.ManageMemberAsync(
            new AccountOrganizationMemberManageRequest(
                "organization-member-owner-cert",
                "UPDATE_ROLE",
                "bke-org-member-v1_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "MEMBER"),
            CancellationToken.None);
        Require(
            lastOwnerResult.Status == "LAST_OWNER_REQUIRED" &&
            lastOwnerResult.Error?.Code == "LAST_OWNER_REQUIRED" &&
            lastOwnerStore.State is ActiveAccountSessionState,
            "Agent member management weakened last-owner protection or destroyed valid session custody");


        var transferStore = OrganizationStore.Active(account);
        var transferRemote = new FakeOrganizationRemote(
            ready,
            ownershipTransferResult:
                new RemoteAccountOrganizationOwnershipTransferResult(
                    "transferred",
                    ReauthenticationRequired: true));
        var transfer = new AccountOrganizationService(
            new OrganizationAuthenticatedSessionService(account),
            transferStore,
            transferRemote);
        var transferResult = await transfer.TransferOwnershipAsync(
            new AccountOrganizationOwnershipTransferRequest(
                "organization-owner-transfer-cert",
                "bke-org-member-v1_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
            CancellationToken.None);
        Require(
            transferResult.Status == "TRANSFERRED" &&
            transferResult.ReauthenticationRequired &&
            transferResult.Error is null &&
            transferRemote.OwnershipTransferCalls == 1 &&
            transferRemote.LastOwnershipTransferHandle ==
                "bke-org-member-v1_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" &&
            transferRemote.LastAccessToken ==
                "organization-access-secret" &&
            transferStore.State is null,
            "Agent ownership transfer did not clear selected-account custody after authoritative transfer");

        var missingTransferStore = OrganizationStore.Active(account);
        var missingTransfer = new AccountOrganizationService(
            new OrganizationAuthenticatedSessionService(account),
            missingTransferStore,
            new FakeOrganizationRemote(
                ready,
                ownershipTransferResult:
                    new RemoteAccountOrganizationOwnershipTransferResult(
                        "member_not_found",
                        ErrorCode: "MEMBER_NOT_FOUND")));
        var missingTransferResult =
            await missingTransfer.TransferOwnershipAsync(
                new AccountOrganizationOwnershipTransferRequest(
                    "organization-owner-transfer-missing-cert",
                    "bke-org-member-v1_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
                CancellationToken.None);
        Require(
            missingTransferResult.Status == "MEMBER_NOT_FOUND" &&
            !missingTransferResult.ReauthenticationRequired &&
            missingTransferResult.Error?.Code == "MEMBER_NOT_FOUND" &&
            missingTransferStore.State is ActiveAccountSessionState,
            "Explicit invalid ownership target destroyed otherwise-valid selected-account custody");

        var ambiguousTransferStore = OrganizationStore.Active(account);
        var ambiguousTransfer = new AccountOrganizationService(
            new OrganizationAuthenticatedSessionService(account),
            ambiguousTransferStore,
            new ThrowingOrganizationRemote(
                new HttpRequestException(
                    "certified ownership transfer ambiguity")));
        var ambiguousTransferResult =
            await ambiguousTransfer.TransferOwnershipAsync(
                new AccountOrganizationOwnershipTransferRequest(
                    "organization-owner-transfer-unknown-cert",
                    "bke-org-member-v1_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
                CancellationToken.None);
        Require(
            ambiguousTransferResult.Status == "OUTCOME_UNKNOWN" &&
            ambiguousTransferResult.ReauthenticationRequired &&
            ambiguousTransferResult.Error?.Code ==
                "ORGANIZATION_OWNERSHIP_TRANSFER_OUTCOME_UNKNOWN" &&
            ambiguousTransferStore.State is null,
            "Ambiguous ownership transfer remained replayable or retained stale selected-account custody");


        var leaveStore = OrganizationStore.Active(account);
        var leaveRemote = new FakeOrganizationRemote(
            ready,
            leaveResult:
                new RemoteAccountOrganizationLeaveResult(
                    "left",
                    ReauthenticationRequired: true));
        var leave = new AccountOrganizationService(
            new OrganizationAuthenticatedSessionService(account),
            leaveStore,
            leaveRemote);
        var leaveResult = await leave.LeaveAsync(
            new AccountOrganizationLeaveRequest(
                "organization-leave-cert"),
            CancellationToken.None);
        Require(
            leaveResult.Status == "LEFT" &&
            leaveResult.ReauthenticationRequired &&
            leaveResult.Error is null &&
            leaveRemote.LeaveCalls == 1 &&
            leaveRemote.LastAccessToken ==
                "organization-access-secret" &&
            leaveStore.State is null,
            "Agent organization leave did not clear selected-account session custody");

        var ownerLeaveStore = OrganizationStore.Active(account);
        var ownerLeave = new AccountOrganizationService(
            new OrganizationAuthenticatedSessionService(account),
            ownerLeaveStore,
            new FakeOrganizationRemote(
                ready,
                leaveResult:
                    new RemoteAccountOrganizationLeaveResult(
                        "owner_cannot_leave",
                        ErrorCode: "OWNER_CANNOT_LEAVE")));
        var ownerLeaveResult = await ownerLeave.LeaveAsync(
            new AccountOrganizationLeaveRequest(
                "organization-owner-leave-cert"),
            CancellationToken.None);
        Require(
            ownerLeaveResult.Status == "OWNER_CANNOT_LEAVE" &&
            !ownerLeaveResult.ReauthenticationRequired &&
            ownerLeaveResult.Error?.Code ==
                "OWNER_CANNOT_LEAVE" &&
            ownerLeaveStore.State is ActiveAccountSessionState,
            "Agent organization owner-leave denial destroyed valid session custody");

        var missingLeaveStore = OrganizationStore.Active(account);
        var missingLeave = new AccountOrganizationService(
            new OrganizationAuthenticatedSessionService(account),
            missingLeaveStore,
            new FakeOrganizationRemote(
                ready,
                leaveResult:
                    new RemoteAccountOrganizationLeaveResult(
                        "member_not_found",
                        ErrorCode: "MEMBER_NOT_FOUND")));
        var missingLeaveResult = await missingLeave.LeaveAsync(
            new AccountOrganizationLeaveRequest(
                "organization-missing-leave-cert"),
            CancellationToken.None);
        Require(
            missingLeaveResult.Status == "MEMBER_NOT_FOUND" &&
            missingLeaveResult.ReauthenticationRequired &&
            missingLeaveResult.Error?.Code == "MEMBER_NOT_FOUND" &&
            missingLeaveStore.State is null,
            "Agent stale organization membership did not clear selected-account session custody");

        var personal = new AccountOrganizationService(
            new OrganizationAuthenticatedSessionService(account),
            OrganizationStore.Active(account),
            new FakeOrganizationRemote(
                new RemoteAccountOrganizationResult(
                    "not_organization")));
        var personalResult = await personal.GetAsync(
            new AccountOrganizationOverviewRequest(
                "organization-personal-cert"),
            CancellationToken.None);
        Require(
            personalResult.Status == "NOT_ORGANIZATION" &&
            personalResult.Account is null &&
            personalResult.Members.Count == 0,
            "Agent organization overview did not preserve personal-account no-op semantics");

        var invalidStore = OrganizationStore.Active(account);
        var invalid = new AccountOrganizationService(
            new OrganizationAuthenticatedSessionService(account),
            invalidStore,
            new ThrowingOrganizationRemote(
                new UnauthorizedAccessException(
                    "certified selected account rejection")));
        var invalidResult = await invalid.GetAsync(
            new AccountOrganizationOverviewRequest(
                "organization-invalid-cert"),
            CancellationToken.None);
        Require(
            invalidResult.Status == "AUTH_REQUIRED" &&
            invalidStore.State is null,
            "Agent organization selected-account rejection did not clear session custody");

        var outageStore = OrganizationStore.Active(account);
        var outage = new AccountOrganizationService(
            new OrganizationAuthenticatedSessionService(account),
            outageStore,
            new ThrowingOrganizationRemote(
                new HttpRequestException(
                    "certified organization outage")));
        var outageResult = await outage.GetAsync(
            new AccountOrganizationOverviewRequest(
                "organization-outage-cert"),
            CancellationToken.None);
        Require(
            outageResult.Status == "FAILED" &&
            outageStore.State is ActiveAccountSessionState,
            "read-only organization failure destroyed a valid Agent session");

        var createUnknownStore = OrganizationStore.Active(account);
        var createUnknown = new AccountOrganizationService(
            new OrganizationAuthenticatedSessionService(account),
            createUnknownStore,
            new ThrowingOrganizationRemote(
                new HttpRequestException(
                    "certified organization create ambiguity")));
        var createUnknownResult = await createUnknown.CreateAsync(
            new AccountOrganizationCreateRequest(
                "organization-create-unknown-cert",
                "Unknown Organization",
                "Unknown Organization Legal",
                "unknown@example.test",
                null,
                null),
            CancellationToken.None);
        Require(
            createUnknownResult.Status == "OUTCOME_UNKNOWN" &&
            createUnknownStore.State is ActiveAccountSessionState &&
            createUnknownResult.Error?.Retryable == false,
            "Agent organization create ambiguity was replayable or destroyed session custody");

        var profileDeniedStore = OrganizationStore.Active(account);
        var profileDenied = new AccountOrganizationService(
            new OrganizationAuthenticatedSessionService(account),
            profileDeniedStore,
            new FakeOrganizationRemote(
                ready,
                profileResult:
                    new RemoteAccountOrganizationProfileUpdateResult(
                        "account_forbidden",
                        "ACCOUNT_ROLE_FORBIDDEN")));
        var profileDeniedResult = await profileDenied.UpdateProfileAsync(
            new AccountOrganizationProfileUpdateRequest(
                "organization-profile-denied-cert",
                false,
                null,
                null,
                null,
                true,
                "billing-denied@example.test",
                null),
            CancellationToken.None);
        Require(
            profileDeniedResult.Status == "ACCOUNT_FORBIDDEN" &&
            profileDeniedStore.State is ActiveAccountSessionState,
            "Agent organization profile role denial destroyed valid session custody");

        var profileUnknownStore = OrganizationStore.Active(account);
        var profileUnknown = new AccountOrganizationService(
            new OrganizationAuthenticatedSessionService(account),
            profileUnknownStore,
            new ThrowingOrganizationRemote(
                new HttpRequestException(
                    "certified organization profile ambiguity")));
        var profileUnknownResult = await profileUnknown.UpdateProfileAsync(
            new AccountOrganizationProfileUpdateRequest(
                "organization-profile-unknown-cert",
                true,
                "Ambiguous Organization",
                "Ambiguous Organization Legal",
                "REG-AMBIGUOUS",
                false,
                null,
                null),
            CancellationToken.None);
        Require(
            profileUnknownResult.Status == "OUTCOME_UNKNOWN" &&
            profileUnknownStore.State is ActiveAccountSessionState &&
            profileUnknownResult.Error?.Retryable == false,
            "Agent organization profile ambiguity was replayable or destroyed session custody");

        var invitationDeniedStore = OrganizationStore.Active(account);
        var invitationDenied = new AccountOrganizationService(
            new OrganizationAuthenticatedSessionService(account),
            invitationDeniedStore,
            new FakeOrganizationRemote(
                ready,
                invitationResult:
                    new RemoteAccountOrganizationInvitationCreateResult(
                        "account_forbidden",
                        ErrorCode: "ACCOUNT_ROLE_FORBIDDEN")));
        var invitationDeniedResult =
            await invitationDenied.CreateInvitationAsync(
                new AccountOrganizationInvitationCreateRequest(
                    "organization-invitation-denied-cert",
                    "denied@example.test",
                    "MEMBER"),
                CancellationToken.None);
        Require(
            invitationDeniedResult.Status == "ACCOUNT_FORBIDDEN" &&
            invitationDeniedResult.InvitationCode is null &&
            invitationDeniedStore.State is ActiveAccountSessionState,
            "Agent organization invitation role denial leaked a code or destroyed valid session custody");

        var invitationUnknownStore = OrganizationStore.Active(account);
        var invitationUnknown = new AccountOrganizationService(
            new OrganizationAuthenticatedSessionService(account),
            invitationUnknownStore,
            new ThrowingOrganizationRemote(
                new HttpRequestException(
                    "certified organization invitation ambiguity")));
        var invitationUnknownResult =
            await invitationUnknown.CreateInvitationAsync(
                new AccountOrganizationInvitationCreateRequest(
                    "organization-invitation-unknown-cert",
                    "ambiguous@example.test",
                    "MEMBER"),
                CancellationToken.None);
        Require(
            invitationUnknownResult.Status == "OUTCOME_UNKNOWN" &&
            invitationUnknownResult.InvitationCode is null &&
            invitationUnknownResult.Error?.Retryable == false &&
            invitationUnknownStore.State is ActiveAccountSessionState,
            "Agent organization invitation ambiguity became replayable, leaked a code, or destroyed session custody");

        var invitationInvalidStore = OrganizationStore.Active(account);
        var invitationInvalid = new AccountOrganizationService(
            new OrganizationAuthenticatedSessionService(account),
            invitationInvalidStore,
            new ThrowingOrganizationRemote(
                new UnauthorizedAccessException(
                    "certified organization invitation session rejection")));
        var invitationInvalidResult =
            await invitationInvalid.CreateInvitationAsync(
                new AccountOrganizationInvitationCreateRequest(
                    "organization-invitation-invalid-cert",
                    "invalid@example.test",
                    "MEMBER"),
                CancellationToken.None);
        Require(
            invitationInvalidResult.Status == "AUTH_REQUIRED" &&
            invitationInvalidStore.State is null,
            "Agent organization invitation invalid token did not clear session custody");

        var manageUnknownStore = OrganizationStore.Active(account);
        var manageUnknown = new AccountOrganizationService(
            new OrganizationAuthenticatedSessionService(account),
            manageUnknownStore,
            new ThrowingOrganizationRemote(
                new HttpRequestException(
                    "certified invitation-management ambiguity")));
        var manageUnknownResult =
            await manageUnknown.ManageInvitationAsync(
                new AccountOrganizationInvitationManageRequest(
                    "organization-invitation-manage-unknown-cert",
                    "RESEND",
                    "bke-org-invite-v1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                CancellationToken.None);
        Require(
            manageUnknownResult.Status == "OUTCOME_UNKNOWN" &&
            manageUnknownResult.InvitationCode is null &&
            manageUnknownResult.Error?.Retryable == false &&
            manageUnknownStore.State is ActiveAccountSessionState,
            "Agent invitation management ambiguity became replayable or destroyed session custody");

        var memberManageUnknownStore =
            OrganizationStore.Active(account);
        var memberManageUnknown =
            new AccountOrganizationService(
                new OrganizationAuthenticatedSessionService(account),
                memberManageUnknownStore,
                new ThrowingOrganizationRemote(
                    new HttpRequestException(
                        "certified member-management ambiguity")));
        var memberManageUnknownResult =
            await memberManageUnknown.ManageMemberAsync(
                new AccountOrganizationMemberManageRequest(
                    "organization-member-manage-unknown-cert",
                    "REMOVE",
                    "bke-org-member-v1_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                    null),
                CancellationToken.None);
        Require(
            memberManageUnknownResult.Status == "OUTCOME_UNKNOWN" &&
            memberManageUnknownResult.Error?.Retryable == false &&
            memberManageUnknownStore.State is ActiveAccountSessionState,
            "Agent member-management ambiguity became replayable or destroyed session custody");


        var leaveUnknownStore = OrganizationStore.Active(account);
        var leaveUnknown = new AccountOrganizationService(
            new OrganizationAuthenticatedSessionService(account),
            leaveUnknownStore,
            new ThrowingOrganizationRemote(
                new HttpRequestException(
                    "certified organization leave ambiguity")));
        var leaveUnknownResult = await leaveUnknown.LeaveAsync(
            new AccountOrganizationLeaveRequest(
                "organization-leave-unknown-cert"),
            CancellationToken.None);
        Require(
            leaveUnknownResult.Status == "OUTCOME_UNKNOWN" &&
            leaveUnknownResult.ReauthenticationRequired &&
            leaveUnknownResult.Error?.Retryable == false &&
            leaveUnknownStore.State is null,
            "Agent organization leave ambiguity remained replayable or retained unsafe selected-account custody");

        var signedOutRemote = new FakeOrganizationRemote(ready);
        var signedOut = new AccountOrganizationService(
            new OrganizationSignedOutSessionService(),
            OrganizationStore.Active(account),
            signedOutRemote);
        var signedOutResult = await signedOut.GetAsync(
            new AccountOrganizationOverviewRequest(
                "organization-auth-cert"),
            CancellationToken.None);
        Require(
            signedOutResult.Status == "AUTH_REQUIRED" &&
            signedOutRemote.Calls == 0,
            "Agent organization authority was called without authenticated session custody");

        var signedOutProfile = await signedOut.UpdateProfileAsync(
            new AccountOrganizationProfileUpdateRequest(
                "organization-profile-auth-cert",
                true,
                "Signed Out Organization",
                "Signed Out Organization Legal",
                null,
                false,
                null,
                null),
            CancellationToken.None);
        Require(
            signedOutProfile.Status == "AUTH_REQUIRED" &&
            signedOutRemote.ProfileUpdateCalls == 0,
            "Agent organization profile authority was called without authenticated session custody");

        var signedOutInvitation =
            await signedOut.CreateInvitationAsync(
                new AccountOrganizationInvitationCreateRequest(
                    "organization-invitation-auth-cert",
                    "signed-out@example.test",
                    "MEMBER"),
                CancellationToken.None);
        Require(
            signedOutInvitation.Status == "AUTH_REQUIRED" &&
            signedOutInvitation.InvitationCode is null &&
            signedOutRemote.InvitationCreateCalls == 0,
            "Agent organization invitation authority was called without authenticated session custody");

        var signedOutManage = await signedOut.ManageInvitationAsync(
            new AccountOrganizationInvitationManageRequest(
                "organization-invitation-manage-auth-cert",
                "REVOKE",
                "bke-org-invite-v1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            CancellationToken.None);
        Require(
            signedOutManage.Status == "AUTH_REQUIRED" &&
            signedOutManage.InvitationCode is null &&
            signedOutRemote.InvitationManageCalls == 0,
            "Agent organization invitation management authority was called without session custody");

        var signedOutMemberManage =
            await signedOut.ManageMemberAsync(
                new AccountOrganizationMemberManageRequest(
                    "organization-member-manage-auth-cert",
                    "REMOVE",
                    "bke-org-member-v1_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                    null),
                CancellationToken.None);
        Require(
            signedOutMemberManage.Status == "AUTH_REQUIRED" &&
            signedOutRemote.MemberManageCalls == 0,
            "Agent organization member authority was called without session custody");


        var signedOutLeave = await signedOut.LeaveAsync(
            new AccountOrganizationLeaveRequest(
                "organization-leave-auth-cert"),
            CancellationToken.None);
        Require(
            signedOutLeave.Status == "AUTH_REQUIRED" &&
            signedOutLeave.ReauthenticationRequired &&
            signedOutRemote.LeaveCalls == 0,
            "Agent organization leave authority was called without session custody");
    }

    private static async Task CertifyRemoteTransportAsync()
    {
        const string token = "organization-transport-secret";
        var handler = new OrganizationTransportHandler(
            HttpStatusCode.OK,
            """
            {
              "status":"ready",
              "account":{
                "type":"ORGANIZATION",
                "display_name":"Certification Organization",
                "lifecycle_state":"ACTIVE",
                "role":"OWNER"
              },
              "permissions":{
                "manage_members":true,
                "leave_organization":false,
                "view_billing":true,
                "view_licenses":true
              },
              "organization":{
                "legal_name":"Certification Organization Legal",
                "registration_number":"REG-001"
              },
              "billing_email":"billing@example.test",
              "tax_id":"TAX-001",
              "counts":{
                "licenses":2,
                "subscriptions":1,
                "orders":3
              },
              "members":[
                {
                  "email":"owner@example.test",
                  "name":"Owner",
                  "role":"OWNER",
                  "management_handle":"bke-org-member-v1_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                }
              ],
              "invitations":[
                {
                  "email":"invitee@example.test",
                  "role":"MEMBER",
                  "status":"PENDING",
                  "expires_at":"2026-10-01T12:00:00.000Z",
                  "created_at":"2026-09-29T12:00:00.000Z",
                  "management_handle":"bke-org-invite-v1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                }
              ]
            }
            """);
        using (var client = new HttpClient(handler))
        using (var remote = new AccountOrganizationRemote(
            client,
            "https://organization-cert.example.test"))
        {
            var result = await remote.GetAsync(
                token,
                CancellationToken.None);
            Require(
                result.Status == "ready" &&
                result.Account?.Role == "OWNER" &&
                result.Permissions?.LeaveOrganization == false &&
                result.Members?.Count == 1 &&
                result.Members[0].ManagementHandle ==
                    "bke-org-member-v1_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" &&
                handler.RequestCount == 1 &&
                handler.SawBearer &&
                handler.SawProtocol &&
                handler.SawGet &&
                handler.SawNoBody,
                "Agent organization remote transport drifted");
        }

        var notOrgHandler = new OrganizationTransportHandler(
            HttpStatusCode.OK,
            """{"status":"not_organization"}""");
        using (var client = new HttpClient(notOrgHandler))
        using (var remote = new AccountOrganizationRemote(
            client,
            "https://organization-cert.example.test"))
        {
            var result = await remote.GetAsync(
                token,
                CancellationToken.None);
            Require(
                result.Status == "not_organization",
                "Agent organization remote lost personal-account no-op response");
        }

        var createHandler = new OrganizationCreateTransportHandler(
            HttpStatusCode.Created,
            """
            {
              "status":"created",
              "switch_required":true,
              "account":{
                "type":"ORGANIZATION",
                "display_name":"Created Organization"
              }
            }
            """);
        using (var client = new HttpClient(createHandler))
        using (var remote = new AccountOrganizationRemote(
            client,
            "https://organization-cert.example.test"))
        {
            var result = await remote.CreateAsync(
                token,
                "Created Organization",
                "Created Organization Legal",
                "billing-created@example.test",
                "REG-CREATE",
                "TAX-CREATE",
                CancellationToken.None);
            Require(
                result.Status == "created" &&
                result.DisplayName == "Created Organization" &&
                result.SwitchRequired &&
                createHandler.RequestCount == 1 &&
                createHandler.SawBearer &&
                createHandler.SawProtocol &&
                createHandler.SawPost &&
                createHandler.BodyExcludedAuthorityIds,
                "Agent organization create transport drifted");
        }

        var organizationProfileHandler =
            new OrganizationProfileTransportHandler(
                expectOrganizationFields: true,
                expectBillingFields: false);
        using (var client = new HttpClient(organizationProfileHandler))
        using (var remote = new AccountOrganizationRemote(
            client,
            "https://organization-cert.example.test"))
        {
            var result = await remote.UpdateProfileAsync(
                token,
                true,
                "Updated Organization",
                "Updated Organization Legal",
                null,
                false,
                null,
                null,
                CancellationToken.None);
            Require(
                result.Status == "updated" &&
                organizationProfileHandler.RequestCount == 1 &&
                organizationProfileHandler.SawBearer &&
                organizationProfileHandler.SawProtocol &&
                organizationProfileHandler.SawPatch &&
                organizationProfileHandler.BodyMatchedFieldGroups &&
                organizationProfileHandler.BodyExcludedAuthorityIds,
                "Agent organization-profile organization-field transport drifted");
        }

        var billingProfileHandler =
            new OrganizationProfileTransportHandler(
                expectOrganizationFields: false,
                expectBillingFields: true);
        using (var client = new HttpClient(billingProfileHandler))
        using (var remote = new AccountOrganizationRemote(
            client,
            "https://organization-cert.example.test"))
        {
            var result = await remote.UpdateProfileAsync(
                token,
                false,
                null,
                null,
                null,
                true,
                "billing-updated@example.test",
                null,
                CancellationToken.None);
            Require(
                result.Status == "updated" &&
                billingProfileHandler.RequestCount == 1 &&
                billingProfileHandler.BodyMatchedFieldGroups &&
                billingProfileHandler.BodyExcludedAuthorityIds,
                "Agent organization-profile billing-field transport drifted");
        }

        var invitationHandler =
            new OrganizationInvitationTransportHandler();
        using (var client = new HttpClient(invitationHandler))
        using (var remote = new AccountOrganizationRemote(
            client,
            "https://organization-cert.example.test"))
        {
            var result = await remote.CreateInvitationAsync(
                token,
                "new-member@example.test",
                "MEMBER",
                CancellationToken.None);
            Require(
                result.Status == "created" &&
                result.Invitation?.Email ==
                    "new-member@example.test" &&
                result.Invitation?.Role == "MEMBER" &&
                result.InvitationCode ==
                    "organization-invitation-code-cert" &&
                invitationHandler.RequestCount == 1 &&
                invitationHandler.SawBearer &&
                invitationHandler.SawProtocol &&
                invitationHandler.SawPost &&
                invitationHandler.BodyMatchedIntent &&
                invitationHandler.BodyExcludedAuthorityIds,
                "Agent organization invitation transport drifted");
        }

        var leakingInvitationHandler =
            new OrganizationTransportHandler(
                HttpStatusCode.Created,
                """
                {
                  "status":"created",
                  "invitation":{
                    "id":"must-not-cross",
                    "email":"new-member@example.test",
                    "role":"MEMBER",
                    "status":"PENDING",
                    "expires_at":"2026-10-07T00:00:00.000Z",
                    "created_at":"2026-09-30T00:00:00.000Z"
                  },
                  "invitation_code":"organization-invitation-code-cert"
                }
                """);
        using (var client = new HttpClient(leakingInvitationHandler))
        using (var remote = new AccountOrganizationRemote(
            client,
            "https://organization-cert.example.test"))
        {
            await RequireThrowsAsync<InvalidDataException>(
                () => remote.CreateInvitationAsync(
                    token,
                    "new-member@example.test",
                    "MEMBER",
                    CancellationToken.None),
                "Agent organization invitation accepted a cloud invitation identifier");
        }

        var manageResendHandler =
            new OrganizationInvitationManageTransportHandler(
                "resend",
                includeCode: true);
        using (var client = new HttpClient(manageResendHandler))
        using (var remote = new AccountOrganizationRemote(
            client,
            "https://organization-cert.example.test"))
        {
            var result = await remote.ManageInvitationAsync(
                token,
                "RESEND",
                "bke-org-invite-v1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                CancellationToken.None);
            Require(
                result.Status == "resent" &&
                result.InvitationCode ==
                    "organization-invitation-resend-code-cert" &&
                manageResendHandler.RequestCount == 1 &&
                manageResendHandler.BodyMatchedIntent &&
                manageResendHandler.BodyExcludedAuthorityIds,
                "Agent invitation resend transport drifted");
        }

        var manageRevokeHandler =
            new OrganizationInvitationManageTransportHandler(
                "revoke",
                includeCode: false);
        using (var client = new HttpClient(manageRevokeHandler))
        using (var remote = new AccountOrganizationRemote(
            client,
            "https://organization-cert.example.test"))
        {
            var result = await remote.ManageInvitationAsync(
                token,
                "REVOKE",
                "bke-org-invite-v1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                CancellationToken.None);
            Require(
                result.Status == "revoked" &&
                result.Invitation?.Status == "REVOKED" &&
                result.InvitationCode is null &&
                manageRevokeHandler.RequestCount == 1 &&
                manageRevokeHandler.BodyMatchedIntent,
                "Agent invitation revoke transport drifted");
        }

        var roleUpdateHandler =
            new OrganizationMemberManageTransportHandler(
                "update_role",
                "BILLING");
        using (var client = new HttpClient(roleUpdateHandler))
        using (var remote = new AccountOrganizationRemote(
            client,
            "https://organization-cert.example.test"))
        {
            var result = await remote.ManageMemberAsync(
                token,
                "UPDATE_ROLE",
                "bke-org-member-v1_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "BILLING",
                CancellationToken.None);
            Require(
                result.Status == "updated" &&
                roleUpdateHandler.RequestCount == 1 &&
                roleUpdateHandler.BodyMatchedIntent &&
                roleUpdateHandler.BodyExcludedAuthorityIds,
                "Agent member role-update transport drifted");
        }

        var removeMemberHandler =
            new OrganizationMemberManageTransportHandler(
                "remove",
                null);
        using (var client = new HttpClient(removeMemberHandler))
        using (var remote = new AccountOrganizationRemote(
            client,
            "https://organization-cert.example.test"))
        {
            var result = await remote.ManageMemberAsync(
                token,
                "REMOVE",
                "bke-org-member-v1_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                null,
                CancellationToken.None);
            Require(
                result.Status == "removed" &&
                removeMemberHandler.RequestCount == 1 &&
                removeMemberHandler.BodyMatchedIntent &&
                removeMemberHandler.BodyExcludedAuthorityIds,
                "Agent member removal transport drifted");
        }


        var transferHandler =
            new OrganizationOwnershipTransferTransportHandler(
                HttpStatusCode.OK,
                """{"status":"transferred","reauthentication_required":true}""");
        using (var client = new HttpClient(transferHandler))
        using (var remote = new AccountOrganizationRemote(
            client,
            "https://organization-cert.example.test"))
        {
            var result = await remote.TransferOwnershipAsync(
                token,
                "bke-org-member-v1_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                CancellationToken.None);
            Require(
                result.Status == "transferred" &&
                result.ReauthenticationRequired &&
                transferHandler.RequestCount == 1 &&
                transferHandler.SawBearer &&
                transferHandler.SawProtocol &&
                transferHandler.SawPost &&
                transferHandler.BodyMatchedIntent &&
                transferHandler.BodyExcludedAuthorityIds,
                "Agent ownership transfer transport widened target intent or lost session mediation");
        }

        var missingTransferHandler =
            new OrganizationOwnershipTransferTransportHandler(
                HttpStatusCode.NotFound,
                """{"error":"MEMBER_NOT_FOUND"}""");
        using (var client = new HttpClient(missingTransferHandler))
        using (var remote = new AccountOrganizationRemote(
            client,
            "https://organization-cert.example.test"))
        {
            var result = await remote.TransferOwnershipAsync(
                token,
                "bke-org-member-v1_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                CancellationToken.None);
            Require(
                result.Status == "member_not_found" &&
                !result.ReauthenticationRequired &&
                result.ErrorCode == "MEMBER_NOT_FOUND" &&
                missingTransferHandler.RequestCount == 1,
                "Agent ownership transfer lost explicit target rejection semantics");
        }

        var driftedTransferHandler =
            new OrganizationOwnershipTransferTransportHandler(
                HttpStatusCode.OK,
                """{"status":"transferred","reauthentication_required":true,"owner_id":"forbidden"}""");
        using (var client = new HttpClient(driftedTransferHandler))
        using (var remote = new AccountOrganizationRemote(
            client,
            "https://organization-cert.example.test"))
        {
            await RequireThrowsAsync<InvalidDataException>(
                () => remote.TransferOwnershipAsync(
                    token,
                    "bke-org-member-v1_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                    CancellationToken.None),
                "Agent ownership transfer accepted authority identifiers in success response");
        }


        var leaveHandler = new OrganizationLeaveTransportHandler(
            HttpStatusCode.OK,
            """{"status":"left","reauthentication_required":true}""");
        using (var client = new HttpClient(leaveHandler))
        using (var remote = new AccountOrganizationRemote(
            client,
            "https://organization-cert.example.test"))
        {
            var result = await remote.LeaveAsync(
                token,
                CancellationToken.None);
            Require(
                result.Status == "left" &&
                result.ReauthenticationRequired &&
                leaveHandler.RequestCount == 1 &&
                leaveHandler.SawBearer &&
                leaveHandler.SawProtocol &&
                leaveHandler.SawPost &&
                leaveHandler.BodyWasEmptyObject &&
                leaveHandler.BodyExcludedAuthorityIds,
                "Agent organization leave transport widened self-only intent or lost session mediation");
        }

        var ownerLeaveHandler = new OrganizationLeaveTransportHandler(
            HttpStatusCode.Conflict,
            """{"error":"OWNER_CANNOT_LEAVE"}""");
        using (var client = new HttpClient(ownerLeaveHandler))
        using (var remote = new AccountOrganizationRemote(
            client,
            "https://organization-cert.example.test"))
        {
            var result = await remote.LeaveAsync(
                token,
                CancellationToken.None);
            Require(
                result.Status == "owner_cannot_leave" &&
                result.ErrorCode == "OWNER_CANNOT_LEAVE" &&
                !result.ReauthenticationRequired,
                "Agent organization leave lost Digital Solutions owner protection");
        }

        var driftedLeaveHandler = new OrganizationLeaveTransportHandler(
            HttpStatusCode.OK,
            """{"status":"left","reauthentication_required":true,"account_id":"forbidden"}""");
        using (var client = new HttpClient(driftedLeaveHandler))
        using (var remote = new AccountOrganizationRemote(
            client,
            "https://organization-cert.example.test"))
        {
            await RequireThrowsAsync<InvalidDataException>(
                () => remote.LeaveAsync(
                    token,
                    CancellationToken.None),
                "Agent organization leave accepted authority identifiers in the success response");
        }

        var redirect = new OrganizationTransportHandler(
            HttpStatusCode.Redirect,
            "{}");
        using (var client = new HttpClient(redirect))
        using (var remote = new AccountOrganizationRemote(
            client,
            "https://organization-cert.example.test"))
        {
            await RequireThrowsAsync<HttpRequestException>(
                () => remote.GetAsync(
                    token,
                    CancellationToken.None),
                "Agent organization redirect was not rejected");
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

    private static void Require(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }
}

sealed class OrganizationStore : IAccountSessionSecretStore
{
    public AccountSessionStoredState? State { get; private set; }

    private OrganizationStore(AccountSessionStoredState? state)
    {
        State = state;
    }

    public static OrganizationStore Active(
        AccountSessionAccount account) =>
        new(new ActiveAccountSessionState(
            "organization-access-secret",
            "organization-refresh-secret",
            "organization-session",
            DateTimeOffset.UtcNow.AddMinutes(15),
            DateTimeOffset.UtcNow.AddDays(30),
            account));

    public Task<AccountSessionStoredState?> ReadAsync(
        CancellationToken cancellationToken) =>
        Task.FromResult(State);

    public Task WriteAsync(
        AccountSessionStoredState state,
        CancellationToken cancellationToken)
    {
        State = state;
        return Task.CompletedTask;
    }

    public Task ClearAsync(CancellationToken cancellationToken)
    {
        State = null;
        return Task.CompletedTask;
    }
}

sealed class OrganizationAuthenticatedSessionService(
    AccountSessionAccount account) : IAccountSessionService
{
    public Task<AccountSessionStatusResponse> StatusAsync(
        AccountSessionStatusRequest request,
        CancellationToken cancellationToken) =>
        Task.FromResult(new AccountSessionStatusResponse(
            LocalAgentContract.AccountSessionCapabilityId,
            LocalAgentContract.AccountSessionContractVersion,
            "AUTHENTICATED",
            account,
            null));

    public Task<AccountSessionCompleteResponse> CompleteAsync(
        AccountSessionCompleteRequest request,
        CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task<AccountSessionStartResponse> StartAsync(
        AccountSessionStartRequest request,
        CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task<AccountSessionLogoutResponse> LogoutAsync(
        AccountSessionLogoutRequest request,
        CancellationToken cancellationToken) =>
        throw new NotSupportedException();
}

sealed class OrganizationSignedOutSessionService : IAccountSessionService
{
    public Task<AccountSessionStatusResponse> StatusAsync(
        AccountSessionStatusRequest request,
        CancellationToken cancellationToken) =>
        Task.FromResult(new AccountSessionStatusResponse(
            LocalAgentContract.AccountSessionCapabilityId,
            LocalAgentContract.AccountSessionContractVersion,
            "SIGNED_OUT",
            null,
            null));

    public Task<AccountSessionCompleteResponse> CompleteAsync(
        AccountSessionCompleteRequest request,
        CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task<AccountSessionStartResponse> StartAsync(
        AccountSessionStartRequest request,
        CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task<AccountSessionLogoutResponse> LogoutAsync(
        AccountSessionLogoutRequest request,
        CancellationToken cancellationToken) =>
        throw new NotSupportedException();
}

sealed class FakeOrganizationRemote(
    RemoteAccountOrganizationResult result,
    RemoteAccountOrganizationCreateResult? createResult = null,
    RemoteAccountOrganizationProfileUpdateResult? profileResult = null,
    RemoteAccountOrganizationInvitationCreateResult? invitationResult = null,
    RemoteAccountOrganizationMemberManageResult? memberManageResult = null,
    RemoteAccountOrganizationOwnershipTransferResult? ownershipTransferResult = null,
    RemoteAccountOrganizationLeaveResult? leaveResult = null) :
    IAccountOrganizationRemote
{
    public int Calls { get; private set; }
    public int CreateCalls { get; private set; }
    public int ProfileUpdateCalls { get; private set; }
    public int InvitationCreateCalls { get; private set; }
    public int InvitationManageCalls { get; private set; }
    public int MemberManageCalls { get; private set; }
    public int OwnershipTransferCalls { get; private set; }
    public int LeaveCalls { get; private set; }
    public string? LastAccessToken { get; private set; }
    public bool LastUpdateOrganizationProfile { get; private set; }
    public bool LastUpdateBillingProfile { get; private set; }
    public string? LastRegistrationNumber { get; private set; }
    public string? LastTaxId { get; private set; }
    public string? LastInvitationEmail { get; private set; }
    public string? LastInvitationRole { get; private set; }
    public string? LastInvitationManageAction { get; private set; }
    public string? LastInvitationManagementHandle { get; private set; }
    public string? LastMemberManageAction { get; private set; }
    public string? LastMemberManagementHandle { get; private set; }
    public string? LastMemberManageRole { get; private set; }
    public string? LastOwnershipTransferHandle { get; private set; }

    public Task<RemoteAccountOrganizationResult> GetAsync(
        string accessToken,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Calls++;
        LastAccessToken = accessToken;
        return Task.FromResult(result);
    }

    public Task<RemoteAccountOrganizationCreateResult> CreateAsync(
        string accessToken,
        string displayName,
        string legalName,
        string billingEmail,
        string? registrationNumber,
        string? taxId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        CreateCalls++;
        LastAccessToken = accessToken;
        return Task.FromResult(
            createResult ??
            new RemoteAccountOrganizationCreateResult(
                "created",
                displayName,
                true));
    }

    public Task<RemoteAccountOrganizationProfileUpdateResult> UpdateProfileAsync(
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
        cancellationToken.ThrowIfCancellationRequested();
        ProfileUpdateCalls++;
        LastAccessToken = accessToken;
        LastUpdateOrganizationProfile = updateOrganizationProfile;
        LastUpdateBillingProfile = updateBillingProfile;
        LastRegistrationNumber = registrationNumber;
        LastTaxId = taxId;
        return Task.FromResult(
            profileResult ??
            new RemoteAccountOrganizationProfileUpdateResult(
                "updated"));
    }

    public Task<RemoteAccountOrganizationInvitationCreateResult> CreateInvitationAsync(
        string accessToken,
        string email,
        string role,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        InvitationCreateCalls++;
        LastAccessToken = accessToken;
        LastInvitationEmail = email;
        LastInvitationRole = role;
        return Task.FromResult(
            invitationResult ??
            new RemoteAccountOrganizationInvitationCreateResult(
                "created",
                new AccountOrganizationInvitationIssued(
                    email,
                    role,
                    "PENDING",
                    "2026-10-07T00:00:00.000Z",
                    "2026-09-30T00:00:00.000Z"),
                "organization-invitation-code-cert"));
    }

    public Task<RemoteAccountOrganizationInvitationManageResult> ManageInvitationAsync(
        string accessToken,
        string action,
        string managementHandle,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        InvitationManageCalls++;
        LastAccessToken = accessToken;
        LastInvitationManageAction = action;
        LastInvitationManagementHandle = managementHandle;
        var revoked = action == "REVOKE";
        return Task.FromResult(
            new RemoteAccountOrganizationInvitationManageResult(
                revoked ? "revoked" : "resent",
                new AccountOrganizationInvitationIssued(
                    "invitee@example.test",
                    "MEMBER",
                    revoked ? "REVOKED" : "PENDING",
                    "2026-10-08T00:00:00.000Z",
                    "2026-09-29T12:00:00.000Z"),
                revoked
                    ? null
                    : "organization-invitation-resend-code-cert"));
    }

    public Task<RemoteAccountOrganizationMemberManageResult> ManageMemberAsync(
        string accessToken,
        string action,
        string managementHandle,
        string? role,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        MemberManageCalls++;
        LastAccessToken = accessToken;
        LastMemberManageAction = action;
        LastMemberManagementHandle = managementHandle;
        LastMemberManageRole = role;
        return Task.FromResult(
            memberManageResult ??
            new RemoteAccountOrganizationMemberManageResult(
                action == "REMOVE" ? "removed" : "updated"));
    }

    public Task<RemoteAccountOrganizationOwnershipTransferResult> TransferOwnershipAsync(
        string accessToken,
        string managementHandle,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        OwnershipTransferCalls++;
        LastAccessToken = accessToken;
        LastOwnershipTransferHandle = managementHandle;
        return Task.FromResult(
            ownershipTransferResult ??
            new RemoteAccountOrganizationOwnershipTransferResult(
                "transferred",
                ReauthenticationRequired: true));
    }

    public Task<RemoteAccountOrganizationLeaveResult> LeaveAsync(
        string accessToken,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        LeaveCalls++;
        LastAccessToken = accessToken;
        return Task.FromResult(
            leaveResult ??
            new RemoteAccountOrganizationLeaveResult(
                "left",
                ReauthenticationRequired: true));
    }
}



sealed class ThrowingOrganizationRemote(
    Exception error) : IAccountOrganizationRemote
{
    public Task<RemoteAccountOrganizationResult> GetAsync(
        string accessToken,
        CancellationToken cancellationToken) =>
        Task.FromException<RemoteAccountOrganizationResult>(error);

    public Task<RemoteAccountOrganizationCreateResult> CreateAsync(
        string accessToken,
        string displayName,
        string legalName,
        string billingEmail,
        string? registrationNumber,
        string? taxId,
        CancellationToken cancellationToken) =>
        Task.FromException<RemoteAccountOrganizationCreateResult>(error);

    public Task<RemoteAccountOrganizationProfileUpdateResult> UpdateProfileAsync(
        string accessToken,
        bool updateOrganizationProfile,
        string? displayName,
        string? legalName,
        string? registrationNumber,
        bool updateBillingProfile,
        string? billingEmail,
        string? taxId,
        CancellationToken cancellationToken) =>
        Task.FromException<RemoteAccountOrganizationProfileUpdateResult>(
            error);

    public Task<RemoteAccountOrganizationInvitationCreateResult> CreateInvitationAsync(
        string accessToken,
        string email,
        string role,
        CancellationToken cancellationToken) =>
        Task.FromException<RemoteAccountOrganizationInvitationCreateResult>(
            error);

    public Task<RemoteAccountOrganizationInvitationManageResult> ManageInvitationAsync(
        string accessToken,
        string action,
        string managementHandle,
        CancellationToken cancellationToken) =>
        Task.FromException<RemoteAccountOrganizationInvitationManageResult>(
            error);

    public Task<RemoteAccountOrganizationMemberManageResult> ManageMemberAsync(
        string accessToken,
        string action,
        string managementHandle,
        string? role,
        CancellationToken cancellationToken) =>
        Task.FromException<RemoteAccountOrganizationMemberManageResult>(
            error);

    public Task<RemoteAccountOrganizationOwnershipTransferResult> TransferOwnershipAsync(
        string accessToken,
        string managementHandle,
        CancellationToken cancellationToken) =>
        Task.FromException<RemoteAccountOrganizationOwnershipTransferResult>(
            error);

    public Task<RemoteAccountOrganizationLeaveResult> LeaveAsync(
        string accessToken,
        CancellationToken cancellationToken) =>
        Task.FromException<RemoteAccountOrganizationLeaveResult>(
            error);
}


sealed class OrganizationTransportHandler(
    HttpStatusCode statusCode,
    string json) : HttpMessageHandler
{
    public int RequestCount { get; private set; }
    public bool SawBearer { get; private set; }
    public bool SawProtocol { get; private set; }
    public bool SawGet { get; private set; }
    public bool SawNoBody { get; private set; }

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        RequestCount++;
        SawBearer =
            request.Headers.Authorization?.Scheme == "Bearer" &&
            request.Headers.Authorization.Parameter ==
                "organization-transport-secret";
        SawProtocol =
            request.Headers.TryGetValues(
                "x-bke-account-session-version",
                out var values) &&
            values.SingleOrDefault() ==
                AccountSessionRemote.ProtocolVersion;
        SawGet =
            request.Method == HttpMethod.Get &&
            request.RequestUri?.AbsolutePath ==
                "/api/agent-sessions/account/organization";
        SawNoBody = request.Content is null;

        var response = new HttpResponseMessage(statusCode)
        {
            Content = new StringContent(
                json,
                Encoding.UTF8,
                "application/json"),
        };
        if ((int)statusCode is not (>= 300 and <= 399))
        {
            response.Headers.TryAddWithoutValidation(
                "x-bke-account-session-version",
                AccountSessionRemote.ProtocolVersion);
        }
        return Task.FromResult(response);
    }
}


sealed class OrganizationCreateTransportHandler(
    HttpStatusCode statusCode,
    string json) : HttpMessageHandler
{
    public int RequestCount { get; private set; }
    public bool SawBearer { get; private set; }
    public bool SawProtocol { get; private set; }
    public bool SawPost { get; private set; }
    public bool BodyExcludedAuthorityIds { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        RequestCount++;
        SawBearer =
            request.Headers.Authorization?.Scheme == "Bearer" &&
            request.Headers.Authorization.Parameter ==
                "organization-transport-secret";
        SawProtocol =
            request.Headers.TryGetValues(
                "x-bke-account-session-version",
                out var values) &&
            values.SingleOrDefault() ==
                AccountSessionRemote.ProtocolVersion;
        SawPost =
            request.Method == HttpMethod.Post &&
            request.RequestUri?.AbsolutePath ==
                "/api/agent-sessions/account/organization/create";

        var body = request.Content is null
            ? string.Empty
            : await request.Content.ReadAsStringAsync(
                cancellationToken);
        BodyExcludedAuthorityIds =
            body.Contains(
                "\"display_name\":\"Created Organization\"",
                StringComparison.Ordinal) &&
            !body.Contains(
                "account_id",
                StringComparison.OrdinalIgnoreCase) &&
            !body.Contains(
                "user_id",
                StringComparison.OrdinalIgnoreCase) &&
            !body.Contains(
                "owner_id",
                StringComparison.OrdinalIgnoreCase);

        var response = new HttpResponseMessage(statusCode)
        {
            Content = new StringContent(
                json,
                Encoding.UTF8,
                "application/json"),
        };
        if ((int)statusCode is not (>= 300 and <= 399))
        {
            response.Headers.TryAddWithoutValidation(
                "x-bke-account-session-version",
                AccountSessionRemote.ProtocolVersion);
        }
        return response;
    }
}


sealed class OrganizationProfileTransportHandler(
    bool expectOrganizationFields,
    bool expectBillingFields) : HttpMessageHandler
{
    public int RequestCount { get; private set; }
    public bool SawBearer { get; private set; }
    public bool SawProtocol { get; private set; }
    public bool SawPatch { get; private set; }
    public bool BodyMatchedFieldGroups { get; private set; }
    public bool BodyExcludedAuthorityIds { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        RequestCount++;
        SawBearer =
            request.Headers.Authorization?.Scheme == "Bearer" &&
            request.Headers.Authorization.Parameter ==
                "organization-transport-secret";
        SawProtocol =
            request.Headers.TryGetValues(
                "x-bke-account-session-version",
                out var values) &&
            values.SingleOrDefault() ==
                AccountSessionRemote.ProtocolVersion;
        SawPatch =
            request.Method == HttpMethod.Patch &&
            request.RequestUri?.AbsolutePath ==
                "/api/agent-sessions/account/organization/profile";

        var body = request.Content is null
            ? string.Empty
            : await request.Content.ReadAsStringAsync(
                cancellationToken);
        using var document =
            System.Text.Json.JsonDocument.Parse(body);
        var root = document.RootElement;

        var hasDisplay = root.TryGetProperty(
            "display_name",
            out _);
        var hasLegal = root.TryGetProperty(
            "legal_name",
            out _);
        var hasRegistration = root.TryGetProperty(
            "registration_number",
            out var registration);
        var hasBilling = root.TryGetProperty(
            "billing_email",
            out _);
        var hasTax = root.TryGetProperty(
            "tax_id",
            out var tax);

        BodyMatchedFieldGroups =
            hasDisplay == expectOrganizationFields &&
            hasLegal == expectOrganizationFields &&
            hasRegistration == expectOrganizationFields &&
            hasBilling == expectBillingFields &&
            hasTax == expectBillingFields &&
            (!expectOrganizationFields ||
                registration.ValueKind ==
                    System.Text.Json.JsonValueKind.Null) &&
            (!expectBillingFields ||
                tax.ValueKind ==
                    System.Text.Json.JsonValueKind.Null);

        BodyExcludedAuthorityIds =
            !body.Contains(
                "account_id",
                StringComparison.OrdinalIgnoreCase) &&
            !body.Contains(
                "user_id",
                StringComparison.OrdinalIgnoreCase) &&
            !body.Contains(
                "owner_id",
                StringComparison.OrdinalIgnoreCase) &&
            !body.Contains(
                "member_id",
                StringComparison.OrdinalIgnoreCase) &&
            !body.Contains(
                "invitation_id",
                StringComparison.OrdinalIgnoreCase);

        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(
                """{"status":"updated"}""",
                Encoding.UTF8,
                "application/json"),
        };
        response.Headers.TryAddWithoutValidation(
            "x-bke-account-session-version",
            AccountSessionRemote.ProtocolVersion);
        return response;
    }
}


sealed class OrganizationInvitationTransportHandler :
    HttpMessageHandler
{
    public int RequestCount { get; private set; }
    public bool SawBearer { get; private set; }
    public bool SawProtocol { get; private set; }
    public bool SawPost { get; private set; }
    public bool BodyMatchedIntent { get; private set; }
    public bool BodyExcludedAuthorityIds { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        RequestCount++;
        SawBearer =
            request.Headers.Authorization?.Scheme == "Bearer" &&
            request.Headers.Authorization.Parameter ==
                "organization-transport-secret";
        SawProtocol =
            request.Headers.TryGetValues(
                "x-bke-account-session-version",
                out var values) &&
            values.SingleOrDefault() ==
                AccountSessionRemote.ProtocolVersion;
        SawPost =
            request.Method == HttpMethod.Post &&
            request.RequestUri?.AbsolutePath ==
                "/api/agent-sessions/account/organization/invitations/create";

        var body = request.Content is null
            ? string.Empty
            : await request.Content.ReadAsStringAsync(
                cancellationToken);
        using var document =
            System.Text.Json.JsonDocument.Parse(body);
        var root = document.RootElement;

        BodyMatchedIntent =
            root.EnumerateObject().Select(property => property.Name)
                .OrderBy(value => value, StringComparer.Ordinal)
                .SequenceEqual(
                    new[] { "email", "role" }
                        .OrderBy(value => value, StringComparer.Ordinal)) &&
            root.GetProperty("email").GetString() ==
                "new-member@example.test" &&
            root.GetProperty("role").GetString() == "MEMBER";

        BodyExcludedAuthorityIds =
            !body.Contains(
                "account_id",
                StringComparison.OrdinalIgnoreCase) &&
            !body.Contains(
                "user_id",
                StringComparison.OrdinalIgnoreCase) &&
            !body.Contains(
                "owner_id",
                StringComparison.OrdinalIgnoreCase) &&
            !body.Contains(
                "invitation_id",
                StringComparison.OrdinalIgnoreCase) &&
            !body.Contains(
                "token_hash",
                StringComparison.OrdinalIgnoreCase);

        var response = new HttpResponseMessage(
            HttpStatusCode.Created)
        {
            Content = new StringContent(
                """
                {
                  "status":"created",
                  "invitation":{
                    "email":"new-member@example.test",
                    "role":"MEMBER",
                    "status":"PENDING",
                    "expires_at":"2026-10-07T00:00:00.000Z",
                    "created_at":"2026-09-30T00:00:00.000Z"
                  },
                  "invitation_code":"organization-invitation-code-cert"
                }
                """,
                Encoding.UTF8,
                "application/json"),
        };
        response.Headers.TryAddWithoutValidation(
            "x-bke-account-session-version",
            AccountSessionRemote.ProtocolVersion);
        return response;
    }
}


sealed class OrganizationInvitationManageTransportHandler(
    string action,
    bool includeCode) : HttpMessageHandler
{
    public int RequestCount { get; private set; }
    public bool BodyMatchedIntent { get; private set; }
    public bool BodyExcludedAuthorityIds { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        RequestCount++;
        var body = request.Content is null
            ? string.Empty
            : await request.Content.ReadAsStringAsync(cancellationToken);
        using var document =
            System.Text.Json.JsonDocument.Parse(body);
        var root = document.RootElement;

        BodyMatchedIntent =
            request.Method == HttpMethod.Post &&
            request.RequestUri?.AbsolutePath ==
                "/api/agent-sessions/account/organization/invitations/manage" &&
            root.GetProperty("action").GetString() == action &&
            root.GetProperty("management_handle").GetString() ==
                "bke-org-invite-v1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &&
            root.EnumerateObject().Count() == 2;
        BodyExcludedAuthorityIds =
            !body.Contains("invitation_id", StringComparison.OrdinalIgnoreCase) &&
            !body.Contains("account_id", StringComparison.OrdinalIgnoreCase) &&
            !body.Contains("user_id", StringComparison.OrdinalIgnoreCase) &&
            !body.Contains("owner_id", StringComparison.OrdinalIgnoreCase);

        var status = action == "resend" ? "resent" : "revoked";
        var invitationStatus =
            action == "resend" ? "PENDING" : "REVOKED";
        var code = includeCode
            ? ",\"invitation_code\":\"organization-invitation-resend-code-cert\""
            : string.Empty;
        var json =
            "{\"status\":\"" + status +
            "\",\"invitation\":{" +
            "\"email\":\"invitee@example.test\"," +
            "\"role\":\"MEMBER\"," +
            "\"status\":\"" + invitationStatus + "\"," +
            "\"expires_at\":\"2026-10-08T00:00:00.000Z\"," +
            "\"created_at\":\"2026-09-29T12:00:00.000Z\"" +
            "}" + code + "}";

        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(
                json,
                Encoding.UTF8,
                "application/json"),
        };
        response.Headers.TryAddWithoutValidation(
            "x-bke-account-session-version",
            AccountSessionRemote.ProtocolVersion);
        return response;
    }
}

sealed class OrganizationMemberManageTransportHandler(
    string action,
    string? role) : HttpMessageHandler
{
    public int RequestCount { get; private set; }
    public bool BodyMatchedIntent { get; private set; }
    public bool BodyExcludedAuthorityIds { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        RequestCount++;

        var body = request.Content is null
            ? string.Empty
            : await request.Content.ReadAsStringAsync(
                cancellationToken);
        using var document =
            System.Text.Json.JsonDocument.Parse(body);
        var root = document.RootElement;

        var expectedFieldCount = role is null ? 2 : 3;
        BodyMatchedIntent =
            request.Method == HttpMethod.Post &&
            request.RequestUri?.AbsolutePath ==
                "/api/agent-sessions/account/organization/members/manage" &&
            root.GetProperty("action").GetString() == action &&
            root.GetProperty("management_handle").GetString() ==
                "bke-org-member-v1_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" &&
            root.EnumerateObject().Count() == expectedFieldCount &&
            (
                role is null
                    ? !root.TryGetProperty("role", out _)
                    : root.GetProperty("role").GetString() == role
            );

        BodyExcludedAuthorityIds =
            !body.Contains("account_id", StringComparison.OrdinalIgnoreCase) &&
            !body.Contains("user_id", StringComparison.OrdinalIgnoreCase) &&
            !body.Contains("member_id", StringComparison.OrdinalIgnoreCase) &&
            !body.Contains("membership_id", StringComparison.OrdinalIgnoreCase) &&
            !body.Contains("owner_id", StringComparison.OrdinalIgnoreCase);

        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(
                action == "remove"
                    ? """{"status":"removed"}"""
                    : """{"status":"updated"}""",
                Encoding.UTF8,
                "application/json"),
        };
        response.Headers.TryAddWithoutValidation(
            "x-bke-account-session-version",
            AccountSessionRemote.ProtocolVersion);
        return response;
    }
}


sealed class OrganizationOwnershipTransferTransportHandler(
    HttpStatusCode statusCode,
    string json) : HttpMessageHandler
{
    public int RequestCount { get; private set; }
    public bool SawBearer { get; private set; }
    public bool SawProtocol { get; private set; }
    public bool SawPost { get; private set; }
    public bool BodyMatchedIntent { get; private set; }
    public bool BodyExcludedAuthorityIds { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        RequestCount++;
        SawBearer =
            request.Headers.Authorization?.Scheme == "Bearer" &&
            request.Headers.Authorization.Parameter ==
                "organization-transport-secret";
        SawProtocol =
            request.Headers.TryGetValues(
                "x-bke-account-session-version",
                out var values) &&
            values.SingleOrDefault() ==
                AccountSessionRemote.ProtocolVersion;
        SawPost =
            request.Method == HttpMethod.Post &&
            request.RequestUri?.AbsolutePath ==
                "/api/agent-sessions/account/organization/ownership/transfer";

        var body = request.Content is null
            ? string.Empty
            : await request.Content.ReadAsStringAsync(
                cancellationToken);
        using var document =
            System.Text.Json.JsonDocument.Parse(body);
        var root = document.RootElement;
        BodyMatchedIntent =
            root.GetProperty("management_handle").GetString() ==
                "bke-org-member-v1_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" &&
            root.EnumerateObject().Count() == 1;
        BodyExcludedAuthorityIds =
            !body.Contains("account_id", StringComparison.OrdinalIgnoreCase) &&
            !body.Contains("user_id", StringComparison.OrdinalIgnoreCase) &&
            !body.Contains("member_id", StringComparison.OrdinalIgnoreCase) &&
            !body.Contains("membership_id", StringComparison.OrdinalIgnoreCase) &&
            !body.Contains("owner_id", StringComparison.OrdinalIgnoreCase);

        var response = new HttpResponseMessage(statusCode)
        {
            Content = new StringContent(
                json,
                Encoding.UTF8,
                "application/json"),
        };
        response.Headers.TryAddWithoutValidation(
            "x-bke-account-session-version",
            AccountSessionRemote.ProtocolVersion);
        return response;
    }
}


sealed class OrganizationLeaveTransportHandler(
    HttpStatusCode statusCode,
    string json) : HttpMessageHandler
{
    public int RequestCount { get; private set; }
    public bool SawBearer { get; private set; }
    public bool SawProtocol { get; private set; }
    public bool SawPost { get; private set; }
    public bool BodyWasEmptyObject { get; private set; }
    public bool BodyExcludedAuthorityIds { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        RequestCount++;
        SawBearer =
            request.Headers.Authorization?.Scheme == "Bearer" &&
            request.Headers.Authorization.Parameter ==
                "organization-transport-secret";
        SawProtocol =
            request.Headers.TryGetValues(
                "x-bke-account-session-version",
                out var values) &&
            values.SingleOrDefault() ==
                AccountSessionRemote.ProtocolVersion;
        SawPost =
            request.Method == HttpMethod.Post &&
            request.RequestUri?.AbsolutePath ==
                "/api/agent-sessions/account/organization/leave";

        var body = request.Content is null
            ? string.Empty
            : await request.Content.ReadAsStringAsync(
                cancellationToken);
        BodyWasEmptyObject = body.Trim() == "{}";
        BodyExcludedAuthorityIds =
            !body.Contains("account_id", StringComparison.OrdinalIgnoreCase) &&
            !body.Contains("user_id", StringComparison.OrdinalIgnoreCase) &&
            !body.Contains("member_id", StringComparison.OrdinalIgnoreCase) &&
            !body.Contains("membership_id", StringComparison.OrdinalIgnoreCase) &&
            !body.Contains("owner_id", StringComparison.OrdinalIgnoreCase) &&
            !body.Contains("management_handle", StringComparison.OrdinalIgnoreCase);

        var response = new HttpResponseMessage(statusCode)
        {
            Content = new StringContent(
                json,
                Encoding.UTF8,
                "application/json"),
        };
        response.Headers.TryAddWithoutValidation(
            "x-bke-account-session-version",
            AccountSessionRemote.ProtocolVersion);
        return response;
    }
}
