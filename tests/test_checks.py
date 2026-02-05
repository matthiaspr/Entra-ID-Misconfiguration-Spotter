"""Tests for all checks."""

from unittest.mock import AsyncMock

import pytest

from entra_spotter.checks.user_consent import check_user_consent
from entra_spotter.checks.admin_consent_workflow import check_admin_consent_workflow
from entra_spotter.checks.sp_admin_roles import check_sp_admin_roles
from entra_spotter.checks.sp_graph_roles import check_sp_graph_roles
from entra_spotter.checks.legacy_auth_blocked import check_legacy_auth_blocked
from entra_spotter.checks.device_code_blocked import check_device_code_blocked
from entra_spotter.checks.privileged_roles_mfa import check_privileged_roles_mfa, PRIVILEGED_ROLES
from entra_spotter.checks.global_admin_count import check_global_admin_count, GLOBAL_ADMIN_ROLE_ID
from entra_spotter.checks.guest_invite_policy import check_guest_invite_policy

from conftest import (
    MockAuthorizationPolicy,
    MockAdminConsentRequestPolicy,
    MockReviewerScope,
    MockUser,
    MockGroup,
    MockGroupMembersResponse,
    MockDirectoryRoleInfo,
    MockRoleDefinition,
    MockRoleMember,
    MockRoleAssignment,
    MockRoleAssignmentsResponse,
    MockAppRoleAssignment,
    MockServicePrincipal,
    MockServicePrincipalsResponse,
    MockCAGrantControls,
    MockCAUsers,
    MockCAApplications,
    MockCAAuthenticationFlows,
    MockCAConditions,
    MockConditionalAccessPolicy,
    MockCAPoliciesResponse,
)


class TestUserConsent:
    """Tests for user consent check."""

    async def test_pass_when_no_policies_assigned(self, mock_graph_client):
        """Should pass when no consent policies are assigned."""
        mock_graph_client.policies.authorization_policy.get.return_value = (
            MockAuthorizationPolicy(permission_grant_policies_assigned=[])
        )

        result = await check_user_consent(mock_graph_client)

        assert result.status == "pass"
        assert result.check_id == "user-consent"

    async def test_pass_when_policies_is_none(self, mock_graph_client):
        """Should pass when policies field is None."""
        mock_graph_client.policies.authorization_policy.get.return_value = (
            MockAuthorizationPolicy(permission_grant_policies_assigned=None)
        )

        result = await check_user_consent(mock_graph_client)

        assert result.status == "pass"

    async def test_pass_when_only_disabled_policy(self, mock_graph_client):
        """Should pass when only the 'Do not allow' policy is assigned."""
        mock_graph_client.policies.authorization_policy.get.return_value = (
            MockAuthorizationPolicy(
                permission_grant_policies_assigned=[
                    "ManagePermissionGrantsForSelf.microsoft-user-default-recommended"
                ]
            )
        )

        result = await check_user_consent(mock_graph_client)

        assert result.status == "pass"
        assert result.check_id == "user-consent"
        assert "cannot consent" in result.message

    async def test_pass_when_only_owned_resource_policy(self, mock_graph_client):
        """Should pass when only developer consent for owned resources is assigned."""
        mock_graph_client.policies.authorization_policy.get.return_value = (
            MockAuthorizationPolicy(
                permission_grant_policies_assigned=[
                    "ManagePermissionGrantsForOwnedResource.DeveloperConsent"
                ]
            )
        )

        result = await check_user_consent(mock_graph_client)

        assert result.status == "pass"
        assert result.check_id == "user-consent"

    async def test_fail_when_legacy_policy(self, mock_graph_client):
        """Should fail when legacy 'allow all apps' policy is assigned."""
        mock_graph_client.policies.authorization_policy.get.return_value = (
            MockAuthorizationPolicy(
                permission_grant_policies_assigned=[
                    "ManagePermissionGrantsForSelf.microsoft-user-default-legacy"
                ]
            )
        )

        result = await check_user_consent(mock_graph_client)

        assert result.status == "fail"
        assert result.check_id == "user-consent"
        assert "all apps" in result.message
        assert result.recommendation is not None
        assert "permission_grant_policies_assigned" in result.details

    async def test_fail_when_low_policy(self, mock_graph_client):
        """Should fail when 'verified publishers' policy is assigned."""
        mock_graph_client.policies.authorization_policy.get.return_value = (
            MockAuthorizationPolicy(
                permission_grant_policies_assigned=[
                    "ManagePermissionGrantsForSelf.microsoft-user-default-low"
                ]
            )
        )

        result = await check_user_consent(mock_graph_client)

        assert result.status == "fail"
        assert result.check_id == "user-consent"
        assert "verified publishers" in result.message

    async def test_warning_when_custom_policy(self, mock_graph_client):
        """Should warn when custom user consent policy is assigned."""
        mock_graph_client.policies.authorization_policy.get.return_value = (
            MockAuthorizationPolicy(
                permission_grant_policies_assigned=[
                    "ManagePermissionGrantsForSelf.my-custom-policy"
                ]
            )
        )

        result = await check_user_consent(mock_graph_client)

        assert result.status == "warning"
        assert result.check_id == "user-consent"
        assert "custom" in result.message.lower()
        assert "custom_policies" in result.details


class TestAdminConsentWorkflow:
    """Tests for admin consent workflow check."""

    async def test_pass_with_user_reviewer_resolved(self, mock_graph_client):
        """Should pass and show user UPN when resolved."""
        user_id = "906e0ee5-6372-4cc8-8248-fdf2846b48ed"
        mock_graph_client.policies.admin_consent_request_policy.get.return_value = (
            MockAdminConsentRequestPolicy(
                is_enabled=True,
                reviewers=[MockReviewerScope(f"/users/{user_id}")]
            )
        )
        mock_graph_client.users.by_user_id.return_value.get.return_value = (
            MockUser(id=user_id, user_principal_name="john.doe@contoso.com")
        )

        result = await check_admin_consent_workflow(mock_graph_client)

        assert result.status == "pass"
        assert result.check_id == "admin-consent-workflow"
        assert "1 reviewer(s)" in result.message
        assert "john.doe@contoso.com" in result.message
        assert result.details["reviewers"][0]["type"] == "user"
        assert result.details["reviewers"][0]["display_name"] == "john.doe@contoso.com"

    async def test_pass_with_group_reviewer_resolved(self, mock_graph_client):
        """Should pass and show group display name when resolved."""
        group_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        mock_graph_client.policies.admin_consent_request_policy.get.return_value = (
            MockAdminConsentRequestPolicy(
                is_enabled=True,
                reviewers=[MockReviewerScope(f"/groups/{group_id}")]
            )
        )
        mock_graph_client.groups.by_group_id.return_value.get.return_value = (
            MockGroup(id=group_id, display_name="IT Admins")
        )

        result = await check_admin_consent_workflow(mock_graph_client)

        assert result.status == "pass"
        assert "IT Admins" in result.message
        assert result.details["reviewers"][0]["type"] == "group"
        assert result.details["reviewers"][0]["display_name"] == "IT Admins"

    async def test_pass_with_role_reviewer_resolved(self, mock_graph_client):
        """Should pass and show role display name when resolved."""
        role_id = "b2c3d4e5-f6a7-8901-bcde-f23456789012"
        mock_graph_client.policies.admin_consent_request_policy.get.return_value = (
            MockAdminConsentRequestPolicy(
                is_enabled=True,
                reviewers=[MockReviewerScope(f"/directoryRoles/{role_id}")]
            )
        )
        mock_graph_client.directory_roles.by_directory_role_id.return_value.get.return_value = (
            MockDirectoryRoleInfo(id=role_id, display_name="Global Administrator")
        )

        result = await check_admin_consent_workflow(mock_graph_client)

        assert result.status == "pass"
        assert "Global Administrator" in result.message
        assert result.details["reviewers"][0]["type"] == "role"
        assert result.details["reviewers"][0]["display_name"] == "Global Administrator"

    async def test_pass_with_multiple_reviewers(self, mock_graph_client):
        """Should pass and show all reviewer names."""
        user_id = "user-123"
        group_id = "group-456"
        mock_graph_client.policies.admin_consent_request_policy.get.return_value = (
            MockAdminConsentRequestPolicy(
                is_enabled=True,
                reviewers=[
                    MockReviewerScope(f"/users/{user_id}"),
                    MockReviewerScope(f"/groups/{group_id}"),
                ]
            )
        )
        mock_graph_client.users.by_user_id.return_value.get.return_value = (
            MockUser(id=user_id, user_principal_name="alice@contoso.com")
        )
        mock_graph_client.groups.by_group_id.return_value.get.return_value = (
            MockGroup(id=group_id, display_name="Security Team")
        )

        result = await check_admin_consent_workflow(mock_graph_client)

        assert result.status == "pass"
        assert "2 reviewer(s)" in result.message
        assert "alice@contoso.com" in result.message
        assert "Security Team" in result.message
        assert len(result.details["reviewers"]) == 2

    async def test_pass_with_unresolvable_reviewer(self, mock_graph_client):
        """Should pass and show ID when reviewer cannot be resolved."""
        user_id = "deleted-user-id"
        mock_graph_client.policies.admin_consent_request_policy.get.return_value = (
            MockAdminConsentRequestPolicy(
                is_enabled=True,
                reviewers=[MockReviewerScope(f"/users/{user_id}")]
            )
        )
        mock_graph_client.users.by_user_id.return_value.get.side_effect = Exception("Not found")

        result = await check_admin_consent_workflow(mock_graph_client)

        assert result.status == "pass"
        assert "1 reviewer(s)" in result.message
        assert f"user: {user_id}" in result.message
        assert result.details["reviewers"][0]["display_name"] is None

    async def test_pass_with_version_prefixed_user_path(self, mock_graph_client):
        """Should handle /v1.0/ prefix in user paths."""
        user_id = "e1cbc750-722a-4d8a-95d1-f2c7203faeaf"
        mock_graph_client.policies.admin_consent_request_policy.get.return_value = (
            MockAdminConsentRequestPolicy(
                is_enabled=True,
                reviewers=[MockReviewerScope(f"/v1.0/users/{user_id}")]
            )
        )
        mock_graph_client.users.by_user_id.return_value.get.return_value = (
            MockUser(id=user_id, user_principal_name="jane.smith@contoso.com")
        )

        result = await check_admin_consent_workflow(mock_graph_client)

        assert result.status == "pass"
        assert "jane.smith@contoso.com" in result.message
        assert result.details["reviewers"][0]["type"] == "user"
        assert result.details["reviewers"][0]["display_name"] == "jane.smith@contoso.com"

    async def test_pass_with_role_assignment_query(self, mock_graph_client):
        """Should resolve role definition ID from role assignment filter query."""
        role_def_id = "62e90394-69f5-4237-9190-012177145e10"  # Global Administrator
        query = f"/beta/roleManagement/directory/roleAssignments?$filter=roleDefinitionId eq '{role_def_id}'"
        mock_graph_client.policies.admin_consent_request_policy.get.return_value = (
            MockAdminConsentRequestPolicy(
                is_enabled=True,
                reviewers=[MockReviewerScope(query)]
            )
        )
        mock_graph_client.role_management.directory.role_definitions.by_unified_role_definition_id.return_value.get.return_value = (
            MockRoleDefinition(id=role_def_id, display_name="Global Administrator")
        )

        result = await check_admin_consent_workflow(mock_graph_client)

        assert result.status == "pass"
        assert "Users with Global Administrator role" in result.message
        assert result.details["reviewers"][0]["type"] == "role"

    async def test_pass_with_mixed_reviewer_formats(self, mock_graph_client):
        """Should handle mix of version-prefixed paths and role assignment queries."""
        user_id = "e1cbc750-722a-4d8a-95d1-f2c7203faeaf"
        role_def_id = "62e90394-69f5-4237-9190-012177145e10"
        mock_graph_client.policies.admin_consent_request_policy.get.return_value = (
            MockAdminConsentRequestPolicy(
                is_enabled=True,
                reviewers=[
                    MockReviewerScope(f"/v1.0/users/{user_id}"),
                    MockReviewerScope(
                        f"/beta/roleManagement/directory/roleAssignments?$filter=roleDefinitionId eq '{role_def_id}'"
                    ),
                ]
            )
        )
        mock_graph_client.users.by_user_id.return_value.get.return_value = (
            MockUser(id=user_id, user_principal_name="jane.smith@contoso.com")
        )
        mock_graph_client.role_management.directory.role_definitions.by_unified_role_definition_id.return_value.get.return_value = (
            MockRoleDefinition(id=role_def_id, display_name="Global Administrator")
        )

        result = await check_admin_consent_workflow(mock_graph_client)

        assert result.status == "pass"
        assert "2 reviewer(s)" in result.message
        assert "jane.smith@contoso.com" in result.message
        assert "Users with Global Administrator role" in result.message

    async def test_fail_when_disabled(self, mock_graph_client):
        """Should fail when workflow is disabled."""
        mock_graph_client.policies.admin_consent_request_policy.get.return_value = (
            MockAdminConsentRequestPolicy(is_enabled=False, reviewers=[])
        )

        result = await check_admin_consent_workflow(mock_graph_client)

        assert result.status == "fail"
        assert result.check_id == "admin-consent-workflow"
        assert result.recommendation is not None

    async def test_warning_when_enabled_but_no_reviewers(self, mock_graph_client):
        """Should warn when workflow is enabled but has no reviewers."""
        mock_graph_client.policies.admin_consent_request_policy.get.return_value = (
            MockAdminConsentRequestPolicy(is_enabled=True, reviewers=[])
        )

        result = await check_admin_consent_workflow(mock_graph_client)

        assert result.status == "warning"
        assert result.check_id == "admin-consent-workflow"
        assert result.recommendation is not None

    async def test_warning_when_enabled_but_reviewers_is_none(self, mock_graph_client):
        """Should warn when workflow is enabled but reviewers is None."""
        mock_graph_client.policies.admin_consent_request_policy.get.return_value = (
            MockAdminConsentRequestPolicy(is_enabled=True, reviewers=None)
        )

        result = await check_admin_consent_workflow(mock_graph_client)

        assert result.status == "warning"


class TestServicePrincipalAdminRoles:
    """Tests for service principal admin roles check."""

    async def test_pass_when_no_privileged_roles(self, mock_graph_client):
        """Should pass when no role assignments for privileged roles exist."""
        # Return only non-privileged role assignments
        mock_graph_client.role_management.directory.role_assignments.get.return_value = (
            MockRoleAssignmentsResponse([
                MockRoleAssignment(
                    role_definition_id="some-other-role-id",
                    principal_id="user-1",
                    principal=MockRoleMember("user-1", "John Doe", "#microsoft.graph.user"),
                )
            ])
        )

        result = await check_sp_admin_roles(mock_graph_client)

        assert result.status == "pass"
        assert result.check_id == "sp-admin-roles"

    async def test_pass_when_privileged_role_has_only_users(self, mock_graph_client):
        """Should pass when privileged roles have only user members."""
        # Global Administrator with only user members
        mock_graph_client.role_management.directory.role_assignments.get.return_value = (
            MockRoleAssignmentsResponse([
                MockRoleAssignment(
                    role_definition_id="62e90394-69f5-4237-9190-012177145e10",
                    principal_id="user-1",
                    principal=MockRoleMember("user-1", "John Doe", "#microsoft.graph.user"),
                )
            ])
        )

        result = await check_sp_admin_roles(mock_graph_client)

        assert result.status == "pass"

    async def test_warning_when_sp_in_global_admin(self, mock_graph_client):
        """Should warn when a service principal is in Global Administrator role."""
        mock_graph_client.role_management.directory.role_assignments.get.return_value = (
            MockRoleAssignmentsResponse([
                MockRoleAssignment(
                    role_definition_id="62e90394-69f5-4237-9190-012177145e10",
                    principal_id="sp-1",
                    principal=MockRoleMember(
                        "sp-1", "My Service Principal", "#microsoft.graph.servicePrincipal"
                    ),
                )
            ])
        )

        result = await check_sp_admin_roles(mock_graph_client)

        assert result.status == "warning"
        assert result.check_id == "sp-admin-roles"
        assert result.recommendation is not None
        assert len(result.details["service_principals"]) == 1
        assert result.details["service_principals"][0]["display_name"] == "My Service Principal"
        assert result.details["service_principals"][0]["role"] == "Global Administrator"

    async def test_warning_with_multiple_sps_in_multiple_roles(self, mock_graph_client):
        """Should warn and list all service principals in privileged roles."""
        mock_graph_client.role_management.directory.role_assignments.get.return_value = (
            MockRoleAssignmentsResponse([
                MockRoleAssignment(
                    role_definition_id="62e90394-69f5-4237-9190-012177145e10",
                    principal_id="sp-1",
                    principal=MockRoleMember(
                        "sp-1", "SP One", "#microsoft.graph.servicePrincipal"
                    ),
                ),
                MockRoleAssignment(
                    role_definition_id="9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
                    principal_id="sp-2",
                    principal=MockRoleMember(
                        "sp-2", "SP Two", "#microsoft.graph.servicePrincipal"
                    ),
                ),
            ])
        )

        result = await check_sp_admin_roles(mock_graph_client)

        assert result.status == "warning"
        assert len(result.details["service_principals"]) == 2

    async def test_pass_when_no_assignments_exist(self, mock_graph_client):
        """Should pass when no role assignments exist."""
        mock_graph_client.role_management.directory.role_assignments.get.return_value = (
            MockRoleAssignmentsResponse([])
        )

        result = await check_sp_admin_roles(mock_graph_client)

        assert result.status == "pass"

    async def test_handles_none_principal(self, mock_graph_client):
        """Should handle role assignments where principal is None."""
        mock_graph_client.role_management.directory.role_assignments.get.return_value = (
            MockRoleAssignmentsResponse([
                MockRoleAssignment(
                    role_definition_id="62e90394-69f5-4237-9190-012177145e10",
                    principal_id="sp-1",
                    principal=None,
                )
            ])
        )

        result = await check_sp_admin_roles(mock_graph_client)

        assert result.status == "pass"


class TestServicePrincipalGraphRoles:
    """Tests for service principal MS Graph app roles check."""

    async def test_pass_when_no_service_principals(self, mock_graph_client):
        """Should pass when no service principals exist."""
        mock_graph_client.service_principals.get.return_value = MockServicePrincipalsResponse([])

        result = await check_sp_graph_roles(mock_graph_client)

        assert result.status == "pass"
        assert result.check_id == "sp-graph-roles"

    async def test_pass_when_no_sensitive_roles(self, mock_graph_client):
        """Should pass when SPs have no sensitive app roles."""
        mock_graph_client.service_principals.get.return_value = MockServicePrincipalsResponse([
            MockServicePrincipal(
                id="sp-1",
                display_name="Safe App",
                app_role_assignments=[
                    MockAppRoleAssignment(app_role_id="some-harmless-role-id"),
                ],
            )
        ])

        result = await check_sp_graph_roles(mock_graph_client)

        assert result.status == "pass"

    async def test_pass_when_no_app_role_assignments(self, mock_graph_client):
        """Should pass when SPs have no app role assignments."""
        mock_graph_client.service_principals.get.return_value = MockServicePrincipalsResponse([
            MockServicePrincipal(
                id="sp-1",
                display_name="App Without Roles",
                app_role_assignments=None,
            )
        ])

        result = await check_sp_graph_roles(mock_graph_client)

        assert result.status == "pass"

    async def test_warning_when_sp_has_role_management_role(self, mock_graph_client):
        """Should warn when SP has RoleManagement.ReadWrite.Directory."""
        mock_graph_client.service_principals.get.return_value = MockServicePrincipalsResponse([
            MockServicePrincipal(
                id="sp-1",
                display_name="Privileged App",
                app_role_assignments=[
                    MockAppRoleAssignment(
                        app_role_id="9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8",  # RoleManagement.ReadWrite.Directory
                    ),
                ],
            )
        ])

        result = await check_sp_graph_roles(mock_graph_client)

        assert result.status == "warning"
        assert result.check_id == "sp-graph-roles"
        assert len(result.details["service_principals"]) == 1
        assert result.details["service_principals"][0]["app_role"] == "RoleManagement.ReadWrite.Directory"

    async def test_warning_when_sp_has_app_role_assignment_role(self, mock_graph_client):
        """Should warn when SP has AppRoleAssignment.ReadWrite.All."""
        mock_graph_client.service_principals.get.return_value = MockServicePrincipalsResponse([
            MockServicePrincipal(
                id="sp-1",
                display_name="Another Privileged App",
                app_role_assignments=[
                    MockAppRoleAssignment(
                        app_role_id="06b708a9-e830-4db3-a914-8e69da51d44f",  # AppRoleAssignment.ReadWrite.All
                    ),
                ],
            )
        ])

        result = await check_sp_graph_roles(mock_graph_client)

        assert result.status == "warning"
        assert result.details["service_principals"][0]["app_role"] == "AppRoleAssignment.ReadWrite.All"

    async def test_warning_when_sp_has_user_auth_method_role(self, mock_graph_client):
        """Should warn when SP has UserAuthenticationMethod.ReadWrite.All."""
        mock_graph_client.service_principals.get.return_value = MockServicePrincipalsResponse([
            MockServicePrincipal(
                id="sp-1",
                display_name="Auth Method App",
                app_role_assignments=[
                    MockAppRoleAssignment(
                        app_role_id="50483e42-d915-4231-9639-7fdb7fd190e5",  # UserAuthenticationMethod.ReadWrite.All
                    ),
                ],
            )
        ])

        result = await check_sp_graph_roles(mock_graph_client)

        assert result.status == "warning"
        assert result.details["service_principals"][0]["app_role"] == "UserAuthenticationMethod.ReadWrite.All"

    async def test_warning_with_multiple_sps_and_roles(self, mock_graph_client):
        """Should warn and list all SPs with sensitive roles."""
        mock_graph_client.service_principals.get.return_value = MockServicePrincipalsResponse([
            MockServicePrincipal(
                id="sp-1",
                display_name="App One",
                app_role_assignments=[
                    MockAppRoleAssignment(app_role_id="9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"),
                ],
            ),
            MockServicePrincipal(
                id="sp-2",
                display_name="App Two",
                app_role_assignments=[
                    MockAppRoleAssignment(app_role_id="06b708a9-e830-4db3-a914-8e69da51d44f"),
                ],
            ),
        ])

        result = await check_sp_graph_roles(mock_graph_client)

        assert result.status == "warning"
        assert len(result.details["service_principals"]) == 2
        assert "2 service principal(s)" in result.message


class TestLegacyAuthBlocked:
    """Tests for legacy authentication blocking check."""

    def _create_blocking_policy(
        self,
        policy_id: str = "policy-1",
        name: str = "Block Legacy Auth",
        state: str = "enabled",
        exclude_users: list[str] | None = None,
        exclude_groups: list[str] | None = None,
        exclude_roles: list[str] | None = None,
        exclude_applications: list[str] | None = None,
    ) -> MockConditionalAccessPolicy:
        """Helper to create a valid legacy auth blocking policy."""
        return MockConditionalAccessPolicy(
            id=policy_id,
            display_name=name,
            state=state,
            conditions=MockCAConditions(
                client_app_types=["exchangeActiveSync", "other"],
                users=MockCAUsers(
                    include_users=["All"],
                    exclude_users=exclude_users,
                    exclude_groups=exclude_groups,
                    exclude_roles=exclude_roles,
                ),
                applications=MockCAApplications(
                    include_applications=["All"],
                    exclude_applications=exclude_applications,
                ),
            ),
            grant_controls=MockCAGrantControls(built_in_controls=["block"]),
        )

    async def test_pass_when_enforced_policy_exists_no_exclusions(self, mock_graph_client):
        """Should pass when an enforced policy blocks legacy auth without exclusions."""
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([self._create_blocking_policy()])
        )

        result = await check_legacy_auth_blocked(mock_graph_client)

        assert result.status == "pass"
        assert result.check_id == "legacy-auth-blocked"
        assert "1 policy(ies) block legacy authentication" in result.message

    async def test_fail_when_no_policies_exist(self, mock_graph_client):
        """Should fail when no CA policies exist."""
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([])
        )

        result = await check_legacy_auth_blocked(mock_graph_client)

        assert result.status == "fail"
        assert result.check_id == "legacy-auth-blocked"
        assert result.recommendation is not None

    async def test_fail_when_no_blocking_policies_exist(self, mock_graph_client):
        """Should fail when policies exist but none block legacy auth."""
        # Policy that doesn't block legacy auth (wrong client types)
        policy = MockConditionalAccessPolicy(
            id="policy-1",
            display_name="Some Other Policy",
            state="enabled",
            conditions=MockCAConditions(
                client_app_types=["browser", "mobileAppsAndDesktopClients"],
                applications=MockCAApplications(include_applications=["All"]),
            ),
            grant_controls=MockCAGrantControls(built_in_controls=["mfa"]),
        )
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([policy])
        )

        result = await check_legacy_auth_blocked(mock_graph_client)

        assert result.status == "fail"

    async def test_warning_when_only_report_only_policy_exists(self, mock_graph_client):
        """Should warn when only report-only policies exist."""
        policy = self._create_blocking_policy(
            state="enabledForReportingButNotEnforced"
        )
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([policy])
        )

        result = await check_legacy_auth_blocked(mock_graph_client)

        assert result.status == "warning"
        assert "report-only" in result.message
        assert len(result.details["report_only_policies"]) == 1
        assert len(result.details["enforced_policies"]) == 0

    async def test_warning_when_policy_has_user_exclusions(self, mock_graph_client):
        """Should warn when policy has user exclusions."""
        policy = self._create_blocking_policy(
            exclude_users=["user-id-1", "user-id-2"]
        )
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([policy])
        )

        result = await check_legacy_auth_blocked(mock_graph_client)

        assert result.status == "warning"
        assert "exclusions" in result.message
        assert result.details["enforced_policies"][0]["exclusions"]["users"] == [
            "user-id-1",
            "user-id-2",
        ]

    async def test_warning_when_policy_has_group_exclusions(self, mock_graph_client):
        """Should warn when policy has group exclusions."""
        policy = self._create_blocking_policy(exclude_groups=["group-id-1"])
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([policy])
        )

        result = await check_legacy_auth_blocked(mock_graph_client)

        assert result.status == "warning"
        assert result.details["enforced_policies"][0]["exclusions"]["groups"] == [
            "group-id-1"
        ]

    async def test_warning_when_policy_has_application_exclusions(self, mock_graph_client):
        """Should warn when policy has application exclusions."""
        policy = self._create_blocking_policy(exclude_applications=["app-id-1"])
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([policy])
        )

        result = await check_legacy_auth_blocked(mock_graph_client)

        assert result.status == "warning"
        assert result.details["enforced_policies"][0]["exclusions"]["applications"] == [
            "app-id-1"
        ]

    async def test_fail_when_policy_missing_other_client_type(self, mock_graph_client):
        """Should fail when policy only blocks exchangeActiveSync but not other."""
        policy = MockConditionalAccessPolicy(
            id="policy-1",
            display_name="Partial Block",
            state="enabled",
            conditions=MockCAConditions(
                client_app_types=["exchangeActiveSync"],  # Missing "other"
                applications=MockCAApplications(include_applications=["All"]),
            ),
            grant_controls=MockCAGrantControls(built_in_controls=["block"]),
        )
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([policy])
        )

        result = await check_legacy_auth_blocked(mock_graph_client)

        assert result.status == "fail"

    async def test_fail_when_policy_not_targeting_all_apps(self, mock_graph_client):
        """Should fail when policy doesn't target all applications."""
        policy = MockConditionalAccessPolicy(
            id="policy-1",
            display_name="Limited Block",
            state="enabled",
            conditions=MockCAConditions(
                client_app_types=["exchangeActiveSync", "other"],
                applications=MockCAApplications(
                    include_applications=["specific-app-id"]  # Not "All"
                ),
            ),
            grant_controls=MockCAGrantControls(built_in_controls=["block"]),
        )
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([policy])
        )

        result = await check_legacy_auth_blocked(mock_graph_client)

        assert result.status == "fail"

    async def test_pass_with_multiple_enforced_policies(self, mock_graph_client):
        """Should pass and report multiple enforced policies."""
        policies = [
            self._create_blocking_policy(policy_id="p1", name="Policy 1"),
            self._create_blocking_policy(policy_id="p2", name="Policy 2"),
        ]
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse(policies)
        )

        result = await check_legacy_auth_blocked(mock_graph_client)

        assert result.status == "pass"
        assert "2 policy(ies)" in result.message
        assert len(result.details["enforced_policies"]) == 2

    async def test_disabled_policy_is_ignored(self, mock_graph_client):
        """Should ignore disabled policies."""
        policy = self._create_blocking_policy(state="disabled")
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([policy])
        )

        result = await check_legacy_auth_blocked(mock_graph_client)

        assert result.status == "fail"


class TestDeviceCodeBlocked:
    """Tests for device code flow blocking check."""

    def _create_blocking_policy(
        self,
        policy_id: str = "policy-1",
        name: str = "Block Device Code Flow",
        state: str = "enabled",
        exclude_users: list[str] | None = None,
        exclude_groups: list[str] | None = None,
        exclude_roles: list[str] | None = None,
        exclude_applications: list[str] | None = None,
    ) -> MockConditionalAccessPolicy:
        """Helper to create a valid device code flow blocking policy."""
        return MockConditionalAccessPolicy(
            id=policy_id,
            display_name=name,
            state=state,
            conditions=MockCAConditions(
                authentication_flows=MockCAAuthenticationFlows(
                    transfer_methods=["deviceCodeFlow"]
                ),
                users=MockCAUsers(
                    include_users=["All"],
                    exclude_users=exclude_users,
                    exclude_groups=exclude_groups,
                    exclude_roles=exclude_roles,
                ),
                applications=MockCAApplications(
                    include_applications=["All"],
                    exclude_applications=exclude_applications,
                ),
            ),
            grant_controls=MockCAGrantControls(built_in_controls=["block"]),
        )

    async def test_pass_when_enforced_policy_exists_no_exclusions(self, mock_graph_client):
        """Should pass when an enforced policy blocks device code flow without exclusions."""
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([self._create_blocking_policy()])
        )

        result = await check_device_code_blocked(mock_graph_client)

        assert result.status == "pass"
        assert result.check_id == "device-code-blocked"
        assert "1 policy(ies) block device code flow" in result.message

    async def test_fail_when_no_policies_exist(self, mock_graph_client):
        """Should fail when no CA policies exist."""
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([])
        )

        result = await check_device_code_blocked(mock_graph_client)

        assert result.status == "fail"
        assert result.check_id == "device-code-blocked"
        assert result.recommendation is not None

    async def test_fail_when_no_blocking_policies_exist(self, mock_graph_client):
        """Should fail when policies exist but none block device code flow."""
        # Policy that doesn't block device code flow (no auth flows condition)
        policy = MockConditionalAccessPolicy(
            id="policy-1",
            display_name="Some Other Policy",
            state="enabled",
            conditions=MockCAConditions(
                applications=MockCAApplications(include_applications=["All"]),
            ),
            grant_controls=MockCAGrantControls(built_in_controls=["mfa"]),
        )
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([policy])
        )

        result = await check_device_code_blocked(mock_graph_client)

        assert result.status == "fail"

    async def test_warning_when_only_report_only_policy_exists(self, mock_graph_client):
        """Should warn when only report-only policies exist."""
        policy = self._create_blocking_policy(
            state="enabledForReportingButNotEnforced"
        )
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([policy])
        )

        result = await check_device_code_blocked(mock_graph_client)

        assert result.status == "warning"
        assert "report-only" in result.message
        assert len(result.details["report_only_policies"]) == 1
        assert len(result.details["enforced_policies"]) == 0

    async def test_warning_when_policy_has_user_exclusions(self, mock_graph_client):
        """Should warn when policy has user exclusions."""
        policy = self._create_blocking_policy(
            exclude_users=["user-id-1", "user-id-2"]
        )
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([policy])
        )

        result = await check_device_code_blocked(mock_graph_client)

        assert result.status == "warning"
        assert "exclusions" in result.message
        assert result.details["enforced_policies"][0]["exclusions"]["users"] == [
            "user-id-1",
            "user-id-2",
        ]

    async def test_warning_when_policy_has_group_exclusions(self, mock_graph_client):
        """Should warn when policy has group exclusions."""
        policy = self._create_blocking_policy(exclude_groups=["group-id-1"])
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([policy])
        )

        result = await check_device_code_blocked(mock_graph_client)

        assert result.status == "warning"
        assert result.details["enforced_policies"][0]["exclusions"]["groups"] == [
            "group-id-1"
        ]

    async def test_fail_when_policy_not_targeting_all_apps(self, mock_graph_client):
        """Should fail when policy doesn't target all applications."""
        policy = MockConditionalAccessPolicy(
            id="policy-1",
            display_name="Limited Block",
            state="enabled",
            conditions=MockCAConditions(
                authentication_flows=MockCAAuthenticationFlows(
                    transfer_methods=["deviceCodeFlow"]
                ),
                applications=MockCAApplications(
                    include_applications=["specific-app-id"]  # Not "All"
                ),
            ),
            grant_controls=MockCAGrantControls(built_in_controls=["block"]),
        )
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([policy])
        )

        result = await check_device_code_blocked(mock_graph_client)

        assert result.status == "fail"

    async def test_fail_when_policy_has_wrong_transfer_method(self, mock_graph_client):
        """Should fail when policy targets different transfer method."""
        policy = MockConditionalAccessPolicy(
            id="policy-1",
            display_name="Wrong Method",
            state="enabled",
            conditions=MockCAConditions(
                authentication_flows=MockCAAuthenticationFlows(
                    transfer_methods=["authenticationTransfer"]  # Not deviceCodeFlow
                ),
                applications=MockCAApplications(include_applications=["All"]),
            ),
            grant_controls=MockCAGrantControls(built_in_controls=["block"]),
        )
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([policy])
        )

        result = await check_device_code_blocked(mock_graph_client)

        assert result.status == "fail"

    async def test_pass_with_multiple_enforced_policies(self, mock_graph_client):
        """Should pass and report multiple enforced policies."""
        policies = [
            self._create_blocking_policy(policy_id="p1", name="Policy 1"),
            self._create_blocking_policy(policy_id="p2", name="Policy 2"),
        ]
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse(policies)
        )

        result = await check_device_code_blocked(mock_graph_client)

        assert result.status == "pass"
        assert "2 policy(ies)" in result.message
        assert len(result.details["enforced_policies"]) == 2

    async def test_disabled_policy_is_ignored(self, mock_graph_client):
        """Should ignore disabled policies."""
        policy = self._create_blocking_policy(state="disabled")
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([policy])
        )

        result = await check_device_code_blocked(mock_graph_client)

        assert result.status == "fail"


class TestPrivilegedRolesMfa:
    """Tests for MFA for privileged roles check."""

    # All 14 privileged role IDs
    ALL_ROLE_IDS = list(PRIVILEGED_ROLES.keys())

    def _create_mfa_policy(
        self,
        policy_id: str = "policy-1",
        name: str = "MFA for Admins",
        state: str = "enabled",
        include_roles: list[str] | None = None,
        exclude_users: list[str] | None = None,
        exclude_groups: list[str] | None = None,
        exclude_roles: list[str] | None = None,
        exclude_applications: list[str] | None = None,
    ) -> MockConditionalAccessPolicy:
        """Helper to create a valid MFA policy for roles."""
        return MockConditionalAccessPolicy(
            id=policy_id,
            display_name=name,
            state=state,
            conditions=MockCAConditions(
                users=MockCAUsers(
                    include_roles=include_roles or self.ALL_ROLE_IDS,
                    exclude_users=exclude_users,
                    exclude_groups=exclude_groups,
                    exclude_roles=exclude_roles,
                ),
                applications=MockCAApplications(
                    include_applications=["All"],
                    exclude_applications=exclude_applications,
                ),
            ),
            grant_controls=MockCAGrantControls(built_in_controls=["mfa"]),
        )

    async def test_pass_when_all_roles_covered_no_exclusions(self, mock_graph_client):
        """Should pass when all privileged roles are covered by MFA with no exclusions."""
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([self._create_mfa_policy()])
        )

        result = await check_privileged_roles_mfa(mock_graph_client)

        assert result.status == "pass"
        assert result.check_id == "privileged-roles-mfa"
        assert "All 14 privileged roles require MFA" in result.message

    async def test_fail_when_no_policies_exist(self, mock_graph_client):
        """Should fail when no CA policies exist."""
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([])
        )

        result = await check_privileged_roles_mfa(mock_graph_client)

        assert result.status == "fail"
        assert result.check_id == "privileged-roles-mfa"
        assert result.recommendation is not None

    async def test_fail_when_some_roles_not_covered(self, mock_graph_client):
        """Should fail when some privileged roles are not covered."""
        # Only cover 10 of the 14 roles
        partial_roles = self.ALL_ROLE_IDS[:10]
        policy = self._create_mfa_policy(include_roles=partial_roles)
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([policy])
        )

        result = await check_privileged_roles_mfa(mock_graph_client)

        assert result.status == "fail"
        assert "4/14" in result.message
        assert "roles_not_covered" in result.details

    async def test_pass_when_multiple_policies_cover_all_roles(self, mock_graph_client):
        """Should pass when multiple policies together cover all roles."""
        # Split roles between two policies
        half = len(self.ALL_ROLE_IDS) // 2
        policy1 = self._create_mfa_policy(
            policy_id="p1",
            name="Policy 1",
            include_roles=self.ALL_ROLE_IDS[:half],
        )
        policy2 = self._create_mfa_policy(
            policy_id="p2",
            name="Policy 2",
            include_roles=self.ALL_ROLE_IDS[half:],
        )
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([policy1, policy2])
        )

        result = await check_privileged_roles_mfa(mock_graph_client)

        assert result.status == "pass"
        assert len(result.details["enforced_policies"]) == 2

    async def test_warning_when_only_report_only_policies(self, mock_graph_client):
        """Should warn when only report-only policies exist."""
        policy = self._create_mfa_policy(state="enabledForReportingButNotEnforced")
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([policy])
        )

        result = await check_privileged_roles_mfa(mock_graph_client)

        assert result.status == "warning"
        assert "report-only" in result.message

    async def test_warning_when_policy_has_exclusions(self, mock_graph_client):
        """Should warn when policy has exclusions."""
        policy = self._create_mfa_policy(exclude_users=["break-glass-account"])
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([policy])
        )

        result = await check_privileged_roles_mfa(mock_graph_client)

        assert result.status == "warning"
        assert "exclusions" in result.message

    async def test_fail_when_policy_not_targeting_all_apps(self, mock_graph_client):
        """Should fail when policy doesn't target all applications."""
        policy = MockConditionalAccessPolicy(
            id="policy-1",
            display_name="Limited MFA",
            state="enabled",
            conditions=MockCAConditions(
                users=MockCAUsers(include_roles=self.ALL_ROLE_IDS),
                applications=MockCAApplications(
                    include_applications=["specific-app-id"]  # Not "All"
                ),
            ),
            grant_controls=MockCAGrantControls(built_in_controls=["mfa"]),
        )
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([policy])
        )

        result = await check_privileged_roles_mfa(mock_graph_client)

        assert result.status == "fail"

    async def test_fail_when_policy_has_no_mfa_control(self, mock_graph_client):
        """Should fail when policy doesn't require MFA."""
        policy = MockConditionalAccessPolicy(
            id="policy-1",
            display_name="No MFA Policy",
            state="enabled",
            conditions=MockCAConditions(
                users=MockCAUsers(include_roles=self.ALL_ROLE_IDS),
                applications=MockCAApplications(include_applications=["All"]),
            ),
            grant_controls=MockCAGrantControls(built_in_controls=["compliantDevice"]),
        )
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([policy])
        )

        result = await check_privileged_roles_mfa(mock_graph_client)

        assert result.status == "fail"

    async def test_disabled_policy_is_ignored(self, mock_graph_client):
        """Should ignore disabled policies."""
        policy = self._create_mfa_policy(state="disabled")
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([policy])
        )

        result = await check_privileged_roles_mfa(mock_graph_client)

        assert result.status == "fail"

    async def test_details_include_covered_role_names(self, mock_graph_client):
        """Should include role names in policy details."""
        # Only cover Global Administrator
        policy = self._create_mfa_policy(
            include_roles=["62e90394-69f5-4237-9190-012177145e10"]
        )
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([policy])
        )

        result = await check_privileged_roles_mfa(mock_graph_client)

        # Should fail since not all roles covered, but check the details
        assert result.status == "fail"
        assert "Global Administrator" in result.details["enforced_policies"][0]["covered_roles"]


class TestGlobalAdminCount:
    """Tests for global admin count check."""

    def _create_user_principal(self, user_id: str, display_name: str):
        """Create a mock user principal for role assignment."""
        principal = MockRoleMember(
            id=user_id,
            display_name=display_name,
            odata_type="#microsoft.graph.user",
        )
        return principal

    def _create_sp_principal(self, sp_id: str, display_name: str):
        """Create a mock service principal for role assignment."""
        principal = MockRoleMember(
            id=sp_id,
            display_name=display_name,
            odata_type="#microsoft.graph.servicePrincipal",
        )
        return principal

    def _create_group_principal(self, group_id: str, display_name: str):
        """Create a mock group principal for role assignment."""
        principal = MockRoleMember(
            id=group_id,
            display_name=display_name,
            odata_type="#microsoft.graph.group",
        )
        return principal

    async def test_pass_with_valid_user_count(self, mock_graph_client):
        """Should pass with 2-8 cloud-only users."""
        user1 = self._create_user_principal("user-1", "Admin One")
        user2 = self._create_user_principal("user-2", "Admin Two")
        user3 = self._create_user_principal("user-3", "Admin Three")

        mock_graph_client.role_management.directory.role_assignments.get.return_value = (
            MockRoleAssignmentsResponse([
                MockRoleAssignment(GLOBAL_ADMIN_ROLE_ID, "user-1", user1),
                MockRoleAssignment(GLOBAL_ADMIN_ROLE_ID, "user-2", user2),
                MockRoleAssignment(GLOBAL_ADMIN_ROLE_ID, "user-3", user3),
            ])
        )

        # Mock user lookups - all cloud-only
        def user_lookup(user_id):
            users = {
                "user-1": MockUser("user-1", "admin1@contoso.com", on_premises_sync_enabled=False),
                "user-2": MockUser("user-2", "admin2@contoso.com", on_premises_sync_enabled=None),
                "user-3": MockUser("user-3", "admin3@contoso.com", on_premises_sync_enabled=False),
            }
            mock = AsyncMock(return_value=users[user_id])
            return type("Mock", (), {"get": mock})()

        mock_graph_client.users.by_user_id.side_effect = user_lookup

        result = await check_global_admin_count(mock_graph_client)

        assert result.status == "pass"
        assert result.check_id == "global-admin-count"
        assert "3 cloud-only user(s)" in result.message
        assert "admin1@contoso.com" in result.message
        assert result.details["user_count"] == 3

    async def test_fail_with_too_few_users(self, mock_graph_client):
        """Should fail with fewer than 2 users."""
        user1 = self._create_user_principal("user-1", "Admin One")

        mock_graph_client.role_management.directory.role_assignments.get.return_value = (
            MockRoleAssignmentsResponse([
                MockRoleAssignment(GLOBAL_ADMIN_ROLE_ID, "user-1", user1),
            ])
        )

        mock_graph_client.users.by_user_id.return_value.get.return_value = (
            MockUser("user-1", "admin1@contoso.com", on_premises_sync_enabled=False)
        )

        result = await check_global_admin_count(mock_graph_client)

        assert result.status == "fail"
        assert "Only 1 user(s)" in result.message
        assert "minimum: 2" in result.message

    async def test_fail_with_too_many_users(self, mock_graph_client):
        """Should fail with more than 8 users."""
        users = []
        for i in range(9):
            users.append(MockRoleAssignment(
                GLOBAL_ADMIN_ROLE_ID,
                f"user-{i}",
                self._create_user_principal(f"user-{i}", f"Admin {i}"),
            ))

        mock_graph_client.role_management.directory.role_assignments.get.return_value = (
            MockRoleAssignmentsResponse(users)
        )

        def user_lookup(user_id):
            mock = AsyncMock(return_value=MockUser(
                user_id, f"{user_id}@contoso.com", on_premises_sync_enabled=False
            ))
            return type("Mock", (), {"get": mock})()

        mock_graph_client.users.by_user_id.side_effect = user_lookup

        result = await check_global_admin_count(mock_graph_client)

        assert result.status == "fail"
        assert "9 user(s)" in result.message
        assert "maximum: 8" in result.message

    async def test_fail_with_synced_user(self, mock_graph_client):
        """Should fail when a user is synced from on-premises AD."""
        user1 = self._create_user_principal("user-1", "Admin One")
        user2 = self._create_user_principal("user-2", "Admin Two")

        mock_graph_client.role_management.directory.role_assignments.get.return_value = (
            MockRoleAssignmentsResponse([
                MockRoleAssignment(GLOBAL_ADMIN_ROLE_ID, "user-1", user1),
                MockRoleAssignment(GLOBAL_ADMIN_ROLE_ID, "user-2", user2),
            ])
        )

        def user_lookup(user_id):
            users = {
                "user-1": MockUser("user-1", "admin1@contoso.com", on_premises_sync_enabled=False),
                "user-2": MockUser("user-2", "synced@contoso.com", on_premises_sync_enabled=True),
            }
            mock = AsyncMock(return_value=users[user_id])
            return type("Mock", (), {"get": mock})()

        mock_graph_client.users.by_user_id.side_effect = user_lookup

        result = await check_global_admin_count(mock_graph_client)

        assert result.status == "fail"
        assert "synced" in result.message.lower()
        assert "synced@contoso.com" in result.message
        assert result.details["synced_user_count"] == 1

    async def test_service_principals_counted_separately(self, mock_graph_client):
        """Service principals should not count toward the 2-8 user limit."""
        user1 = self._create_user_principal("user-1", "Admin One")
        user2 = self._create_user_principal("user-2", "Admin Two")
        sp1 = self._create_sp_principal("sp-1", "Backup App")

        mock_graph_client.role_management.directory.role_assignments.get.return_value = (
            MockRoleAssignmentsResponse([
                MockRoleAssignment(GLOBAL_ADMIN_ROLE_ID, "user-1", user1),
                MockRoleAssignment(GLOBAL_ADMIN_ROLE_ID, "user-2", user2),
                MockRoleAssignment(GLOBAL_ADMIN_ROLE_ID, "sp-1", sp1),
            ])
        )

        def user_lookup(user_id):
            users = {
                "user-1": MockUser("user-1", "admin1@contoso.com", on_premises_sync_enabled=False),
                "user-2": MockUser("user-2", "admin2@contoso.com", on_premises_sync_enabled=False),
            }
            mock = AsyncMock(return_value=users[user_id])
            return type("Mock", (), {"get": mock})()

        mock_graph_client.users.by_user_id.side_effect = user_lookup

        result = await check_global_admin_count(mock_graph_client)

        assert result.status == "pass"
        assert result.details["user_count"] == 2
        assert result.details["service_principal_count"] == 1
        assert "Backup App" in result.details["service_principals"]
        assert "Service principals:" in result.message

    async def test_group_members_expanded(self, mock_graph_client):
        """Should expand group membership to count users."""
        group1 = self._create_group_principal("group-1", "Admin Group")

        mock_graph_client.role_management.directory.role_assignments.get.return_value = (
            MockRoleAssignmentsResponse([
                MockRoleAssignment(GLOBAL_ADMIN_ROLE_ID, "group-1", group1),
            ])
        )

        # Group members
        group_member1 = MockRoleMember("user-1", "Admin One", "#microsoft.graph.user")
        group_member2 = MockRoleMember("user-2", "Admin Two", "#microsoft.graph.user")

        mock_graph_client.groups.by_group_id.return_value.members.get.return_value = (
            MockGroupMembersResponse([group_member1, group_member2])
        )

        def user_lookup(user_id):
            users = {
                "user-1": MockUser("user-1", "admin1@contoso.com", on_premises_sync_enabled=False),
                "user-2": MockUser("user-2", "admin2@contoso.com", on_premises_sync_enabled=False),
            }
            mock = AsyncMock(return_value=users[user_id])
            return type("Mock", (), {"get": mock})()

        mock_graph_client.users.by_user_id.side_effect = user_lookup

        result = await check_global_admin_count(mock_graph_client)

        assert result.status == "pass"
        assert result.details["user_count"] == 2
        assert "admin1@contoso.com" in result.details["users"]
        assert "admin2@contoso.com" in result.details["users"]

    async def test_pass_with_exactly_two_users(self, mock_graph_client):
        """Should pass with exactly 2 users (minimum)."""
        user1 = self._create_user_principal("user-1", "Admin One")
        user2 = self._create_user_principal("user-2", "Admin Two")

        mock_graph_client.role_management.directory.role_assignments.get.return_value = (
            MockRoleAssignmentsResponse([
                MockRoleAssignment(GLOBAL_ADMIN_ROLE_ID, "user-1", user1),
                MockRoleAssignment(GLOBAL_ADMIN_ROLE_ID, "user-2", user2),
            ])
        )

        def user_lookup(user_id):
            users = {
                "user-1": MockUser("user-1", "admin1@contoso.com", on_premises_sync_enabled=False),
                "user-2": MockUser("user-2", "admin2@contoso.com", on_premises_sync_enabled=False),
            }
            mock = AsyncMock(return_value=users[user_id])
            return type("Mock", (), {"get": mock})()

        mock_graph_client.users.by_user_id.side_effect = user_lookup

        result = await check_global_admin_count(mock_graph_client)

        assert result.status == "pass"

    async def test_pass_with_exactly_eight_users(self, mock_graph_client):
        """Should pass with exactly 8 users (maximum)."""
        assignments = []
        for i in range(8):
            assignments.append(MockRoleAssignment(
                GLOBAL_ADMIN_ROLE_ID,
                f"user-{i}",
                self._create_user_principal(f"user-{i}", f"Admin {i}"),
            ))

        mock_graph_client.role_management.directory.role_assignments.get.return_value = (
            MockRoleAssignmentsResponse(assignments)
        )

        def user_lookup(user_id):
            mock = AsyncMock(return_value=MockUser(
                user_id, f"{user_id}@contoso.com", on_premises_sync_enabled=False
            ))
            return type("Mock", (), {"get": mock})()

        mock_graph_client.users.by_user_id.side_effect = user_lookup

        result = await check_global_admin_count(mock_graph_client)

        assert result.status == "pass"
        assert result.details["user_count"] == 8


class TestGuestInvitePolicy:
    """Tests for guest invite policy check."""

    async def test_pass_when_no_one_can_invite(self, mock_graph_client):
        """Should pass when guest invitations are disabled."""
        mock_graph_client.policies.authorization_policy.get.return_value = (
            MockAuthorizationPolicy(allow_invites_from="none")
        )

        result = await check_guest_invite_policy(mock_graph_client)

        assert result.status == "pass"
        assert result.check_id == "guest-invite-policy"
        assert "disabled" in result.message.lower()
        assert result.details["allow_invites_from"] == "none"

    async def test_fail_when_everyone_can_invite(self, mock_graph_client):
        """Should fail when anyone can invite guests."""
        mock_graph_client.policies.authorization_policy.get.return_value = (
            MockAuthorizationPolicy(allow_invites_from="everyone")
        )

        result = await check_guest_invite_policy(mock_graph_client)

        assert result.status == "fail"
        assert result.check_id == "guest-invite-policy"
        assert "Anyone" in result.message
        assert result.recommendation is not None
        assert result.details["allow_invites_from"] == "everyone"

    async def test_warning_when_admins_and_guest_inviters(self, mock_graph_client):
        """Should warn when only admins and guest inviters can invite."""
        mock_graph_client.policies.authorization_policy.get.return_value = (
            MockAuthorizationPolicy(allow_invites_from="adminsAndGuestInviters")
        )

        result = await check_guest_invite_policy(mock_graph_client)

        assert result.status == "warning"
        assert result.check_id == "guest-invite-policy"
        assert "admin roles" in result.message.lower()
        assert result.details["allow_invites_from"] == "adminsAndGuestInviters"

    async def test_warning_when_admins_and_all_members(self, mock_graph_client):
        """Should warn when admins, guest inviters, and all members can invite."""
        mock_graph_client.policies.authorization_policy.get.return_value = (
            MockAuthorizationPolicy(allow_invites_from="adminsGuestInvitersAndAllMembers")
        )

        result = await check_guest_invite_policy(mock_graph_client)

        assert result.status == "warning"
        assert result.check_id == "guest-invite-policy"
        assert "Member users" in result.message
        assert result.details["allow_invites_from"] == "adminsGuestInvitersAndAllMembers"

    async def test_error_when_property_missing(self, mock_graph_client):
        """Should return error when allowInvitesFrom is not in response."""
        # Use a mock that doesn't have allow_invites_from
        mock_graph_client.policies.authorization_policy.get.return_value = (
            MockAuthorizationPolicy(permission_grant_policies_assigned=[])
        )

        result = await check_guest_invite_policy(mock_graph_client)

        assert result.status == "error"
        assert result.check_id == "guest-invite-policy"
        assert "Could not determine" in result.message
