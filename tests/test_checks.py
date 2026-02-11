"""Tests for all checks."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from entra_spotter.checks.user_consent import check_user_consent
from entra_spotter.checks.admin_consent_workflow import check_admin_consent_workflow
from entra_spotter.checks.sp_admin_roles import check_sp_admin_roles
from entra_spotter.checks.sp_graph_roles import check_sp_graph_roles
from entra_spotter.checks.sp_multiple_secrets import check_sp_multiple_secrets
from entra_spotter.checks.legacy_auth_blocked import check_legacy_auth_blocked
from entra_spotter.checks.device_code_blocked import check_device_code_blocked
from entra_spotter.checks.privileged_roles_mfa import check_privileged_roles_mfa, PRIVILEGED_ROLES
from entra_spotter.checks.global_admin_count import check_global_admin_count, GLOBAL_ADMIN_ROLE_ID
from entra_spotter.checks.guest_invite_policy import check_guest_invite_policy
from entra_spotter.checks.guest_access import check_guest_access
from entra_spotter.checks.privileged_roles_phishing_resistant_mfa import (
    check_privileged_roles_phishing_resistant_mfa,
    PRIVILEGED_ROLES as PHISHING_RESISTANT_PRIVILEGED_ROLES,
)
from entra_spotter.checks.shadow_admins_app_owners import check_shadow_admins_app_owners
from entra_spotter.checks.shadow_admins_group_owners import check_shadow_admins_group_owners
from entra_spotter.checks.dynamic_group_hijack import check_dynamic_group_hijack
from entra_spotter.checks.auth_methods_number_matching import check_auth_methods_number_matching
from entra_spotter.checks.break_glass_exclusion import check_break_glass_exclusion
from entra_spotter.checks.privileged_roles_license import check_privileged_roles_license

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
    MockPasswordCredential,
    MockKeyCredential,
    MockServicePrincipal,
    MockServicePrincipalsResponse,
    MockCAAuthenticationStrength,
    MockCAGrantControls,
    MockCAUsers,
    MockCAApplications,
    MockCAAuthenticationFlows,
    MockCAConditions,
    MockConditionalAccessPolicy,
    MockCAPoliciesResponse,
    MockOwnersResponse,
    MockDynamicGroup,
    MockServicePrincipalDetail,
    MockNumberMatchingState,
    MockIncludeTarget,
    MockFeatureSettings,
    MockAuthenticatorConfig,
    MockApplication,
    MockApplicationsResponse,
    MockAssignedPlan,
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


class TestServicePrincipalMultipleSecrets:
    """Tests for service principal multiple secrets check."""

    async def test_pass_when_no_service_principals(self, mock_graph_client):
        """Should pass when no service principals exist."""
        mock_graph_client.service_principals.get.return_value = MockServicePrincipalsResponse([])
        mock_graph_client.applications.get.return_value = MockApplicationsResponse([])

        result = await check_sp_multiple_secrets(mock_graph_client)

        assert result.status == "pass"
        assert result.check_id == "sp-multiple-secrets"

    async def test_pass_when_every_sp_has_zero_or_one_credential(self, mock_graph_client):
        """Should pass when each service principal has fewer than two credentials."""
        mock_graph_client.service_principals.get.return_value = MockServicePrincipalsResponse([
            MockServicePrincipal(
                id="sp-1",
                display_name="One Secret App",
                password_credentials=[MockPasswordCredential(display_name="Secret A")],
            ),
            MockServicePrincipal(
                id="sp-2",
                display_name="One Certificate App",
                key_credentials=[MockKeyCredential(display_name="Cert A")],
            ),
            MockServicePrincipal(
                id="sp-3",
                display_name="No Credentials App",
                password_credentials=None,
                key_credentials=None,
            ),
        ])
        mock_graph_client.applications.get.return_value = MockApplicationsResponse([])

        result = await check_sp_multiple_secrets(mock_graph_client)

        assert result.status == "pass"

    async def test_warning_when_sp_has_two_client_secrets(self, mock_graph_client):
        """Should warn when one service principal has two client secrets."""
        mock_graph_client.service_principals.get.return_value = MockServicePrincipalsResponse([
            MockServicePrincipal(
                id="sp-1",
                display_name="Dual Secret App",
                password_credentials=[
                    MockPasswordCredential(display_name="Secret One"),
                    MockPasswordCredential(display_name="Secret Two"),
                ],
                key_credentials=[],
            )
        ])
        mock_graph_client.applications.get.return_value = MockApplicationsResponse([])

        result = await check_sp_multiple_secrets(mock_graph_client)

        assert result.status == "warning"
        assert result.check_id == "sp-multiple-secrets"
        assert len(result.details["service_principals"]) == 1
        finding = result.details["service_principals"][0]
        assert finding["display_name"] == "Dual Secret App"
        assert finding["secret_count"] == 2
        assert finding["secrets"][0]["type"] == "client_secret"
        assert finding["secrets"][1]["type"] == "client_secret"
        assert finding["secrets"][0]["source"] == "service_principal"
        assert finding["secrets"][1]["source"] == "service_principal"

    async def test_warning_when_sp_has_mixed_secret_types(self, mock_graph_client):
        """Should warn when one service principal has secret + certificate."""
        mock_graph_client.service_principals.get.return_value = MockServicePrincipalsResponse([
            MockServicePrincipal(
                id="sp-1",
                display_name="Mixed Credential App",
                password_credentials=[MockPasswordCredential(display_name="Client Secret")],
                key_credentials=[MockKeyCredential(display_name="Signing Cert")],
            )
        ])
        mock_graph_client.applications.get.return_value = MockApplicationsResponse([])

        result = await check_sp_multiple_secrets(mock_graph_client)

        assert result.status == "warning"
        assert "1 service principal(s)" in result.message
        finding = result.details["service_principals"][0]
        assert finding["secret_count"] == 2
        assert finding["secrets"][0]["name"] == "Client Secret"
        assert finding["secrets"][0]["type"] == "client_secret"
        assert finding["secrets"][1]["name"] == "Signing Cert"
        assert finding["secrets"][1]["type"] == "certificate"
        assert "Client Secret (client_secret, service_principal)" in result.details["details_summary"]
        assert "Signing Cert (certificate, service_principal)" in result.details["details_summary"]

    async def test_warning_when_app_registration_has_two_client_secrets(self, mock_graph_client):
        """Should warn when backing app registration has two client secrets."""
        mock_graph_client.service_principals.get.return_value = MockServicePrincipalsResponse([
            MockServicePrincipal(
                id="sp-1",
                display_name="App Reg Secret App",
                app_id="app-id-1",
                password_credentials=[],
                key_credentials=[],
            )
        ])
        mock_graph_client.applications.get.return_value = MockApplicationsResponse([
            MockApplication(
                id="app-obj-1",
                app_id="app-id-1",
                display_name="App Registration One",
                password_credentials=[
                    MockPasswordCredential(display_name="App Secret A"),
                    MockPasswordCredential(display_name="App Secret B"),
                ],
                key_credentials=[],
            )
        ])

        result = await check_sp_multiple_secrets(mock_graph_client)

        assert result.status == "warning"
        finding = result.details["service_principals"][0]
        assert finding["display_name"] == "App Reg Secret App"
        assert finding["app_registration_display_name"] == "App Registration One"
        assert finding["service_principal_secret_count"] == 0
        assert finding["app_registration_secret_count"] == 2
        assert finding["secret_count"] == 2
        assert finding["secrets"][0]["source"] == "app_registration"
        assert finding["secrets"][1]["source"] == "app_registration"

    async def test_warning_when_sp_and_app_registration_combine_to_two(self, mock_graph_client):
        """Should warn when SP + app registration credentials jointly meet threshold."""
        mock_graph_client.service_principals.get.return_value = MockServicePrincipalsResponse([
            MockServicePrincipal(
                id="sp-1",
                display_name="Combined App",
                app_id="app-id-1",
                password_credentials=[MockPasswordCredential(display_name="SP Secret")],
                key_credentials=[],
            )
        ])
        mock_graph_client.applications.get.return_value = MockApplicationsResponse([
            MockApplication(
                id="app-obj-1",
                app_id="app-id-1",
                key_credentials=[MockKeyCredential(display_name="App Cert")],
            )
        ])

        result = await check_sp_multiple_secrets(mock_graph_client)

        assert result.status == "warning"
        finding = result.details["service_principals"][0]
        assert finding["service_principal_secret_count"] == 1
        assert finding["app_registration_secret_count"] == 1
        assert finding["secret_count"] == 2
        assert any(
            secret["source"] == "service_principal" and secret["name"] == "SP Secret"
            for secret in finding["secrets"]
        )
        assert any(
            secret["source"] == "app_registration" and secret["name"] == "App Cert"
            for secret in finding["secrets"]
        )

    async def test_pass_when_only_unrelated_app_registration_has_multiple_secrets(self, mock_graph_client):
        """Should ignore credentials from app registrations that do not match SP app_id."""
        mock_graph_client.service_principals.get.return_value = MockServicePrincipalsResponse([
            MockServicePrincipal(
                id="sp-1",
                display_name="Single Secret SP",
                app_id="app-id-1",
                password_credentials=[MockPasswordCredential(display_name="Only SP Secret")],
            )
        ])
        mock_graph_client.applications.get.return_value = MockApplicationsResponse([
            MockApplication(
                id="app-obj-2",
                app_id="different-app-id",
                password_credentials=[
                    MockPasswordCredential(display_name="Unrelated Secret A"),
                    MockPasswordCredential(display_name="Unrelated Secret B"),
                ],
            )
        ])

        result = await check_sp_multiple_secrets(mock_graph_client)

        assert result.status == "pass"

    async def test_warning_uses_fallback_names_when_missing_display_name(self, mock_graph_client):
        """Should use key_id fallback names when credential display names are missing."""
        mock_graph_client.service_principals.get.return_value = MockServicePrincipalsResponse([
            MockServicePrincipal(
                id="sp-1",
                display_name="",
                password_credentials=[MockPasswordCredential(display_name=None, key_id="secret-key-1")],
                key_credentials=[MockKeyCredential(display_name=None, key_id="cert-key-1")],
            )
        ])
        mock_graph_client.applications.get.return_value = MockApplicationsResponse([])

        result = await check_sp_multiple_secrets(mock_graph_client)

        assert result.status == "warning"
        finding = result.details["service_principals"][0]
        assert finding["display_name"] == "Unknown"
        assert finding["secrets"][0]["name"] == "Unnamed secret (key_id=secret-key-1)"
        assert finding["secrets"][1]["name"] == "Unnamed key (key_id=cert-key-1)"

    async def test_warning_with_multiple_service_principals(self, mock_graph_client):
        """Should include every matching service principal in details."""
        mock_graph_client.service_principals.get.return_value = MockServicePrincipalsResponse([
            MockServicePrincipal(
                id="sp-1",
                display_name="App One",
                password_credentials=[
                    MockPasswordCredential(display_name="Secret One"),
                    MockPasswordCredential(display_name="Secret Two"),
                ],
            ),
            MockServicePrincipal(
                id="sp-2",
                display_name="App Two",
                password_credentials=[MockPasswordCredential(display_name="One Secret")],
                key_credentials=[MockKeyCredential(display_name="One Cert")],
            ),
        ])
        mock_graph_client.applications.get.return_value = MockApplicationsResponse([])

        result = await check_sp_multiple_secrets(mock_graph_client)

        assert result.status == "warning"
        assert len(result.details["service_principals"]) == 2
        assert '"App One"' in result.details["details_summary"]
        assert '"App Two"' in result.details["details_summary"]

    async def test_paginates_through_all_service_principals(self, mock_graph_client):
        """Should evaluate service principals across paginated responses."""
        first_page = MockServicePrincipalsResponse(
            [
                MockServicePrincipal(
                    id="sp-1",
                    display_name="Paged App One",
                    password_credentials=[MockPasswordCredential(display_name="Secret One")],
                )
            ],
            odata_next_link="next-page-url",
        )
        second_page = MockServicePrincipalsResponse(
            [
                MockServicePrincipal(
                    id="sp-2",
                    display_name="Paged App Two",
                    password_credentials=[MockPasswordCredential(display_name="Secret Two")],
                    key_credentials=[MockKeyCredential(display_name="Cert Two")],
                )
            ]
        )
        app_first_page = MockApplicationsResponse(
            [
                MockApplication(
                    id="app-obj-1",
                    app_id="app-id-1",
                    password_credentials=[],
                )
            ],
            odata_next_link="next-app-page-url",
        )
        app_second_page = MockApplicationsResponse(
            [
                MockApplication(
                    id="app-obj-2",
                    app_id="app-id-2",
                    key_credentials=[MockKeyCredential(display_name="App Cert Two")],
                )
            ]
        )

        mock_graph_client.service_principals.get.return_value = first_page
        mock_graph_client.service_principals.with_url = MagicMock(
            return_value=MagicMock(get=AsyncMock(return_value=second_page))
        )
        mock_graph_client.applications.get.return_value = app_first_page
        mock_graph_client.applications.with_url = MagicMock(
            return_value=MagicMock(get=AsyncMock(return_value=app_second_page))
        )

        result = await check_sp_multiple_secrets(mock_graph_client)

        assert result.status == "warning"
        assert len(result.details["service_principals"]) == 1
        assert result.details["service_principals"][0]["display_name"] == "Paged App Two"
        mock_graph_client.service_principals.with_url.assert_called_once_with("next-page-url")
        mock_graph_client.applications.with_url.assert_called_once_with("next-app-page-url")


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

    async def test_fail_when_only_report_only_policy_exists(self, mock_graph_client):
        """Should fail when only report-only policies exist."""
        policy = self._create_blocking_policy(
            state="enabledForReportingButNotEnforced"
        )
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([policy])
        )

        result = await check_legacy_auth_blocked(mock_graph_client)

        assert result.status == "fail"
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

    async def test_fail_when_policy_not_targeting_all_users(self, mock_graph_client):
        """Should fail when policy doesn't target all users."""
        policy = MockConditionalAccessPolicy(
            id="policy-1",
            display_name="Limited Users",
            state="enabled",
            conditions=MockCAConditions(
                authentication_flows=MockCAAuthenticationFlows(
                    transfer_methods=["deviceCodeFlow"]
                ),
                users=MockCAUsers(include_users=["user-id-1"]),
                applications=MockCAApplications(include_applications=["All"]),
            ),
            grant_controls=MockCAGrantControls(built_in_controls=["block"]),
        )
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([policy])
        )

        result = await check_device_code_blocked(mock_graph_client)

        assert result.status == "fail"

    async def test_fail_when_policy_not_targeting_all_users(self, mock_graph_client):
        """Should fail when policy doesn't target all users."""
        policy = MockConditionalAccessPolicy(
            id="policy-1",
            display_name="Limited Users",
            state="enabled",
            conditions=MockCAConditions(
                client_app_types=["exchangeActiveSync", "other"],
                users=MockCAUsers(include_users=["user-id-1"]),
                applications=MockCAApplications(include_applications=["All"]),
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

    async def test_fail_when_only_report_only_policy_exists(self, mock_graph_client):
        """Should fail when only report-only policies exist."""
        policy = self._create_blocking_policy(
            state="enabledForReportingButNotEnforced"
        )
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([policy])
        )

        result = await check_device_code_blocked(mock_graph_client)

        assert result.status == "fail"
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

    async def test_fail_when_only_report_only_policies(self, mock_graph_client):
        """Should fail when only report-only policies exist."""
        policy = self._create_mfa_policy(state="enabledForReportingButNotEnforced")
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([policy])
        )

        result = await check_privileged_roles_mfa(mock_graph_client)

        assert result.status == "fail"
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

    async def test_fail_when_policy_allows_or_bypass(self, mock_graph_client):
        """Should fail when MFA is combined with other controls using OR."""
        policy = MockConditionalAccessPolicy(
            id="policy-1",
            display_name="MFA Or Compliance",
            state="enabled",
            conditions=MockCAConditions(
                users=MockCAUsers(include_roles=self.ALL_ROLE_IDS),
                applications=MockCAApplications(include_applications=["All"]),
            ),
            grant_controls=MockCAGrantControls(
                built_in_controls=["mfa", "compliantDevice"],
                operator="OR",
            ),
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

    def _set_group_members(
        self,
        mock_graph_client,
        group_pages: dict[str, list[MockGroupMembersResponse]],
    ) -> None:
        """Configure per-group member pages for recursive group expansion tests."""
        cache: dict[str, MagicMock] = {}

        def _group_ref(group_id: str) -> MagicMock:
            if group_id in cache:
                return cache[group_id]

            pages = group_pages[group_id]
            members = MagicMock()
            members.get = AsyncMock(return_value=pages[0])

            next_refs: dict[str, MagicMock] = {}
            for i, page in enumerate(pages[:-1]):
                if page.odata_next_link:
                    next_refs[page.odata_next_link] = MagicMock(
                        get=AsyncMock(return_value=pages[i + 1])
                    )

            members.with_url = MagicMock(side_effect=lambda url: next_refs[url])
            group_ref = MagicMock(members=members)
            cache[group_id] = group_ref
            return group_ref

        mock_graph_client.groups.by_group_id.side_effect = _group_ref

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

    async def test_nested_group_members_expanded_recursively(self, mock_graph_client):
        """Should expand nested groups recursively to count users."""
        root_group = self._create_group_principal("group-1", "Root Admin Group")
        nested_group = self._create_group_principal("group-2", "Nested Admin Group")
        nested_user = MockRoleMember("user-1", "Nested Admin", "#microsoft.graph.user")

        mock_graph_client.role_management.directory.role_assignments.get.return_value = (
            MockRoleAssignmentsResponse([
                MockRoleAssignment(GLOBAL_ADMIN_ROLE_ID, "group-1", root_group),
            ])
        )

        self._set_group_members(
            mock_graph_client,
            {
                "group-1": [MockGroupMembersResponse([nested_group])],
                "group-2": [MockGroupMembersResponse([nested_user])],
            },
        )

        mock_graph_client.users.by_user_id.return_value.get.return_value = (
            MockUser("user-1", "nested@contoso.com", on_premises_sync_enabled=False)
        )

        result = await check_global_admin_count(mock_graph_client)

        assert result.status == "fail"
        assert result.details["user_count"] == 1
        assert "nested@contoso.com" in result.details["users"]

    async def test_nested_group_cycle_handled_without_double_counting(self, mock_graph_client):
        """Should handle nested group cycles and deduplicate users."""
        root_group = self._create_group_principal("group-1", "Root Group")
        group_a = self._create_group_principal("group-1", "Root Group")
        group_b = self._create_group_principal("group-2", "Nested Group")
        user1 = MockRoleMember("user-1", "Admin One", "#microsoft.graph.user")
        user2 = MockRoleMember("user-2", "Admin Two", "#microsoft.graph.user")

        mock_graph_client.role_management.directory.role_assignments.get.return_value = (
            MockRoleAssignmentsResponse([
                MockRoleAssignment(GLOBAL_ADMIN_ROLE_ID, "group-1", root_group),
            ])
        )

        self._set_group_members(
            mock_graph_client,
            {
                "group-1": [MockGroupMembersResponse([group_b, user1])],
                "group-2": [MockGroupMembersResponse([group_a, user1, user2])],
            },
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
        assert sorted(result.details["users"]) == ["admin1@contoso.com", "admin2@contoso.com"]

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


class TestGuestAccess:
    """Tests for guest user access level check."""

    async def test_fail_when_same_access_as_members(self, mock_graph_client):
        """Should fail when guests have the same access as members."""
        mock_graph_client.policies.authorization_policy.get.return_value = (
            MockAuthorizationPolicy(
                guest_user_role_id="a0b1b346-4d3e-4e8b-98f8-753987be4970"
            )
        )

        result = await check_guest_access(mock_graph_client)

        assert result.status == "fail"
        assert result.check_id == "guest-access"
        assert "same access" in result.message.lower()
        assert result.recommendation is not None
        assert result.details["guest_user_role_id"] == "a0b1b346-4d3e-4e8b-98f8-753987be4970"

    async def test_pass_when_limited_access(self, mock_graph_client):
        """Should pass when guests have limited access (default)."""
        mock_graph_client.policies.authorization_policy.get.return_value = (
            MockAuthorizationPolicy(
                guest_user_role_id="10dae51f-b6af-4016-8d66-8c2a99b929b3"
            )
        )

        result = await check_guest_access(mock_graph_client)

        assert result.status == "pass"
        assert result.check_id == "guest-access"
        assert "restricted" in result.message.lower()
        assert result.details["guest_user_role_id"] == "10dae51f-b6af-4016-8d66-8c2a99b929b3"

    async def test_pass_when_most_restrictive(self, mock_graph_client):
        """Should pass when guests have the most restrictive access."""
        mock_graph_client.policies.authorization_policy.get.return_value = (
            MockAuthorizationPolicy(
                guest_user_role_id="2af84b1e-32c8-42b7-82bc-daa82404023b"
            )
        )

        result = await check_guest_access(mock_graph_client)

        assert result.status == "pass"
        assert result.check_id == "guest-access"
        assert "restricted" in result.message.lower()
        assert result.details["guest_user_role_id"] == "2af84b1e-32c8-42b7-82bc-daa82404023b"

    async def test_error_when_property_missing(self, mock_graph_client):
        """Should return error when guestUserRoleId is not in response."""
        mock_graph_client.policies.authorization_policy.get.return_value = (
            MockAuthorizationPolicy(permission_grant_policies_assigned=[])
        )

        result = await check_guest_access(mock_graph_client)

        assert result.status == "error"
        assert result.check_id == "guest-access"
        assert "Could not determine" in result.message

    async def test_pass_when_unknown_role_id(self, mock_graph_client):
        """Should pass with unknown role ID (still not same-as-members)."""
        mock_graph_client.policies.authorization_policy.get.return_value = (
            MockAuthorizationPolicy(
                guest_user_role_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
            )
        )

        result = await check_guest_access(mock_graph_client)

        assert result.status == "pass"
        assert result.check_id == "guest-access"
        assert "Unknown role ID" in result.details["access_level"]


class TestPrivilegedRolesPhishingResistantMfa:
    """Tests for phishing-resistant MFA for privileged roles check."""

    ALL_ROLE_IDS = list(PHISHING_RESISTANT_PRIVILEGED_ROLES.keys())
    PHISHING_RESISTANT_ID = "00000000-0000-0000-0000-000000000004"

    def _create_phishing_resistant_policy(
        self,
        policy_id: str = "policy-1",
        name: str = "Phishing-Resistant MFA for Admins",
        state: str = "enabled",
        include_roles: list[str] | None = None,
        exclude_users: list[str] | None = None,
        exclude_groups: list[str] | None = None,
        exclude_roles: list[str] | None = None,
        exclude_applications: list[str] | None = None,
    ) -> MockConditionalAccessPolicy:
        """Helper to create a valid phishing-resistant MFA policy for roles."""
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
            grant_controls=MockCAGrantControls(
                authentication_strength=MockCAAuthenticationStrength(
                    id=self.PHISHING_RESISTANT_ID,
                ),
            ),
        )

    async def test_pass_when_all_roles_covered_no_exclusions(self, mock_graph_client):
        """Should pass when all privileged roles are covered with no exclusions."""
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([self._create_phishing_resistant_policy()])
        )

        result = await check_privileged_roles_phishing_resistant_mfa(mock_graph_client)

        assert result.status == "pass"
        assert result.check_id == "privileged-roles-phishing-resistant-mfa"
        assert "All 14 privileged roles require phishing-resistant MFA" in result.message

    async def test_fail_when_no_policies_exist(self, mock_graph_client):
        """Should fail when no CA policies exist."""
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([])
        )

        result = await check_privileged_roles_phishing_resistant_mfa(mock_graph_client)

        assert result.status == "fail"
        assert result.check_id == "privileged-roles-phishing-resistant-mfa"
        assert result.recommendation is not None

    async def test_fail_when_some_roles_not_covered(self, mock_graph_client):
        """Should fail when some privileged roles are not covered."""
        partial_roles = self.ALL_ROLE_IDS[:10]
        policy = self._create_phishing_resistant_policy(include_roles=partial_roles)
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([policy])
        )

        result = await check_privileged_roles_phishing_resistant_mfa(mock_graph_client)

        assert result.status == "fail"
        assert "4/14" in result.message
        assert "roles_not_covered" in result.details

    async def test_pass_when_multiple_policies_cover_all_roles(self, mock_graph_client):
        """Should pass when multiple policies together cover all roles."""
        half = len(self.ALL_ROLE_IDS) // 2
        policy1 = self._create_phishing_resistant_policy(
            policy_id="p1",
            name="Policy 1",
            include_roles=self.ALL_ROLE_IDS[:half],
        )
        policy2 = self._create_phishing_resistant_policy(
            policy_id="p2",
            name="Policy 2",
            include_roles=self.ALL_ROLE_IDS[half:],
        )
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([policy1, policy2])
        )

        result = await check_privileged_roles_phishing_resistant_mfa(mock_graph_client)

        assert result.status == "pass"
        assert len(result.details["enforced_policies"]) == 2

    async def test_fail_when_only_report_only_policies(self, mock_graph_client):
        """Should fail when only report-only policies exist."""
        policy = self._create_phishing_resistant_policy(
            state="enabledForReportingButNotEnforced",
        )
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([policy])
        )

        result = await check_privileged_roles_phishing_resistant_mfa(mock_graph_client)

        assert result.status == "fail"
        assert "report-only" in result.message

    async def test_warning_when_policy_has_exclusions(self, mock_graph_client):
        """Should warn when policy has exclusions."""
        policy = self._create_phishing_resistant_policy(
            exclude_users=["break-glass-account"],
        )
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([policy])
        )

        result = await check_privileged_roles_phishing_resistant_mfa(mock_graph_client)

        assert result.status == "warning"
        assert "exclusions" in result.message

    async def test_fail_when_policy_not_targeting_all_apps(self, mock_graph_client):
        """Should fail when policy doesn't target all applications."""
        policy = MockConditionalAccessPolicy(
            id="policy-1",
            display_name="Limited Policy",
            state="enabled",
            conditions=MockCAConditions(
                users=MockCAUsers(include_roles=self.ALL_ROLE_IDS),
                applications=MockCAApplications(
                    include_applications=["specific-app-id"],
                ),
            ),
            grant_controls=MockCAGrantControls(
                authentication_strength=MockCAAuthenticationStrength(
                    id=self.PHISHING_RESISTANT_ID,
                ),
            ),
        )
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([policy])
        )

        result = await check_privileged_roles_phishing_resistant_mfa(mock_graph_client)

        assert result.status == "fail"

    async def test_fail_when_policy_uses_regular_mfa_not_phishing_resistant(self, mock_graph_client):
        """Should fail when policy uses built-in MFA control instead of phishing-resistant strength."""
        policy = MockConditionalAccessPolicy(
            id="policy-1",
            display_name="Regular MFA Policy",
            state="enabled",
            conditions=MockCAConditions(
                users=MockCAUsers(include_roles=self.ALL_ROLE_IDS),
                applications=MockCAApplications(include_applications=["All"]),
            ),
            grant_controls=MockCAGrantControls(built_in_controls=["mfa"]),
        )
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([policy])
        )

        result = await check_privileged_roles_phishing_resistant_mfa(mock_graph_client)

        assert result.status == "fail"

    async def test_fail_when_policy_allows_or_bypass(self, mock_graph_client):
        """Should fail when phishing-resistant strength is combined with OR."""
        policy = MockConditionalAccessPolicy(
            id="policy-1",
            display_name="Strength Or Compliance",
            state="enabled",
            conditions=MockCAConditions(
                users=MockCAUsers(include_roles=self.ALL_ROLE_IDS),
                applications=MockCAApplications(include_applications=["All"]),
            ),
            grant_controls=MockCAGrantControls(
                authentication_strength=MockCAAuthenticationStrength(
                    id=self.PHISHING_RESISTANT_ID,
                ),
                built_in_controls=["compliantDevice"],
                operator="OR",
            ),
        )
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([policy])
        )

        result = await check_privileged_roles_phishing_resistant_mfa(mock_graph_client)

        assert result.status == "fail"

    async def test_fail_when_policy_uses_wrong_strength_id(self, mock_graph_client):
        """Should fail when policy uses a different authentication strength (e.g. regular MFA)."""
        regular_mfa_strength_id = "00000000-0000-0000-0000-000000000002"
        policy = MockConditionalAccessPolicy(
            id="policy-1",
            display_name="Regular MFA Strength Policy",
            state="enabled",
            conditions=MockCAConditions(
                users=MockCAUsers(include_roles=self.ALL_ROLE_IDS),
                applications=MockCAApplications(include_applications=["All"]),
            ),
            grant_controls=MockCAGrantControls(
                authentication_strength=MockCAAuthenticationStrength(
                    id=regular_mfa_strength_id,
                ),
            ),
        )
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([policy])
        )

        result = await check_privileged_roles_phishing_resistant_mfa(mock_graph_client)

        assert result.status == "fail"

    async def test_disabled_policy_is_ignored(self, mock_graph_client):
        """Should ignore disabled policies."""
        policy = self._create_phishing_resistant_policy(state="disabled")
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([policy])
        )

        result = await check_privileged_roles_phishing_resistant_mfa(mock_graph_client)

        assert result.status == "fail"

    async def test_details_include_covered_role_names(self, mock_graph_client):
        """Should include role names in policy details."""
        policy = self._create_phishing_resistant_policy(
            include_roles=["62e90394-69f5-4237-9190-012177145e10"],
        )
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([policy])
        )

        result = await check_privileged_roles_phishing_resistant_mfa(mock_graph_client)

        assert result.status == "fail"
        assert "Global Administrator" in result.details["enforced_policies"][0]["covered_roles"]


# Global Admin role ID used across shadow admin tests
GA_ROLE_ID = "62e90394-69f5-4237-9190-012177145e10"


class TestShadowAdminsAppOwners:
    """Tests for shadow admins via app ownership check."""

    async def test_pass_when_no_privileged_sps(self, mock_graph_client):
        """Should pass when no service principals hold privileged roles."""
        mock_graph_client.role_management.directory.role_assignments.get.return_value = (
            MockRoleAssignmentsResponse([])
        )
        mock_graph_client.service_principals.get.return_value = MockServicePrincipalsResponse([])

        result = await check_shadow_admins_app_owners(mock_graph_client)

        assert result.status == "pass"
        assert result.check_id == "shadow-admins-app-owners"

    async def test_pass_when_no_user_owners(self, mock_graph_client):
        """Should pass when privileged SPs have no user owners."""
        sp_principal = MockRoleMember("sp-1", "Privileged App", "#microsoft.graph.servicePrincipal")
        mock_graph_client.role_management.directory.role_assignments.get.return_value = (
            MockRoleAssignmentsResponse([
                MockRoleAssignment(GA_ROLE_ID, "sp-1", sp_principal),
            ])
        )
        mock_graph_client.service_principals.get.return_value = MockServicePrincipalsResponse([])
        # SP has no owners
        mock_graph_client.service_principals.by_service_principal_id.return_value.owners.get.return_value = (
            MockOwnersResponse([])
        )
        # SP detail returns appId, but app registration also has no owners
        mock_graph_client.service_principals.by_service_principal_id.return_value.get.return_value = (
            MockServicePrincipalDetail("sp-1", "Privileged App", app_id="app-id-1")
        )
        mock_graph_client.applications.get.return_value = MockApplicationsResponse([
            MockApplication(id="app-obj-1", app_id="app-id-1"),
        ])
        mock_graph_client.applications.by_application_id.return_value.owners.get.return_value = (
            MockOwnersResponse([])
        )

        result = await check_shadow_admins_app_owners(mock_graph_client)

        assert result.status == "pass"

    async def test_warning_when_user_owns_privileged_sp(self, mock_graph_client):
        """Should warn when a user owns a service principal with a privileged role."""
        sp_principal = MockRoleMember("sp-1", "Privileged App", "#microsoft.graph.servicePrincipal")
        mock_graph_client.role_management.directory.role_assignments.get.return_value = (
            MockRoleAssignmentsResponse([
                MockRoleAssignment(GA_ROLE_ID, "sp-1", sp_principal),
            ])
        )
        mock_graph_client.service_principals.get.return_value = MockServicePrincipalsResponse([])

        user_owner = MockRoleMember("user-1", "Shadow Admin User", "#microsoft.graph.user", user_principal_name="shadow.admin@contoso.com")
        mock_graph_client.service_principals.by_service_principal_id.return_value.owners.get.return_value = (
            MockOwnersResponse([user_owner])
        )
        # SP detail returns appId, app registration has no owners
        mock_graph_client.service_principals.by_service_principal_id.return_value.get.return_value = (
            MockServicePrincipalDetail("sp-1", "Privileged App", app_id="app-id-1")
        )
        mock_graph_client.applications.get.return_value = MockApplicationsResponse([
            MockApplication(id="app-obj-1", app_id="app-id-1"),
        ])
        mock_graph_client.applications.by_application_id.return_value.owners.get.return_value = (
            MockOwnersResponse([])
        )

        result = await check_shadow_admins_app_owners(mock_graph_client)

        assert result.status == "warning"
        assert result.check_id == "shadow-admins-app-owners"
        assert "1 user(s)" in result.message
        assert "shadow admins" in result.message
        assert len(result.details["shadow_admins"]) == 1
        assert result.details["shadow_admins"][0]["user_display_name"] == "Shadow Admin User"
        assert result.details["shadow_admins"][0]["user_principal_name"] == "shadow.admin@contoso.com"
        assert result.details["shadow_admins"][0]["service_principal_display_name"] == "Privileged App"
        assert result.details["shadow_admins"][0]["ownership_source"] == "service_principal"

    async def test_warning_with_sensitive_graph_role(self, mock_graph_client):
        """Should warn when user owns SP with sensitive Graph app role."""
        mock_graph_client.role_management.directory.role_assignments.get.return_value = (
            MockRoleAssignmentsResponse([])
        )
        mock_graph_client.service_principals.get.return_value = MockServicePrincipalsResponse([
            MockServicePrincipal(
                id="sp-2",
                display_name="Graph Admin App",
                app_role_assignments=[
                    MockAppRoleAssignment(app_role_id="9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"),
                ],
            )
        ])

        user_owner = MockRoleMember("user-1", "Shadow Admin", "#microsoft.graph.user", user_principal_name="shadow@contoso.com")
        mock_graph_client.service_principals.by_service_principal_id.return_value.owners.get.return_value = (
            MockOwnersResponse([user_owner])
        )
        # SP detail returns appId, app registration has no owners
        mock_graph_client.service_principals.by_service_principal_id.return_value.get.return_value = (
            MockServicePrincipalDetail("sp-2", "Graph Admin App", app_id="app-id-2")
        )
        mock_graph_client.applications.get.return_value = MockApplicationsResponse([
            MockApplication(id="app-obj-2", app_id="app-id-2"),
        ])
        mock_graph_client.applications.by_application_id.return_value.owners.get.return_value = (
            MockOwnersResponse([])
        )

        result = await check_shadow_admins_app_owners(mock_graph_client)

        assert result.status == "warning"
        assert len(result.details["shadow_admins"]) == 1
        assert result.details["shadow_admins"][0]["user_principal_name"] == "shadow@contoso.com"
        assert result.details["shadow_admins"][0]["service_principal_display_name"] == "Graph Admin App"
        assert result.details["shadow_admins"][0]["ownership_source"] == "service_principal"

    async def test_warning_when_user_owns_app_registration_only(self, mock_graph_client):
        """Should warn when a user owns only the app registration, not the SP."""
        sp_principal = MockRoleMember("sp-1", "Privileged App", "#microsoft.graph.servicePrincipal")
        mock_graph_client.role_management.directory.role_assignments.get.return_value = (
            MockRoleAssignmentsResponse([
                MockRoleAssignment(GA_ROLE_ID, "sp-1", sp_principal),
            ])
        )
        mock_graph_client.service_principals.get.return_value = MockServicePrincipalsResponse([])
        # SP has no owners
        mock_graph_client.service_principals.by_service_principal_id.return_value.owners.get.return_value = (
            MockOwnersResponse([])
        )
        # SP detail returns appId
        mock_graph_client.service_principals.by_service_principal_id.return_value.get.return_value = (
            MockServicePrincipalDetail("sp-1", "Privileged App", app_id="app-id-1")
        )
        mock_graph_client.applications.get.return_value = MockApplicationsResponse([
            MockApplication(id="app-obj-1", app_id="app-id-1"),
        ])
        # App registration has a user owner
        user_owner = MockRoleMember("user-1", "App Reg Owner", "#microsoft.graph.user", user_principal_name="appreg.owner@contoso.com")
        mock_graph_client.applications.by_application_id.return_value.owners.get.return_value = (
            MockOwnersResponse([user_owner])
        )

        result = await check_shadow_admins_app_owners(mock_graph_client)

        assert result.status == "warning"
        assert "1 user(s)" in result.message
        assert len(result.details["shadow_admins"]) == 1
        assert result.details["shadow_admins"][0]["user_display_name"] == "App Reg Owner"
        assert result.details["shadow_admins"][0]["user_principal_name"] == "appreg.owner@contoso.com"
        assert result.details["shadow_admins"][0]["service_principal_display_name"] == "Privileged App"
        assert result.details["shadow_admins"][0]["ownership_source"] == "app_registration"

    async def test_deduplicates_owners_across_sp_and_app_registration(self, mock_graph_client):
        """Should deduplicate when same user owns both SP and app registration."""
        sp_principal = MockRoleMember("sp-1", "Privileged App", "#microsoft.graph.servicePrincipal")
        mock_graph_client.role_management.directory.role_assignments.get.return_value = (
            MockRoleAssignmentsResponse([
                MockRoleAssignment(GA_ROLE_ID, "sp-1", sp_principal),
            ])
        )
        mock_graph_client.service_principals.get.return_value = MockServicePrincipalsResponse([])
        # Same user owns both SP and app registration
        user_owner = MockRoleMember("user-1", "Dual Owner", "#microsoft.graph.user", user_principal_name="dual.owner@contoso.com")
        mock_graph_client.service_principals.by_service_principal_id.return_value.owners.get.return_value = (
            MockOwnersResponse([user_owner])
        )
        mock_graph_client.service_principals.by_service_principal_id.return_value.get.return_value = (
            MockServicePrincipalDetail("sp-1", "Privileged App", app_id="app-id-1")
        )
        mock_graph_client.applications.get.return_value = MockApplicationsResponse([
            MockApplication(id="app-obj-1", app_id="app-id-1"),
        ])
        mock_graph_client.applications.by_application_id.return_value.owners.get.return_value = (
            MockOwnersResponse([user_owner])
        )

        result = await check_shadow_admins_app_owners(mock_graph_client)

        assert result.status == "warning"
        assert "1 user(s)" in result.message
        assert len(result.details["shadow_admins"]) == 1
        assert result.details["shadow_admins"][0]["user_principal_name"] == "dual.owner@contoso.com"
        assert result.details["shadow_admins"][0]["service_principal_display_name"] == "Privileged App"
        assert result.details["shadow_admins"][0]["ownership_source"] == "both"

    async def test_handles_sp_without_app_registration(self, mock_graph_client):
        """Should still check SP owners when SP has no appId (managed identity)."""
        sp_principal = MockRoleMember("sp-1", "Managed Identity", "#microsoft.graph.servicePrincipal")
        mock_graph_client.role_management.directory.role_assignments.get.return_value = (
            MockRoleAssignmentsResponse([
                MockRoleAssignment(GA_ROLE_ID, "sp-1", sp_principal),
            ])
        )
        mock_graph_client.service_principals.get.return_value = MockServicePrincipalsResponse([])
        # SP has a user owner
        user_owner = MockRoleMember("user-1", "SP Owner", "#microsoft.graph.user", user_principal_name="sp.owner@contoso.com")
        mock_graph_client.service_principals.by_service_principal_id.return_value.owners.get.return_value = (
            MockOwnersResponse([user_owner])
        )
        # SP detail has no appId (managed identity)
        mock_graph_client.service_principals.by_service_principal_id.return_value.get.return_value = (
            MockServicePrincipalDetail("sp-1", "Managed Identity", app_id=None)
        )

        result = await check_shadow_admins_app_owners(mock_graph_client)

        assert result.status == "warning"
        assert "1 user(s)" in result.message
        assert len(result.details["shadow_admins"]) == 1
        assert result.details["shadow_admins"][0]["user_display_name"] == "SP Owner"
        assert result.details["shadow_admins"][0]["user_principal_name"] == "sp.owner@contoso.com"
        assert result.details["shadow_admins"][0]["service_principal_display_name"] == "Managed Identity"
        assert result.details["shadow_admins"][0]["ownership_source"] == "service_principal"

    async def test_handles_app_lookup_returning_empty(self, mock_graph_client):
        """Should still check SP owners when appId exists but no Application found."""
        sp_principal = MockRoleMember("sp-1", "External App", "#microsoft.graph.servicePrincipal")
        mock_graph_client.role_management.directory.role_assignments.get.return_value = (
            MockRoleAssignmentsResponse([
                MockRoleAssignment(GA_ROLE_ID, "sp-1", sp_principal),
            ])
        )
        mock_graph_client.service_principals.get.return_value = MockServicePrincipalsResponse([])
        # SP has a user owner
        user_owner = MockRoleMember("user-1", "SP Owner", "#microsoft.graph.user", user_principal_name="sp.owner@contoso.com")
        mock_graph_client.service_principals.by_service_principal_id.return_value.owners.get.return_value = (
            MockOwnersResponse([user_owner])
        )
        # SP detail returns appId, but application lookup returns empty (multi-tenant/first-party)
        mock_graph_client.service_principals.by_service_principal_id.return_value.get.return_value = (
            MockServicePrincipalDetail("sp-1", "External App", app_id="external-app-id")
        )
        mock_graph_client.applications.get.return_value = MockApplicationsResponse([])

        result = await check_shadow_admins_app_owners(mock_graph_client)

        assert result.status == "warning"
        assert "1 user(s)" in result.message
        assert len(result.details["shadow_admins"]) == 1
        assert result.details["shadow_admins"][0]["user_display_name"] == "SP Owner"
        assert result.details["shadow_admins"][0]["user_principal_name"] == "sp.owner@contoso.com"
        assert result.details["shadow_admins"][0]["service_principal_display_name"] == "External App"
        assert result.details["shadow_admins"][0]["ownership_source"] == "service_principal"


class TestShadowAdminsGroupOwners:
    """Tests for shadow admins via group ownership check."""

    async def test_pass_when_no_privileged_groups(self, mock_graph_client):
        """Should pass when no groups hold privileged roles."""
        mock_graph_client.role_management.directory.role_assignments.get.return_value = (
            MockRoleAssignmentsResponse([])
        )

        result = await check_shadow_admins_group_owners(mock_graph_client)

        assert result.status == "pass"
        assert result.check_id == "shadow-admins-group-owners"

    async def test_pass_when_no_user_owners(self, mock_graph_client):
        """Should pass when privileged groups have no user owners."""
        group_principal = MockRoleMember("group-1", "Admin Group", "#microsoft.graph.group")
        mock_graph_client.role_management.directory.role_assignments.get.return_value = (
            MockRoleAssignmentsResponse([
                MockRoleAssignment(GA_ROLE_ID, "group-1", group_principal),
            ])
        )
        mock_graph_client.groups.by_group_id.return_value.owners.get.return_value = (
            MockOwnersResponse([])
        )

        result = await check_shadow_admins_group_owners(mock_graph_client)

        assert result.status == "pass"

    async def test_warning_when_user_owns_privileged_group(self, mock_graph_client):
        """Should warn when a user owns a group with a privileged role."""
        group_principal = MockRoleMember("group-1", "Admin Group", "#microsoft.graph.group")
        mock_graph_client.role_management.directory.role_assignments.get.return_value = (
            MockRoleAssignmentsResponse([
                MockRoleAssignment(GA_ROLE_ID, "group-1", group_principal),
            ])
        )

        user_owner = MockRoleMember("user-1", "Group Owner", "#microsoft.graph.user")
        mock_graph_client.groups.by_group_id.return_value.owners.get.return_value = (
            MockOwnersResponse([user_owner])
        )

        result = await check_shadow_admins_group_owners(mock_graph_client)

        assert result.status == "warning"
        assert result.check_id == "shadow-admins-group-owners"
        assert "1 user(s)" in result.message
        assert len(result.details["shadow_admins"]) == 1
        assert result.details["shadow_admins"][0]["user_display_name"] == "Group Owner"
        assert "Global Administrator" in result.details["shadow_admins"][0]["roles"]

    async def test_ignores_non_group_principals(self, mock_graph_client):
        """Should not check ownership of users or SPs in privileged roles."""
        user_principal = MockRoleMember("user-1", "Admin", "#microsoft.graph.user")
        sp_principal = MockRoleMember("sp-1", "App", "#microsoft.graph.servicePrincipal")
        mock_graph_client.role_management.directory.role_assignments.get.return_value = (
            MockRoleAssignmentsResponse([
                MockRoleAssignment(GA_ROLE_ID, "user-1", user_principal),
                MockRoleAssignment(GA_ROLE_ID, "sp-1", sp_principal),
            ])
        )

        result = await check_shadow_admins_group_owners(mock_graph_client)

        assert result.status == "pass"


class TestDynamicGroupHijack:
    """Tests for dynamic group privilege escalation check."""

    async def test_pass_when_no_privileged_groups(self, mock_graph_client):
        """Should pass when no groups hold privileged roles."""
        mock_graph_client.role_management.directory.role_assignments.get.return_value = (
            MockRoleAssignmentsResponse([])
        )

        result = await check_dynamic_group_hijack(mock_graph_client)

        assert result.status == "pass"
        assert result.check_id == "dynamic-group-hijack"

    async def test_pass_when_privileged_group_is_static(self, mock_graph_client):
        """Should pass when privileged groups are not dynamic."""
        group_principal = MockRoleMember("group-1", "Admin Group", "#microsoft.graph.group")
        mock_graph_client.role_management.directory.role_assignments.get.return_value = (
            MockRoleAssignmentsResponse([
                MockRoleAssignment(GA_ROLE_ID, "group-1", group_principal),
            ])
        )
        # Group is static (no DynamicMembership type)
        mock_graph_client.groups.by_group_id.return_value.get.return_value = (
            MockDynamicGroup(
                id="group-1",
                display_name="Admin Group",
                group_types=["Unified"],
                membership_rule=None,
            )
        )

        result = await check_dynamic_group_hijack(mock_graph_client)

        assert result.status == "pass"
        assert "No dynamic groups" in result.message

    async def test_fail_when_dynamic_group_uses_mutable_attribute(self, mock_graph_client):
        """Should fail when dynamic group uses mutable attribute like department."""
        group_principal = MockRoleMember("group-1", "Dynamic Admin Group", "#microsoft.graph.group")
        mock_graph_client.role_management.directory.role_assignments.get.return_value = (
            MockRoleAssignmentsResponse([
                MockRoleAssignment(GA_ROLE_ID, "group-1", group_principal),
            ])
        )
        mock_graph_client.groups.by_group_id.return_value.get.return_value = (
            MockDynamicGroup(
                id="group-1",
                display_name="Dynamic Admin Group",
                group_types=["DynamicMembership"],
                membership_rule='(user.department -eq "IT Security")',
            )
        )

        result = await check_dynamic_group_hijack(mock_graph_client)

        assert result.status == "fail"
        assert result.check_id == "dynamic-group-hijack"
        assert "mutable attributes" in result.message
        assert len(result.details["mutable_rule_groups"]) == 1
        assert "department" in result.details["mutable_rule_groups"][0]["mutable_attributes"]

    async def test_warning_when_dynamic_group_uses_immutable_attribute(self, mock_graph_client):
        """Should warn when dynamic group exists but uses non-mutable attributes."""
        group_principal = MockRoleMember("group-1", "Dynamic Group", "#microsoft.graph.group")
        mock_graph_client.role_management.directory.role_assignments.get.return_value = (
            MockRoleAssignmentsResponse([
                MockRoleAssignment(GA_ROLE_ID, "group-1", group_principal),
            ])
        )
        mock_graph_client.groups.by_group_id.return_value.get.return_value = (
            MockDynamicGroup(
                id="group-1",
                display_name="Dynamic Group",
                group_types=["DynamicMembership"],
                membership_rule='(user.objectId -in ["abc-123"])',
            )
        )

        result = await check_dynamic_group_hijack(mock_graph_client)

        assert result.status == "warning"
        assert "No mutable attributes" in result.message

    async def test_detects_multiple_mutable_attributes(self, mock_graph_client):
        """Should detect multiple mutable attributes in a rule."""
        group_principal = MockRoleMember("group-1", "Group", "#microsoft.graph.group")
        mock_graph_client.role_management.directory.role_assignments.get.return_value = (
            MockRoleAssignmentsResponse([
                MockRoleAssignment(GA_ROLE_ID, "group-1", group_principal),
            ])
        )
        mock_graph_client.groups.by_group_id.return_value.get.return_value = (
            MockDynamicGroup(
                id="group-1",
                display_name="Group",
                group_types=["DynamicMembership"],
                membership_rule='(user.department -eq "IT") -and (user.jobTitle -eq "Admin")',
            )
        )

        result = await check_dynamic_group_hijack(mock_graph_client)

        assert result.status == "fail"
        attrs = result.details["mutable_rule_groups"][0]["mutable_attributes"]
        assert "department" in attrs
        assert "jobtitle" in attrs


class TestAuthMethodsNumberMatching:
    """Tests for Authenticator number matching check."""

    async def test_pass_when_number_matching_enabled(self, mock_graph_client):
        """Should pass when number matching is explicitly enabled."""
        config = MockAuthenticatorConfig(
            state="enabled",
            feature_settings=MockFeatureSettings(
                number_matching_required_state=MockNumberMatchingState(state="enabled"),
            ),
        )
        mock_graph_client.policies.authentication_methods_policy.authentication_method_configurations.by_authentication_method_configuration_id.return_value.get.return_value = config

        result = await check_auth_methods_number_matching(mock_graph_client)

        assert result.status == "pass"
        assert result.check_id == "auth-methods-number-matching"

    async def test_pass_when_default_settings(self, mock_graph_client):
        """Should pass when using default settings (Microsoft-managed)."""
        config = MockAuthenticatorConfig(state="enabled", feature_settings=None)
        mock_graph_client.policies.authentication_methods_policy.authentication_method_configurations.by_authentication_method_configuration_id.return_value.get.return_value = config

        result = await check_auth_methods_number_matching(mock_graph_client)

        assert result.status == "pass"
        assert "default" in result.message.lower() or "Microsoft-managed" in result.message

    async def test_fail_when_number_matching_disabled(self, mock_graph_client):
        """Should fail when number matching is explicitly disabled."""
        config = MockAuthenticatorConfig(
            state="enabled",
            feature_settings=MockFeatureSettings(
                number_matching_required_state=MockNumberMatchingState(state="disabled"),
            ),
        )
        mock_graph_client.policies.authentication_methods_policy.authentication_method_configurations.by_authentication_method_configuration_id.return_value.get.return_value = config

        result = await check_auth_methods_number_matching(mock_graph_client)

        assert result.status == "fail"
        assert result.check_id == "auth-methods-number-matching"
        assert "disabled" in result.message.lower()
        assert result.recommendation is not None

    async def test_warning_when_authenticator_disabled(self, mock_graph_client):
        """Should warn when Microsoft Authenticator is disabled entirely."""
        config = MockAuthenticatorConfig(state="disabled", feature_settings=None)
        mock_graph_client.policies.authentication_methods_policy.authentication_method_configurations.by_authentication_method_configuration_id.return_value.get.return_value = config

        result = await check_auth_methods_number_matching(mock_graph_client)

        assert result.status == "warning"
        assert "disabled" in result.message.lower()

    async def test_warning_when_only_specific_groups(self, mock_graph_client):
        """Should warn when number matching is only for specific groups."""
        config = MockAuthenticatorConfig(
            state="enabled",
            feature_settings=MockFeatureSettings(
                number_matching_required_state=MockNumberMatchingState(
                    state="enabled",
                    include_target=MockIncludeTarget(target_type="group"),
                ),
            ),
        )
        mock_graph_client.policies.authentication_methods_policy.authentication_method_configurations.by_authentication_method_configuration_id.return_value.get.return_value = config

        result = await check_auth_methods_number_matching(mock_graph_client)

        assert result.status == "warning"
        assert "specific groups" in result.message.lower()

    async def test_pass_when_microsoft_managed_state(self, mock_graph_client):
        """Should pass when state is 'default' (Microsoft-managed)."""
        config = MockAuthenticatorConfig(
            state="enabled",
            feature_settings=MockFeatureSettings(
                number_matching_required_state=MockNumberMatchingState(state="default"),
            ),
        )
        mock_graph_client.policies.authentication_methods_policy.authentication_method_configurations.by_authentication_method_configuration_id.return_value.get.return_value = config

        result = await check_auth_methods_number_matching(mock_graph_client)

        assert result.status == "pass"
        assert "Microsoft-managed" in result.message


class TestBreakGlassExclusion:
    """Tests for break-glass account CA exclusion check."""

    def _create_enabled_policy(
        self,
        policy_id: str,
        name: str,
        exclude_users: list[str] | None = None,
    ) -> MockConditionalAccessPolicy:
        """Helper to create an enabled CA policy with optional user exclusions."""
        return MockConditionalAccessPolicy(
            id=policy_id,
            display_name=name,
            state="enabled",
            conditions=MockCAConditions(
                users=MockCAUsers(
                    include_users=["All"],
                    exclude_users=exclude_users,
                ),
                applications=MockCAApplications(include_applications=["All"]),
            ),
            grant_controls=MockCAGrantControls(built_in_controls=["mfa"]),
        )

    async def test_pass_when_two_accounts_excluded_from_all(self, mock_graph_client):
        """Should pass when 2+ accounts are excluded from all enabled policies."""
        bg1 = "break-glass-1"
        bg2 = "break-glass-2"
        policies = [
            self._create_enabled_policy("p1", "Policy 1", exclude_users=[bg1, bg2]),
            self._create_enabled_policy("p2", "Policy 2", exclude_users=[bg1, bg2]),
        ]
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse(policies)
        )

        result = await check_break_glass_exclusion(mock_graph_client)

        assert result.status == "pass"
        assert result.check_id == "break-glass-exclusion"
        assert "2 account(s)" in result.message

    async def test_warning_when_only_one_account_excluded(self, mock_graph_client):
        """Should warn when only 1 account is excluded from all policies."""
        bg1 = "break-glass-1"
        policies = [
            self._create_enabled_policy("p1", "Policy 1", exclude_users=[bg1, "other-user"]),
            self._create_enabled_policy("p2", "Policy 2", exclude_users=[bg1]),
        ]
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse(policies)
        )

        result = await check_break_glass_exclusion(mock_graph_client)

        assert result.status == "warning"
        assert "Only 1 account" in result.message

    async def test_fail_when_no_accounts_excluded_from_all(self, mock_graph_client):
        """Should fail when no account is excluded from all policies."""
        policies = [
            self._create_enabled_policy("p1", "Policy 1", exclude_users=["user-a"]),
            self._create_enabled_policy("p2", "Policy 2", exclude_users=["user-b"]),
        ]
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse(policies)
        )

        result = await check_break_glass_exclusion(mock_graph_client)

        assert result.status == "fail"
        assert result.check_id == "break-glass-exclusion"
        assert "No user account" in result.message
        assert result.recommendation is not None

    async def test_fail_when_no_exclusions_at_all(self, mock_graph_client):
        """Should fail when policies have no user exclusions."""
        policies = [
            self._create_enabled_policy("p1", "Policy 1"),
            self._create_enabled_policy("p2", "Policy 2"),
        ]
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse(policies)
        )

        result = await check_break_glass_exclusion(mock_graph_client)

        assert result.status == "fail"

    async def test_warning_when_no_enabled_policies(self, mock_graph_client):
        """Should warn when no enabled CA policies exist."""
        # Only a disabled policy
        policy = MockConditionalAccessPolicy(
            id="p1", display_name="Disabled Policy", state="disabled",
            conditions=MockCAConditions(),
        )
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse([policy])
        )

        result = await check_break_glass_exclusion(mock_graph_client)

        assert result.status == "warning"
        assert "No enabled" in result.message

    async def test_ignores_report_only_policies(self, mock_graph_client):
        """Should only check enabled policies, not report-only ones."""
        bg1 = "break-glass-1"
        bg2 = "break-glass-2"
        policies = [
            self._create_enabled_policy("p1", "Enabled Policy", exclude_users=[bg1, bg2]),
            MockConditionalAccessPolicy(
                id="p2",
                display_name="Report Only Policy",
                state="enabledForReportingButNotEnforced",
                conditions=MockCAConditions(
                    users=MockCAUsers(include_users=["All"]),
                    applications=MockCAApplications(include_applications=["All"]),
                ),
                grant_controls=MockCAGrantControls(built_in_controls=["mfa"]),
            ),
        ]
        mock_graph_client.identity.conditional_access.policies.get.return_value = (
            MockCAPoliciesResponse(policies)
        )

        result = await check_break_glass_exclusion(mock_graph_client)

        assert result.status == "pass"
        assert result.details["enabled_policy_count"] == 1


class TestPrivilegedRolesLicense:
    """Tests for privileged role licensing coverage check."""

    @staticmethod
    def _create_user_principal(user_id: str, display_name: str) -> MockRoleMember:
        return MockRoleMember(
            id=user_id,
            display_name=display_name,
            odata_type="#microsoft.graph.user",
        )

    @staticmethod
    def _create_group_principal(group_id: str, display_name: str) -> MockRoleMember:
        return MockRoleMember(
            id=group_id,
            display_name=display_name,
            odata_type="#microsoft.graph.group",
        )

    @staticmethod
    def _create_sp_principal(sp_id: str, display_name: str) -> MockRoleMember:
        return MockRoleMember(
            id=sp_id,
            display_name=display_name,
            odata_type="#microsoft.graph.servicePrincipal",
        )

    @staticmethod
    def _licensed_user(user_id: str, upn: str) -> MockUser:
        return MockUser(
            id=user_id,
            user_principal_name=upn,
            assigned_plans=[MockAssignedPlan("AAD_PREMIUM", "Enabled")],
        )

    @staticmethod
    def _unlicensed_user(user_id: str, upn: str) -> MockUser:
        return MockUser(
            id=user_id,
            user_principal_name=upn,
            assigned_plans=[],
        )

    @staticmethod
    def _set_group_members(
        mock_graph_client,
        group_pages: dict[str, list[MockGroupMembersResponse]],
    ) -> None:
        cache: dict[str, MagicMock] = {}

        def _group_ref(group_id: str) -> MagicMock:
            if group_id in cache:
                return cache[group_id]

            pages = group_pages[group_id]
            members = MagicMock()
            members.get = AsyncMock(return_value=pages[0])

            next_refs: dict[str, MagicMock] = {}
            for i, page in enumerate(pages[:-1]):
                if page.odata_next_link:
                    next_refs[page.odata_next_link] = MagicMock(
                        get=AsyncMock(return_value=pages[i + 1])
                    )

            members.with_url = MagicMock(side_effect=lambda url: next_refs[url])
            group_ref = MagicMock(members=members)
            cache[group_id] = group_ref
            return group_ref

        mock_graph_client.groups.by_group_id.side_effect = _group_ref

    async def test_pass_when_all_direct_users_have_premium(self, mock_graph_client):
        """Should pass when all direct privileged role users have P1/P2."""
        user1 = self._create_user_principal("user-1", "Admin One")
        user2 = self._create_user_principal("user-2", "Admin Two")
        mock_graph_client.role_management.directory.role_assignments.get.return_value = (
            MockRoleAssignmentsResponse([
                MockRoleAssignment(GLOBAL_ADMIN_ROLE_ID, "user-1", user1),
                MockRoleAssignment(GLOBAL_ADMIN_ROLE_ID, "user-2", user2),
            ])
        )

        def _lookup(user_id: str):
            users = {
                "user-1": self._licensed_user("user-1", "admin1@contoso.com"),
                "user-2": self._licensed_user("user-2", "admin2@contoso.com"),
            }
            return MagicMock(get=AsyncMock(return_value=users[user_id]))

        mock_graph_client.users.by_user_id.side_effect = _lookup

        result = await check_privileged_roles_license(mock_graph_client)

        assert result.status == "pass"
        assert result.check_id == "privileged-roles-license"
        assert result.details["evaluated_user_count"] == 2
        assert result.details["unlicensed_user_count"] == 0

    async def test_fail_when_user_missing_premium_license(self, mock_graph_client):
        """Should fail when at least one privileged user lacks P1/P2."""
        user1 = self._create_user_principal("user-1", "Admin One")
        user2 = self._create_user_principal("user-2", "Admin Two")
        mock_graph_client.role_management.directory.role_assignments.get.return_value = (
            MockRoleAssignmentsResponse([
                MockRoleAssignment(GLOBAL_ADMIN_ROLE_ID, "user-1", user1),
                MockRoleAssignment(GLOBAL_ADMIN_ROLE_ID, "user-2", user2),
            ])
        )

        def _lookup(user_id: str):
            users = {
                "user-1": self._licensed_user("user-1", "admin1@contoso.com"),
                "user-2": self._unlicensed_user("user-2", "admin2@contoso.com"),
            }
            return MagicMock(get=AsyncMock(return_value=users[user_id]))

        mock_graph_client.users.by_user_id.side_effect = _lookup

        result = await check_privileged_roles_license(mock_graph_client)

        assert result.status == "fail"
        assert "do not have Entra ID P1/P2" in result.message
        assert result.details["unlicensed_user_count"] == 1
        assert result.details["unlicensed_users"][0]["upn"] == "admin2@contoso.com"

    async def test_pass_with_recursive_nested_group_lookup(self, mock_graph_client):
        """Should recursively expand nested groups to find licensed users."""
        root_group = self._create_group_principal("group-a", "Privileged Group A")
        nested_group = self._create_group_principal("group-b", "Privileged Group B")
        nested_user = self._create_user_principal("user-1", "Nested User")
        mock_graph_client.role_management.directory.role_assignments.get.return_value = (
            MockRoleAssignmentsResponse([
                MockRoleAssignment(GLOBAL_ADMIN_ROLE_ID, "group-a", root_group),
            ])
        )
        self._set_group_members(
            mock_graph_client,
            {
                "group-a": [MockGroupMembersResponse([nested_group])],
                "group-b": [MockGroupMembersResponse([nested_user])],
            },
        )
        mock_graph_client.users.by_user_id.return_value.get.return_value = (
            self._licensed_user("user-1", "nested@contoso.com")
        )

        result = await check_privileged_roles_license(mock_graph_client)

        assert result.status == "pass"
        assert result.details["evaluated_user_count"] == 1
        assert result.details["licensed_user_count"] == 1

    async def test_handles_group_cycles_without_infinite_loop(self, mock_graph_client):
        """Should handle nested group cycles safely."""
        root_group = self._create_group_principal("group-a", "Group A")
        group_a = self._create_group_principal("group-a", "Group A")
        group_b = self._create_group_principal("group-b", "Group B")
        user1 = self._create_user_principal("user-1", "Cycle User")
        mock_graph_client.role_management.directory.role_assignments.get.return_value = (
            MockRoleAssignmentsResponse([
                MockRoleAssignment(GLOBAL_ADMIN_ROLE_ID, "group-a", root_group),
            ])
        )
        self._set_group_members(
            mock_graph_client,
            {
                "group-a": [MockGroupMembersResponse([group_b])],
                "group-b": [MockGroupMembersResponse([group_a, user1])],
            },
        )
        mock_graph_client.users.by_user_id.return_value.get.return_value = (
            self._licensed_user("user-1", "cycle@contoso.com")
        )

        result = await check_privileged_roles_license(mock_graph_client)

        assert result.status == "pass"
        assert result.details["evaluated_user_count"] == 1

    async def test_role_assignments_pagination_is_supported(self, mock_graph_client):
        """Should handle paginated role assignments."""
        first_page = MockRoleAssignmentsResponse(
            [MockRoleAssignment(
                GLOBAL_ADMIN_ROLE_ID,
                "user-1",
                self._create_user_principal("user-1", "Admin One"),
            )],
            odata_next_link="next-role-page",
        )
        second_page = MockRoleAssignmentsResponse(
            [MockRoleAssignment(
                GLOBAL_ADMIN_ROLE_ID,
                "user-2",
                self._create_user_principal("user-2", "Admin Two"),
            )],
        )
        mock_graph_client.role_management.directory.role_assignments.get.return_value = first_page
        mock_graph_client.role_management.directory.role_assignments.with_url.return_value.get.return_value = (
            second_page
        )

        def _lookup(user_id: str):
            users = {
                "user-1": self._licensed_user("user-1", "admin1@contoso.com"),
                "user-2": self._licensed_user("user-2", "admin2@contoso.com"),
            }
            return MagicMock(get=AsyncMock(return_value=users[user_id]))

        mock_graph_client.users.by_user_id.side_effect = _lookup

        result = await check_privileged_roles_license(mock_graph_client)

        assert result.status == "pass"
        assert result.details["evaluated_user_count"] == 2

    async def test_group_members_pagination_is_supported(self, mock_graph_client):
        """Should handle paginated group members while expanding recursively."""
        root_group = self._create_group_principal("group-a", "Privileged Group A")
        user1 = self._create_user_principal("user-1", "Member One")
        user2 = self._create_user_principal("user-2", "Member Two")
        mock_graph_client.role_management.directory.role_assignments.get.return_value = (
            MockRoleAssignmentsResponse([
                MockRoleAssignment(GLOBAL_ADMIN_ROLE_ID, "group-a", root_group),
            ])
        )
        first_members_page = MockGroupMembersResponse([user1], odata_next_link="next-member-page")
        second_members_page = MockGroupMembersResponse([user2])
        self._set_group_members(
            mock_graph_client,
            {"group-a": [first_members_page, second_members_page]},
        )

        def _lookup(user_id: str):
            users = {
                "user-1": self._licensed_user("user-1", "member1@contoso.com"),
                "user-2": self._licensed_user("user-2", "member2@contoso.com"),
            }
            return MagicMock(get=AsyncMock(return_value=users[user_id]))

        mock_graph_client.users.by_user_id.side_effect = _lookup

        result = await check_privileged_roles_license(mock_graph_client)

        assert result.status == "pass"
        assert result.details["evaluated_user_count"] == 2

    async def test_warning_when_no_user_members_in_scope(self, mock_graph_client):
        """Should warn when no user principals are available to evaluate."""
        sp1 = self._create_sp_principal("sp-1", "Automation SP")
        mock_graph_client.role_management.directory.role_assignments.get.return_value = (
            MockRoleAssignmentsResponse([
                MockRoleAssignment(GLOBAL_ADMIN_ROLE_ID, "sp-1", sp1),
            ])
        )

        result = await check_privileged_roles_license(mock_graph_client)

        assert result.status == "warning"
        assert result.details["evaluated_user_count"] == 0
        assert result.details["ignored_principals"][0]["type"] == "#microsoft.graph.servicePrincipal"

    async def test_warning_when_user_lookup_fails(self, mock_graph_client):
        """Should warn when user lookup errors prevent complete validation."""
        user1 = self._create_user_principal("user-1", "Admin One")
        user2 = self._create_user_principal("user-2", "Admin Two")
        mock_graph_client.role_management.directory.role_assignments.get.return_value = (
            MockRoleAssignmentsResponse([
                MockRoleAssignment(GLOBAL_ADMIN_ROLE_ID, "user-1", user1),
                MockRoleAssignment(GLOBAL_ADMIN_ROLE_ID, "user-2", user2),
            ])
        )

        def _lookup(user_id: str):
            if user_id == "user-2":
                return MagicMock(get=AsyncMock(side_effect=Exception("Not found")))
            return MagicMock(
                get=AsyncMock(return_value=self._licensed_user("user-1", "admin1@contoso.com"))
            )

        mock_graph_client.users.by_user_id.side_effect = _lookup

        result = await check_privileged_roles_license(mock_graph_client)

        assert result.status == "warning"
        assert result.details["unresolved_user_count"] == 1
        assert "lookups failed" in result.message
